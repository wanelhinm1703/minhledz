#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

# Ensure repository root is in sys.path
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.schemas.target import TargetStatus
from backend.app.services.recon_planner import ReconPlanner
from backend.app.services.scope_validator import ScopeValidator, ScopeViolation
from backend.app.services.target_normalizer import TargetNormalizer
from backend.app.services.target_parser import TargetParser
from backend.app.services.target_registry import TargetRegistry
from backend.app.services.target_validator import TargetValidator
from toolkit.scripts.parse_nmap import NmapParser
from toolkit.scripts.run_nmap import run_nmap_scan


def execute_dynamic_scan(raw_target: str, campaign_id: str = "lab-local") -> dict:
    print("\n=======================================================")
    print("[*] AI-PENTEST COPILOT - RECON RUNNER (MILESTONE M0)")
    print(f"[*] Target Input: {raw_target}")
    print("=======================================================\n")

    root = REPO_ROOT

    # 1. Parse Target
    print("==> [1/7] Parsing Target Type...")
    parsed = TargetParser.parse(raw_target)
    print(f"    Target Type: {parsed.target_type.value.upper()}")
    print(f"    Host: {parsed.host} | Port: {parsed.port} | Scheme: {parsed.scheme}")

    # 2. Normalize Target
    print("==> [2/7] Normalizing Target...")
    normalized = TargetNormalizer.normalize(parsed)
    print(f"    Normalized Value: {normalized['normalized_value']}")

    # 3. Validate Syntax
    print("==> [3/7] Validating Syntax & Constraints...")
    val_res = TargetValidator.validate(parsed, normalized)
    if not val_res.is_valid:
        print("[!] SYNTAX VALIDATION FAILED:")
        for err in val_res.errors:
            print(f"    - {err}")
        sys.exit(1)
    print("    [OK] Target syntax is valid.")

    # 4. Create & Register Target Object
    registry = TargetRegistry(root / "toolkit" / "01-targets" / "registry")
    target = registry.create_from_input(
        raw_input=raw_target,
        campaign_id=campaign_id,
        environment="lab",
    )

    # 5. Scope Validation
    print("==> [4/7] Checking Authorization & Scope...")
    scope_validator = ScopeValidator()
    decision = scope_validator.validate(target)

    if not decision.allowed:
        target.status = TargetStatus.BLOCKED
        target.scope.is_in_scope = False
        target.scope.scope_rule = decision.reason
        registry._save()
        print("\n[!] SECURITY ALERT: TARGET BLOCKED BY SCOPE POLICY!")
        print(f"    Reason: {decision.reason}\n")
        raise ScopeViolation(decision.reason)

    target.scope.is_in_scope = True
    target.scope.scope_rule = decision.matched_rule
    registry._save()
    print(f"    [OK] Target Authorized: {decision.reason}")

    # 6. Recon Planning
    print("==> [5/7] Planning Reconnaissance Steps...")
    recon_plan = ReconPlanner.plan(target)
    print(f"    Capabilities: {', '.join(recon_plan.capabilities)}")
    for step in recon_plan.steps:
        print(f"    Step {step.step_number}: [{step.tool.upper()}] {step.purpose}")
        print(f"      Command: {step.command_template}")

    # 7. Execute Recon (Nmap)
    print("==> [6/7] Executing Non-Destructive Reconnaissance...")
    scan_output_dir = (
        root / "toolkit" / "03-network" / "scans" / target.target_id / "nmap"
    )
    raw_res = run_nmap_scan(
        target_id=target.target_id,
        target_host=target.host,
        port=target.port,
        output_dir=scan_output_dir,
    )

    # 8. Parse Raw Evidence -> Structured JSON & Schema Validation
    print("==> [7/7] Parsing Raw Evidence & Validating JSON Schema...")
    raw_xml = pathlib.Path(raw_res["raw_xml_path"])
    structured_json_path = scan_output_dir / "structured" / "nmap_result.json"
    structured_json_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = root / "security" / "schemas" / "nmap_result.schema.json"

    metadata = {
        "target": target.normalized_value,
        "command": raw_res["command"],
        "arguments": raw_res["arguments"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration": raw_res["duration"],
        "exit_code": raw_res["exit_code"],
    }

    structured = NmapParser.parse_xml_file(
        xml_path=raw_xml,
        scan_metadata=metadata,
        schema_path=schema_path,
    )
    structured_json_path.write_text(json.dumps(structured, indent=2), encoding="utf-8")
    print(
        "    [OK] Structured JSON generated and validated against nmap_result.schema.json!"
    )

    print("\n-------------------------------------------------------")
    print("[*] RECON COMPLETED SUCCESSFULLY!")
    print(f"[*] Target ID: {target.target_id}")
    print(f"[*] Raw XML Evidence: {raw_res['raw_xml_path']}")
    print(f"[*] Normal Evidence:  {raw_res['normal_txt_path']}")
    print(f"[*] Audit Log:        {raw_res['commands_log']}")
    print(f"[*] Structured JSON:  {structured_json_path}")
    print("-------------------------------------------------------\n")

    return {
        "target": target,
        "raw_evidence": raw_res["raw_xml_path"],
        "structured_json": str(structured_json_path),
        "commands_md": raw_res["commands_log"],
    }


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Targets CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan dynamic target")
    scan_parser.add_argument(
        "--target", required=True, help="Target input (IP, URL, CIDR, Domain, etc.)"
    )
    scan_parser.add_argument("--campaign", default="lab-local", help="Campaign ID")

    list_parser = subparsers.add_parser("list", help="List registered targets")

    args = parser.parse_args()

    if args.command == "scan":
        try:
            execute_dynamic_scan(raw_target=args.target, campaign_id=args.campaign)
        except ScopeViolation:
            sys.exit(2)
        except Exception as e:
            print(f"[!] Error: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "list":
        root = REPO_ROOT
        registry = TargetRegistry(root / "toolkit" / "01-targets" / "registry")
        targets = registry.list_all()
        print(f"Found {len(targets)} registered target(s):")
        for t in targets:
            print(
                f" - [{t.status.value}] {t.target_id} | {t.type.value} | {t.normalized_value}"
            )


if __name__ == "__main__":
    main()
