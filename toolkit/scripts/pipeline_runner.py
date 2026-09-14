#!/usr/bin/env python3
"""
AI-Pentest Copilot - Reconnaissance Pipeline Orchestrator.
Coordinates: Target Parse -> Normalize -> Scope Validation -> Recon Planning -> Multi-Tool Execution (Nmap, Naabu, Httpx, Nuclei) -> Structured Parsing & Schema Validation -> Evidence Manifest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import pathlib
import sys

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

from toolkit.scripts.run_nmap import run_nmap_scan
from toolkit.scripts.parse_nmap import NmapParser
from toolkit.scripts.run_naabu import run_naabu_scan
from toolkit.scripts.run_httpx import run_httpx_scan
from toolkit.scripts.parse_httpx import HttpxParser
from toolkit.scripts.run_nuclei import run_nuclei_scan
from toolkit.scripts.parse_nuclei import NucleiParser


def run_pipeline(raw_target: str, campaign_id: str = "lab-local") -> dict:
    print("\n=================================================================")
    print("[*] AI-PENTEST COPILOT - MULTI-TOOL RECON PIPELINE (M1)")
    print(f"[*] Target Input: {raw_target}")
    print("=================================================================\n")

    root = REPO_ROOT

    # 1. Parse & Normalize Target
    print("==> [1/6] Ingesting Dynamic Target...")
    parsed = TargetParser.parse(raw_target)
    normalized = TargetNormalizer.normalize(parsed)
    val_res = TargetValidator.validate(parsed, normalized)
    if not val_res.is_valid:
        print(f"[!] SYNTAX VALIDATION FAILED: {'; '.join(val_res.errors)}")
        sys.exit(1)

    # 2. Register & Check Scope
    print("==> [2/6] Enforcing Scope Boundaries...")
    registry = TargetRegistry(root / "toolkit" / "01-targets" / "registry")
    target = registry.create_from_input(raw_input=raw_target, campaign_id=campaign_id)

    scope_validator = ScopeValidator()
    decision = scope_validator.validate(target)
    if not decision.allowed:
        target.status = TargetStatus.BLOCKED
        target.scope.is_in_scope = False
        target.scope.scope_rule = decision.reason
        registry._save()
        print(f"\n[!] SECURITY ALERT: TARGET BLOCKED BY SCOPE POLICY!")
        print(f"    Reason: {decision.reason}\n")
        raise ScopeViolation(decision.reason)

    target.scope.is_in_scope = True
    target.scope.scope_rule = decision.matched_rule
    registry._save()
    print(f"    [OK] Target Authorized: {decision.reason}")

    # 3. Plan Capabilities & Tools
    print("==> [3/6] Formulating Reconnaissance Plan...")
    plan = ReconPlanner.plan(target)
    print(f"    Target Type:  {target.type.value.upper()}")
    print(f"    Capabilities: {', '.join(plan.capabilities)}")
    print("    Scheduled Tools:")
    for step in plan.steps:
        print(f"      - Step {step.step_number} [{step.tool.upper()}]: {step.purpose}")

    evidence_manifest = {
        "target_id": target.target_id,
        "target_input": raw_target,
        "normalized_value": target.normalized_value,
        "campaign_id": campaign_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "capabilities": plan.capabilities,
        "tools_executed": [],
        "evidence_files": {},
    }

    # 4. Execute Tools
    print("\n==> [4/6] Executing Non-Destructive Tool Adapters...")
    
    # Run Naabu if in steps
    if any(s.tool == "naabu" for s in plan.steps):
        print("    --> Running Naabu port scanner...")
        naabu_res = run_naabu_scan(
            target_id=target.target_id,
            target_host=target.host,
            port=target.port,
        )
        evidence_manifest["tools_executed"].append("naabu")
        evidence_manifest["evidence_files"]["naabu"] = {
            "raw": naabu_res["raw_path"],
            "commands": naabu_res["commands_log"],
        }
        print(f"        [OK] Naabu raw evidence saved.")

    # Run Nmap if in steps
    if any(s.tool == "nmap" for s in plan.steps):
        print("    --> Running Nmap service & version detector...")
        scan_output_dir = root / "toolkit" / "03-network" / "scans" / target.target_id / "nmap"
        nmap_res = run_nmap_scan(
            target_id=target.target_id,
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        
        # Parse Nmap
        schema_file = root / "security" / "schemas" / "nmap_result.schema.json"
        structured_nmap_path = scan_output_dir / "structured" / "nmap_result.json"
        structured_nmap_path.parent.mkdir(parents=True, exist_ok=True)
        structured_nmap = NmapParser.parse_xml_file(
            xml_path=pathlib.Path(nmap_res["raw_xml_path"]),
            scan_metadata={
                "target": target.normalized_value,
                "command": nmap_res["command"],
                "arguments": nmap_res["arguments"],
                "duration": nmap_res["duration"],
                "exit_code": nmap_res["exit_code"],
            },
            schema_path=schema_file,
        )
        structured_nmap_path.write_text(json.dumps(structured_nmap, indent=2), encoding="utf-8")

        evidence_manifest["tools_executed"].append("nmap")
        evidence_manifest["evidence_files"]["nmap"] = {
            "raw": nmap_res["raw_xml_path"],
            "normal": nmap_res["normal_txt_path"],
            "structured": str(structured_nmap_path),
            "commands": nmap_res["commands_log"],
        }
        print(f"        [OK] Nmap raw evidence and validated structured JSON saved.")

    # Run Httpx if in steps
    if any(s.tool == "httpx" for s in plan.steps):
        print("    --> Running Httpx web prober...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "httpx"
        httpx_res = run_httpx_scan(
            target_id=target.target_id,
            target_url=target.normalized_value,
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        
        # Parse Httpx
        schema_file = root / "security" / "schemas" / "httpx_result.schema.json"
        structured_httpx_path = scan_output_dir / "structured" / "httpx_result.json"
        structured_httpx_path.parent.mkdir(parents=True, exist_ok=True)
        structured_httpx = HttpxParser.parse_raw_jsonl(
            jsonl_path=pathlib.Path(httpx_res["raw_path"]),
            scan_metadata={
                "target": target.normalized_value,
                "command": httpx_res["command"],
                "arguments": httpx_res["arguments"],
                "duration": httpx_res["duration"],
                "exit_code": httpx_res["exit_code"],
            },
            schema_path=schema_file,
        )
        structured_httpx_path.write_text(json.dumps(structured_httpx, indent=2), encoding="utf-8")

        evidence_manifest["tools_executed"].append("httpx")
        evidence_manifest["evidence_files"]["httpx"] = {
            "raw": httpx_res["raw_path"],
            "structured": str(structured_httpx_path),
            "commands": httpx_res["commands_log"],
        }
        print(f"        [OK] Httpx raw evidence and validated structured JSON saved.")

    # Run Nuclei if in steps
    if any(s.tool == "nuclei" for s in plan.steps):
        print("    --> Running Nuclei read-only vulnerability detector...")
        scan_output_dir = root / "toolkit" / "05-vulnerability" / "scans" / target.target_id / "nuclei"
        nuclei_res = run_nuclei_scan(
            target_id=target.target_id,
            target_url=target.normalized_value,
            target_host=target.host,
            output_dir=scan_output_dir,
        )

        # Parse Nuclei
        schema_file = root / "security" / "schemas" / "nuclei_finding.schema.json"
        structured_nuclei_path = scan_output_dir / "structured" / "nuclei_result.json"
        structured_nuclei_path.parent.mkdir(parents=True, exist_ok=True)
        structured_nuclei = NucleiParser.parse_raw_jsonl(
            jsonl_path=pathlib.Path(nuclei_res["raw_path"]),
            scan_metadata={
                "target": target.normalized_value,
                "command": nuclei_res["command"],
                "arguments": nuclei_res["arguments"],
                "duration": nuclei_res["duration"],
                "exit_code": nuclei_res["exit_code"],
            },
            schema_path=schema_file,
        )
        structured_nuclei_path.write_text(json.dumps(structured_nuclei, indent=2), encoding="utf-8")

        evidence_manifest["tools_executed"].append("nuclei")
        evidence_manifest["evidence_files"]["nuclei"] = {
            "raw": nuclei_res["raw_path"],
            "structured": str(structured_nuclei_path),
            "commands": nuclei_res["commands_log"],
        }
        print(f"        [OK] Nuclei raw evidence and validated structured JSON saved.")

    # 5. Write Evidence Manifest
    print("\n==> [5/6] Consolidating Evidence Manifest...")
    manifest_dir = root / "toolkit" / "09-analysis" / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{target.target_id}_manifest.json"
    manifest_path.write_text(json.dumps(evidence_manifest, indent=2), encoding="utf-8")
    print(f"    [OK] Manifest saved at: {manifest_path}")

    # 6. Summary Output
    print("\n=================================================================")
    print("[*] RECON PIPELINE COMPLETED SUCCESSFULLY!")
    print(f"[*] Target ID:        {target.target_id}")
    print(f"[*] Tools Executed:   {', '.join(evidence_manifest['tools_executed'])}")
    print(f"[*] Evidence Manifest: {manifest_path}")
    print("=================================================================\n")

    return evidence_manifest


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Recon Pipeline")
    parser.add_argument("target", nargs="?", help="Dynamic target (IP, URL, CIDR, Domain)")
    parser.add_argument("--target", dest="target_opt", help="Dynamic target (optional flag)")
    parser.add_argument("--campaign", default="lab-local", help="Campaign ID")
    args = parser.parse_args()

    target_val = args.target or args.target_opt
    if not target_val:
        print("ERROR: Target input is required. Example: python pipeline_runner.py 192.168.56.101")
        sys.exit(1)

    try:
        run_pipeline(raw_target=target_val, campaign_id=args.campaign)
    except ScopeViolation:
        sys.exit(2)
    except Exception as e:
        print(f"[!] Pipeline Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
