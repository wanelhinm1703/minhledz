#!/usr/bin/env python3
"""
AI-Pentest Copilot - Reconnaissance Pipeline Orchestrator.
Coordinates: Target Parse -> Normalize -> Scope Validation -> Recon Planning -> Multi-Tool Execution (Original Toolset) -> Structured Parsing & Schema Validation -> Evidence Manifest.
Distinguishes strictly between REAL, SIMULATED, and FAILED scans (MASTER PROMPT v5.0 §17, §29, §53, §75).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

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
from toolkit.scripts.parse_ffuf import FfufParser
from toolkit.scripts.parse_gobuster import GobusterParser
from toolkit.scripts.parse_httpx import HttpxParser
from toolkit.scripts.parse_katana import KatanaParser
from toolkit.scripts.parse_masscan import MasscanParser
from toolkit.scripts.parse_nikto import NiktoParser
from toolkit.scripts.parse_nmap import NmapParser
from toolkit.scripts.parse_nuclei import NucleiParser
from toolkit.scripts.parse_rustscan import RustscanParser
from toolkit.scripts.parse_searchsploit import SearchsploitParser
from toolkit.scripts.parse_service_enum import ServiceEnumParser
from toolkit.scripts.parse_whatweb import WhatwebParser
from toolkit.scripts.run_ffuf import run_ffuf_scan
from toolkit.scripts.run_gobuster import run_gobuster_scan
from toolkit.scripts.run_httpx import run_httpx_scan
from toolkit.scripts.run_katana import run_katana_scan
from toolkit.scripts.run_masscan import run_masscan_scan
from toolkit.scripts.run_naabu import run_naabu_scan
from toolkit.scripts.run_nikto import run_nikto_scan

# Original Toolset Runners & Parsers
from toolkit.scripts.run_nmap import run_nmap_scan
from toolkit.scripts.run_nuclei import run_nuclei_scan
from toolkit.scripts.run_proxy_manual import run_proxy_manual_workflow
from toolkit.scripts.run_rustscan import run_rustscan_scan
from toolkit.scripts.run_searchsploit import run_searchsploit_lookup
from toolkit.scripts.run_service_enum import run_service_enum_scan
from toolkit.scripts.run_whatweb import run_whatweb_scan
from toolkit.scripts.scan_status import load_scan_status


def handle_tool_result(
    tool_name: str,
    scan_res: dict,
    scan_dir: pathlib.Path,
    evidence_manifest: dict,
    parser_call: Callable[[pathlib.Path], Any] | None = None,
    structured_filename: str = "",
    extra_files: dict | None = None,
):
    """Processes scan output according to mode: real vs simulated vs failed."""
    status = scan_res.get("status") or load_scan_status(scan_dir) or {}
    mode = status.get("mode", "real" if scan_res.get("exit_code") == 0 else "failed")
    status_path = str(scan_dir / "status.json")

    if mode == "failed":
        evidence_manifest["tool_status"][tool_name] = status or {
            "mode": "failed",
            "error": scan_res.get("error"),
        }
        print(
            f"        [!] {tool_name.upper()} execution failed: {status.get('reason') or scan_res.get('error')}"
        )
        return

    raw_path_str = scan_res.get("raw_path") or scan_res.get("raw_xml_path")
    evidence_manifest["tools_executed"].append(tool_name)
    evidence_manifest["tool_status"][tool_name] = status

    if mode == "simulated":
        evidence_manifest.setdefault("simulated_tools", []).append(tool_name)
        file_info = {
            "status": status_path,
            "commands": scan_res.get("commands_log", ""),
            "raw": raw_path_str or "",
            "simulated": raw_path_str or "",
            "mode": "simulated",
            "trustworthy": False,
        }
        if extra_files:
            file_info.update(extra_files)

        if parser_call and raw_path_str and pathlib.Path(raw_path_str).exists():
            sim_dir = scan_dir / "simulated"
            sim_dir.mkdir(parents=True, exist_ok=True)
            sim_struct_path = sim_dir / structured_filename
            try:
                parsed_data = parser_call(pathlib.Path(raw_path_str))
                sim_struct_path.write_text(
                    json.dumps(parsed_data, indent=2), encoding="utf-8"
                )
                file_info["structured"] = str(sim_struct_path)
                file_info["structured_simulated"] = str(sim_struct_path)
            except Exception as e:
                print(f"        [!] Failed parsing simulated {tool_name}: {e}")

        evidence_manifest["evidence_files"][tool_name] = file_info
        print(
            f"        [SIMULATED] {tool_name.upper()} mock evidence saved in simulated/ (trustworthy: false)."
        )

    elif mode == "real":
        evidence_manifest.setdefault("real_tools", []).append(tool_name)
        file_info = {
            "status": status_path,
            "commands": scan_res.get("commands_log", ""),
            "raw": raw_path_str or "",
            "mode": "real",
            "trustworthy": True,
        }
        if extra_files:
            file_info.update(extra_files)

        if parser_call and raw_path_str and pathlib.Path(raw_path_str).exists():
            struct_dir = scan_dir / "structured"
            struct_dir.mkdir(parents=True, exist_ok=True)
            struct_path = struct_dir / structured_filename
            try:
                parsed_data = parser_call(pathlib.Path(raw_path_str))
                struct_path.write_text(
                    json.dumps(parsed_data, indent=2), encoding="utf-8"
                )
                file_info["structured"] = str(struct_path)
            except Exception as e:
                print(f"        [!] Failed parsing {tool_name}: {e}")

        evidence_manifest["evidence_files"][tool_name] = file_info
        print(
            f"        [OK] {tool_name.upper()} real evidence and structured JSON saved."
        )


def run_pipeline(
    raw_target: str,
    campaign_id: str = "lab-local",
    requested_tools: list[str] | None = None,
) -> dict:
    print("\n=================================================================")
    print("[*] AI-PENTEST COPILOT - MULTI-TOOL RECON PIPELINE")
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
        print("\n[!] SECURITY ALERT: TARGET BLOCKED BY SCOPE POLICY!")
        print(f"    Reason: {decision.reason}\n")
        raise ScopeViolation(decision.reason)

    target.scope.is_in_scope = True
    target.scope.scope_rule = decision.matched_rule
    registry._save()
    print(f"    [OK] Target Authorized: {decision.reason}")

    # 3. Plan Capabilities & Tools
    print("==> [3/6] Formulating Reconnaissance Plan...")
    plan = ReconPlanner.plan(target, requested_tools=requested_tools)
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
        "tool_status": {},
        "evidence_files": {},
    }

    # 4. Execute Tools
    print("\n==> [4/6] Executing Non-Destructive Tool Adapters...")

    # --- Naabu ---
    if any(s.tool == "naabu" for s in plan.steps):
        print("    --> Running Naabu port scanner...")
        scan_dir = (
            root / "toolkit" / "03-network" / "scans" / target.target_id / "naabu"
        )
        naabu_res = run_naabu_scan(
            target_id=target.target_id,
            target_host=target.host,
            port=target.port,
            output_dir=scan_dir,
        )
        handle_tool_result(
            tool_name="naabu",
            scan_res=naabu_res,
            scan_dir=scan_dir,
            evidence_manifest=evidence_manifest,
        )

    # --- Masscan ---
    if any(s.tool == "masscan" for s in plan.steps):
        print("    --> Running Masscan port discovery...")
        scan_output_dir = (
            root / "toolkit" / "03-network" / "scans" / target.target_id / "masscan"
        )
        masscan_res = run_masscan_scan(
            target_id=target.target_id,
            target_host=target.host,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "masscan_result.schema.json"
        handle_tool_result(
            tool_name="masscan",
            scan_res=masscan_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: MasscanParser.parse_raw_json(
                json_path=p,
                scan_metadata=masscan_res,
                schema_path=schema_file,
            ),
            structured_filename="masscan_result.json",
        )

    # --- RustScan ---
    if any(s.tool == "rustscan" for s in plan.steps):
        print("    --> Running RustScan port discovery...")
        scan_output_dir = (
            root / "toolkit" / "03-network" / "scans" / target.target_id / "rustscan"
        )
        rustscan_res = run_rustscan_scan(
            target_id=target.target_id,
            target_host=target.host,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "rustscan_result.schema.json"
        handle_tool_result(
            tool_name="rustscan",
            scan_res=rustscan_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: RustscanParser.parse_raw_output(
                raw_path=p,
                scan_metadata=rustscan_res,
                schema_path=schema_file,
            ),
            structured_filename="rustscan_result.json",
        )

    # --- Nmap ---
    if any(s.tool in ("nmap", "nmap-nse") for s in plan.steps):
        print("    --> Running Nmap service & version detector...")
        scan_output_dir = (
            root / "toolkit" / "03-network" / "scans" / target.target_id / "nmap"
        )
        nmap_res = run_nmap_scan(
            target_id=target.target_id,
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "nmap_result.schema.json"
        handle_tool_result(
            tool_name="nmap",
            scan_res=nmap_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: NmapParser.parse_xml_file(
                xml_path=p,
                scan_metadata={
                    "target": target.normalized_value,
                    "command": nmap_res["command"],
                    "arguments": nmap_res["arguments"],
                    "duration": nmap_res["duration"],
                    "exit_code": nmap_res["exit_code"],
                },
                schema_path=schema_file,
            ),
            structured_filename="nmap_result.json",
            extra_files={"normal": nmap_res.get("normal_txt_path", "")},
        )

        # Dynamic Service-Driven Chaining: Enrich plan with discovered open ports and services
        try:
            nmap_struct = scan_output_dir / "structured" / "nmap_result.json"
            if not nmap_struct.exists():
                nmap_struct = scan_output_dir / "simulated" / "nmap_result.json"
            if nmap_struct.exists():
                nmap_data = json.loads(nmap_struct.read_text(encoding="utf-8", errors="replace"))
                discovered_svcs = []
                for host_entry in nmap_data.get("hosts", []):
                    for p_entry in host_entry.get("ports", []):
                        if p_entry.get("state") == "open":
                            s_info = p_entry.get("service") or {}
                            discovered_svcs.append({
                                "port": p_entry.get("portid"),
                                "service": s_info.get("name", ""),
                                "product": s_info.get("product", ""),
                                "version": s_info.get("version", ""),
                            })
                if discovered_svcs:
                    chained_plan = ReconPlanner.plan(
                        target,
                        requested_tools=requested_tools,
                        detected_services=discovered_svcs,
                    )
                    existing_tools = {s.tool for s in plan.steps}
                    for c_step in chained_plan.steps:
                        if c_step.tool not in existing_tools:
                            c_step.step_number = len(plan.steps) + 1
                            plan.steps.append(c_step)
                            existing_tools.add(c_step.tool)
                            print(f"    [+] Service Chaining Auto-Scheduled: [{c_step.tool.upper()}] ({c_step.purpose})")
        except Exception:
            pass

    # --- Httpx ---
    if any(s.tool == "httpx" for s in plan.steps):
        print("    --> Running Httpx web prober...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "httpx"
        )
        httpx_res = run_httpx_scan(
            target_id=target.target_id,
            target_url=target.normalized_value,
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "httpx_result.schema.json"
        handle_tool_result(
            tool_name="httpx",
            scan_res=httpx_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: HttpxParser.parse_raw_jsonl(
                jsonl_path=p,
                scan_metadata={
                    "target": target.normalized_value,
                    "command": httpx_res["command"],
                    "arguments": httpx_res["arguments"],
                    "duration": httpx_res["duration"],
                    "exit_code": httpx_res["exit_code"],
                },
                schema_path=schema_file,
            ),
            structured_filename="httpx_result.json",
        )

    # --- WhatWeb ---
    if any(s.tool == "whatweb" for s in plan.steps):
        print("    --> Running WhatWeb technology fingerprinting...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "whatweb"
        )
        whatweb_res = run_whatweb_scan(
            target_id=target.target_id,
            target_url=target.normalized_value
            if target.type.value == "url"
            else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "whatweb_result.schema.json"
        handle_tool_result(
            tool_name="whatweb",
            scan_res=whatweb_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: WhatwebParser.parse_raw_json(
                json_path=p,
                scan_metadata=whatweb_res,
                schema_path=schema_file,
            ),
            structured_filename="whatweb_result.json",
        )

    # --- Nikto ---
    if any(s.tool == "nikto" for s in plan.steps):
        print("    --> Running Nikto web server audit...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "nikto"
        )
        nikto_res = run_nikto_scan(
            target_id=target.target_id,
            target_url=target.normalized_value
            if target.type.value == "url"
            else f"http://{target.host}",
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "nikto_result.schema.json"
        handle_tool_result(
            tool_name="nikto",
            scan_res=nikto_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: NiktoParser.parse_raw_json(
                json_path=p,
                scan_metadata=nikto_res,
                schema_path=schema_file,
            ),
            structured_filename="nikto_result.json",
        )

    # --- Katana ---
    if any(s.tool == "katana" for s in plan.steps):
        print("    --> Running Katana web crawler...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "katana"
        )
        katana_res = run_katana_scan(
            target_id=target.target_id,
            target_url=target.normalized_value
            if target.type.value == "url"
            else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "katana_result.schema.json"
        handle_tool_result(
            tool_name="katana",
            scan_res=katana_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: KatanaParser.parse_raw_jsonl(
                jsonl_path=p,
                scan_metadata=katana_res,
                schema_path=schema_file,
            ),
            structured_filename="katana_result.json",
        )

    # --- Gobuster ---
    if any(s.tool == "gobuster" for s in plan.steps):
        print("    --> Running Gobuster directory discovery...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "gobuster"
        )
        gobuster_res = run_gobuster_scan(
            target_id=target.target_id,
            target_url=target.normalized_value
            if target.type.value == "url"
            else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "gobuster_result.schema.json"
        handle_tool_result(
            tool_name="gobuster",
            scan_res=gobuster_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: GobusterParser.parse_raw_output(
                raw_path=p,
                scan_metadata=gobuster_res,
                schema_path=schema_file,
            ),
            structured_filename="gobuster_result.json",
        )

    # --- FFUF ---
    if any(s.tool == "ffuf" for s in plan.steps):
        print("    --> Running FFUF content discovery...")
        scan_output_dir = (
            root / "toolkit" / "04-web" / "scans" / target.target_id / "ffuf"
        )
        ffuf_res = run_ffuf_scan(
            target_id=target.target_id,
            target_url=target.normalized_value
            if target.type.value == "url"
            else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "ffuf_result.schema.json"
        handle_tool_result(
            tool_name="ffuf",
            scan_res=ffuf_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: FfufParser.parse_raw_json(
                json_path=p,
                scan_metadata=ffuf_res,
                schema_path=schema_file,
            ),
            structured_filename="ffuf_result.json",
        )

    # --- Nuclei ---
    if any(s.tool == "nuclei" for s in plan.steps):
        print("    --> Running Nuclei read-only vulnerability detector...")
        scan_output_dir = (
            root
            / "toolkit"
            / "05-vulnerability"
            / "scans"
            / target.target_id
            / "nuclei"
        )
        nuclei_res = run_nuclei_scan(
            target_id=target.target_id,
            target_url=target.normalized_value,
            target_host=target.host,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "nuclei_finding.schema.json"
        handle_tool_result(
            tool_name="nuclei",
            scan_res=nuclei_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: NucleiParser.parse_raw_jsonl(
                jsonl_path=p,
                scan_metadata={
                    "target": target.normalized_value,
                    "command": nuclei_res["command"],
                    "arguments": nuclei_res["arguments"],
                    "duration": nuclei_res["duration"],
                    "exit_code": nuclei_res["exit_code"],
                },
                schema_path=schema_file,
            ),
            structured_filename="nuclei_result.json",
        )

    # --- SearchSploit ---
    if any(s.tool == "searchsploit" for s in plan.steps):
        print("    --> Running SearchSploit vulnerability reference lookup...")
        scan_output_dir = (
            root
            / "toolkit"
            / "05-vulnerability"
            / "scans"
            / target.target_id
            / "searchsploit"
        )
        searchsploit_res = run_searchsploit_lookup(
            target_id=target.target_id,
            query=target.host,
            output_dir=scan_output_dir,
        )
        schema_file = root / "security" / "schemas" / "searchsploit_result.schema.json"
        handle_tool_result(
            tool_name="searchsploit",
            scan_res=searchsploit_res,
            scan_dir=scan_output_dir,
            evidence_manifest=evidence_manifest,
            parser_call=lambda p: SearchsploitParser.parse_raw_json(
                json_path=p,
                scan_metadata=searchsploit_res,
                schema_path=schema_file,
            ),
            structured_filename="searchsploit_result.json",
        )

    # --- Service Enum Tools (enum4linux, smbclient, snmpwalk, ldapsearch, database) ---
    service_tools = ["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"]
    for s_tool in service_tools:
        if any(s.tool == s_tool for s in plan.steps):
            print(f"    --> Running {s_tool} service enumeration...")
            scan_output_dir = (
                root
                / "toolkit"
                / "06-service-enum"
                / "scans"
                / target.target_id
                / s_tool
            )
            s_res = run_service_enum_scan(
                target_id=target.target_id,
                target_host=target.host,
                tool_name=s_tool,
                port=target.port,
                output_dir=scan_output_dir,
            )
            schema_file = (
                root / "security" / "schemas" / "service_enum_result.schema.json"
            )
            handle_tool_result(
                tool_name=s_tool,
                scan_res=s_res,
                scan_dir=scan_output_dir,
                evidence_manifest=evidence_manifest,
                parser_call=lambda p, st_tool=s_tool: (
                    ServiceEnumParser.parse_raw_output(
                        raw_path=p,
                        service_name=st_tool,
                        scan_metadata=s_res,
                        schema_path=schema_file,
                    )
                ),
                structured_filename=f"{s_tool}_result.json",
            )

    # --- Manual Proxy Workflows (Burp Suite, OWASP ZAP) ---
    for p_tool in ["burpsuite", "zap"]:
        if any(s.tool == p_tool for s in plan.steps):
            print(f"    --> Setting up {p_tool.upper()} manual testing workflow...")
            scan_output_dir = (
                root / "toolkit" / "08-manual" / "scans" / target.target_id / p_tool
            )
            p_res = run_proxy_manual_workflow(
                target_id=target.target_id,
                target_url=target.normalized_value
                if target.type.value == "url"
                else f"http://{target.host}",
                tool_name=p_tool,
                output_dir=scan_output_dir,
            )
            handle_tool_result(
                tool_name=p_tool,
                scan_res=p_res,
                scan_dir=scan_output_dir,
                evidence_manifest=evidence_manifest,
                structured_filename=f"{p_tool}_result.json",
            )

    # 5. Write Evidence Manifest
    print("\n==> [5/6] Consolidating Evidence Manifest...")
    manifest_dir = root / "toolkit" / "09-analysis" / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{target.target_id}_manifest.json"
    manifest_path.write_text(json.dumps(evidence_manifest, indent=2), encoding="utf-8")
    print(f"    [OK] Manifest saved at: {manifest_path}")

    # 6. Automated Findings Aggregation & Deduplication
    print("\n==> [6/6] Aggregating Evidence & Deduplicating Findings...")
    try:
        from backend.app.services.findings_builder import findings_builder

        consolidated_findings = findings_builder.generate_findings_for_target(
            target.target_id
        )
        evidence_manifest["consolidated_findings_count"] = len(
            consolidated_findings
        )
        print(
            f"    [OK] Consolidated {len(consolidated_findings)} unique deduplicated findings for target: {target.target_id}"
        )
    except Exception as fe:
        print(f"    [!] Warning: Failed to aggregate findings: {fe}")

    # Summary Output
    print("\n=================================================================")
    print("[*] RECON PIPELINE COMPLETED!")
    print(f"[*] Target ID:             {target.target_id}")
    print(
        f"[*] Tools Executed (Real):  {', '.join(evidence_manifest['tools_executed']) or 'None'}"
    )
    print(
        f"[*] Consolidated Findings: {evidence_manifest.get('consolidated_findings_count', 0)}"
    )
    print(f"[*] Evidence Manifest:      {manifest_path}")
    print("=================================================================\n")

    return evidence_manifest


def main():
    parser = argparse.ArgumentParser(description="AI-Pentest Copilot Recon Pipeline")
    parser.add_argument(
        "target", nargs="?", help="Dynamic target (IP, URL, CIDR, Domain)"
    )
    parser.add_argument(
        "--target", dest="target_opt", help="Dynamic target (optional flag)"
    )
    parser.add_argument("--campaign", default="lab-local", help="Campaign ID")
    parser.add_argument("--tools", default=None, help="Comma-separated requested tools")
    args = parser.parse_args()

    target_val = args.target or args.target_opt
    if not target_val:
        print(
            "ERROR: Target input is required. Example: python pipeline_runner.py 192.168.56.101"
        )
        sys.exit(1)

    req_tools = (
        [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else None
    )

    try:
        run_pipeline(
            raw_target=target_val, campaign_id=args.campaign, requested_tools=req_tools
        )
    except ScopeViolation:
        sys.exit(2)
    except Exception as e:
        print(f"[!] Pipeline Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
