#!/usr/bin/env python3
"""
AI-Pentest Copilot - Reconnaissance Pipeline Orchestrator.
Coordinates: Target Parse -> Normalize -> Scope Validation -> Recon Planning -> Multi-Tool Execution (Original Toolset) -> Structured Parsing & Schema Validation -> Evidence Manifest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import pathlib
import sys
from typing import Optional, List

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

# Original Toolset Runners & Parsers
from toolkit.scripts.run_nmap import run_nmap_scan
from toolkit.scripts.parse_nmap import NmapParser
from toolkit.scripts.run_naabu import run_naabu_scan
from toolkit.scripts.run_httpx import run_httpx_scan
from toolkit.scripts.parse_httpx import HttpxParser
from toolkit.scripts.run_nuclei import run_nuclei_scan
from toolkit.scripts.parse_nuclei import NucleiParser

from toolkit.scripts.run_masscan import run_masscan_scan
from toolkit.scripts.parse_masscan import MasscanParser
from toolkit.scripts.run_rustscan import run_rustscan_scan
from toolkit.scripts.parse_rustscan import RustscanParser

from toolkit.scripts.run_whatweb import run_whatweb_scan
from toolkit.scripts.parse_whatweb import WhatwebParser
from toolkit.scripts.run_nikto import run_nikto_scan
from toolkit.scripts.parse_nikto import NiktoParser
from toolkit.scripts.run_gobuster import run_gobuster_scan
from toolkit.scripts.parse_gobuster import GobusterParser
from toolkit.scripts.run_ffuf import run_ffuf_scan
from toolkit.scripts.parse_ffuf import FfufParser
from toolkit.scripts.run_katana import run_katana_scan
from toolkit.scripts.parse_katana import KatanaParser

from toolkit.scripts.run_searchsploit import run_searchsploit_lookup
from toolkit.scripts.parse_searchsploit import SearchsploitParser
from toolkit.scripts.run_service_enum import run_service_enum_scan
from toolkit.scripts.parse_service_enum import ServiceEnumParser
from toolkit.scripts.run_proxy_manual import run_proxy_manual_workflow


def run_pipeline(
    raw_target: str,
    campaign_id: str = "lab-local",
    requested_tools: Optional[List[str]] = None,
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
        print(f"\n[!] SECURITY ALERT: TARGET BLOCKED BY SCOPE POLICY!")
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

    # --- Masscan ---
    if any(s.tool == "masscan" for s in plan.steps):
        print("    --> Running Masscan port discovery...")
        scan_output_dir = root / "toolkit" / "03-network" / "scans" / target.target_id / "masscan"
        masscan_res = run_masscan_scan(
            target_id=target.target_id,
            target_host=target.host,
            output_dir=scan_output_dir,
        )
        if masscan_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "masscan_result.schema.json"
            structured_path = scan_output_dir / "structured" / "masscan_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = MasscanParser.parse_raw_json(
                json_path=pathlib.Path(masscan_res["raw_path"]),
                scan_metadata=masscan_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("masscan")
            evidence_manifest["evidence_files"]["masscan"] = {
                "raw": masscan_res["raw_path"],
                "structured": str(structured_path),
                "commands": masscan_res["commands_log"],
            }
            print(f"        [OK] Masscan evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["masscan"] = masscan_res.get("error")
            print(f"        [!] Masscan skipped: {masscan_res.get('error')}")

    # --- RustScan ---
    if any(s.tool == "rustscan" for s in plan.steps):
        print("    --> Running RustScan port discovery...")
        scan_output_dir = root / "toolkit" / "03-network" / "scans" / target.target_id / "rustscan"
        rustscan_res = run_rustscan_scan(
            target_id=target.target_id,
            target_host=target.host,
            output_dir=scan_output_dir,
        )
        if rustscan_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "rustscan_result.schema.json"
            structured_path = scan_output_dir / "structured" / "rustscan_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = RustscanParser.parse_raw_output(
                raw_path=pathlib.Path(rustscan_res["raw_path"]),
                scan_metadata=rustscan_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("rustscan")
            evidence_manifest["evidence_files"]["rustscan"] = {
                "raw": rustscan_res["raw_path"],
                "structured": str(structured_path),
                "commands": rustscan_res["commands_log"],
            }
            print(f"        [OK] RustScan evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["rustscan"] = rustscan_res.get("error")
            print(f"        [!] RustScan skipped: {rustscan_res.get('error')}")

    # --- Nmap ---
    if any(s.tool in ("nmap", "nmap-nse") for s in plan.steps):
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

    # --- Httpx ---
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

    # --- WhatWeb ---
    if any(s.tool == "whatweb" for s in plan.steps):
        print("    --> Running WhatWeb technology fingerprinting...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "whatweb"
        whatweb_res = run_whatweb_scan(
            target_id=target.target_id,
            target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        if whatweb_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "whatweb_result.schema.json"
            structured_path = scan_output_dir / "structured" / "whatweb_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = WhatwebParser.parse_raw_json(
                json_path=pathlib.Path(whatweb_res["raw_path"]),
                scan_metadata=whatweb_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("whatweb")
            evidence_manifest["evidence_files"]["whatweb"] = {
                "raw": whatweb_res["raw_path"],
                "structured": str(structured_path),
                "commands": whatweb_res["commands_log"],
            }
            print(f"        [OK] WhatWeb evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["whatweb"] = whatweb_res.get("error")
            print(f"        [!] WhatWeb skipped: {whatweb_res.get('error')}")

    # --- Nikto ---
    if any(s.tool == "nikto" for s in plan.steps):
        print("    --> Running Nikto web server audit...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "nikto"
        nikto_res = run_nikto_scan(
            target_id=target.target_id,
            target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
            target_host=target.host,
            port=target.port,
            output_dir=scan_output_dir,
        )
        if nikto_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "nikto_result.schema.json"
            structured_path = scan_output_dir / "structured" / "nikto_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = NiktoParser.parse_raw_json(
                json_path=pathlib.Path(nikto_res["raw_path"]),
                scan_metadata=nikto_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("nikto")
            evidence_manifest["evidence_files"]["nikto"] = {
                "raw": nikto_res["raw_path"],
                "structured": str(structured_path),
                "commands": nikto_res["commands_log"],
            }
            print(f"        [OK] Nikto evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["nikto"] = nikto_res.get("error")
            print(f"        [!] Nikto skipped: {nikto_res.get('error')}")

    # --- Katana ---
    if any(s.tool == "katana" for s in plan.steps):
        print("    --> Running Katana web crawler...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "katana"
        katana_res = run_katana_scan(
            target_id=target.target_id,
            target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        if katana_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "katana_result.schema.json"
            structured_path = scan_output_dir / "structured" / "katana_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = KatanaParser.parse_raw_jsonl(
                jsonl_path=pathlib.Path(katana_res["raw_path"]),
                scan_metadata=katana_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("katana")
            evidence_manifest["evidence_files"]["katana"] = {
                "raw": katana_res["raw_path"],
                "structured": str(structured_path),
                "commands": katana_res["commands_log"],
            }
            print(f"        [OK] Katana evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["katana"] = katana_res.get("error")
            print(f"        [!] Katana skipped: {katana_res.get('error')}")

    # --- Gobuster ---
    if any(s.tool == "gobuster" for s in plan.steps):
        print("    --> Running Gobuster directory discovery...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "gobuster"
        gobuster_res = run_gobuster_scan(
            target_id=target.target_id,
            target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        if gobuster_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "gobuster_result.schema.json"
            structured_path = scan_output_dir / "structured" / "gobuster_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = GobusterParser.parse_raw_output(
                raw_path=pathlib.Path(gobuster_res["raw_path"]),
                scan_metadata=gobuster_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("gobuster")
            evidence_manifest["evidence_files"]["gobuster"] = {
                "raw": gobuster_res["raw_path"],
                "structured": str(structured_path),
                "commands": gobuster_res["commands_log"],
            }
            print(f"        [OK] Gobuster evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["gobuster"] = gobuster_res.get("error")
            print(f"        [!] Gobuster skipped: {gobuster_res.get('error')}")

    # --- FFUF ---
    if any(s.tool == "ffuf" for s in plan.steps):
        print("    --> Running FFUF content discovery...")
        scan_output_dir = root / "toolkit" / "04-web" / "scans" / target.target_id / "ffuf"
        ffuf_res = run_ffuf_scan(
            target_id=target.target_id,
            target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
            output_dir=scan_output_dir,
        )
        if ffuf_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "ffuf_result.schema.json"
            structured_path = scan_output_dir / "structured" / "ffuf_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = FfufParser.parse_raw_json(
                json_path=pathlib.Path(ffuf_res["raw_path"]),
                scan_metadata=ffuf_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("ffuf")
            evidence_manifest["evidence_files"]["ffuf"] = {
                "raw": ffuf_res["raw_path"],
                "structured": str(structured_path),
                "commands": ffuf_res["commands_log"],
            }
            print(f"        [OK] FFUF evidence and structured JSON saved.")
        else:
            evidence_manifest["tool_status"]["ffuf"] = ffuf_res.get("error")
            print(f"        [!] FFUF skipped: {ffuf_res.get('error')}")

    # --- Nuclei ---
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

    # --- SearchSploit ---
    if any(s.tool == "searchsploit" for s in plan.steps):
        print("    --> Running SearchSploit vulnerability reference lookup...")
        scan_output_dir = root / "toolkit" / "05-vulnerability" / "scans" / target.target_id / "searchsploit"
        searchsploit_res = run_searchsploit_lookup(
            target_id=target.target_id,
            query=target.host,
            output_dir=scan_output_dir,
        )
        if searchsploit_res["exit_code"] == 0:
            schema_file = root / "security" / "schemas" / "searchsploit_result.schema.json"
            structured_path = scan_output_dir / "structured" / "searchsploit_result.json"
            structured_path.parent.mkdir(parents=True, exist_ok=True)
            structured_data = SearchsploitParser.parse_raw_json(
                json_path=pathlib.Path(searchsploit_res["raw_path"]),
                scan_metadata=searchsploit_res,
                schema_path=schema_file,
            )
            structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
            evidence_manifest["tools_executed"].append("searchsploit")
            evidence_manifest["evidence_files"]["searchsploit"] = {
                "raw": searchsploit_res["raw_path"],
                "structured": str(structured_path),
                "commands": searchsploit_res["commands_log"],
            }
            print(f"        [OK] SearchSploit reference evidence saved.")
        else:
            evidence_manifest["tool_status"]["searchsploit"] = searchsploit_res.get("error")
            print(f"        [!] SearchSploit skipped: {searchsploit_res.get('error')}")

    # --- Service Enum Tools (enum4linux, smbclient, snmpwalk, ldapsearch, database) ---
    service_tools = ["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"]
    for s_tool in service_tools:
        if any(s.tool == s_tool for s in plan.steps):
            print(f"    --> Running {s_tool} service enumeration...")
            scan_output_dir = root / "toolkit" / "06-service-enum" / "scans" / target.target_id / s_tool
            s_res = run_service_enum_scan(
                target_id=target.target_id,
                target_host=target.host,
                tool_name=s_tool,
                port=target.port,
                output_dir=scan_output_dir,
            )
            if s_res["exit_code"] == 0:
                schema_file = root / "security" / "schemas" / "service_enum_result.schema.json"
                structured_path = scan_output_dir / "structured" / f"{s_tool}_result.json"
                structured_path.parent.mkdir(parents=True, exist_ok=True)
                structured_data = ServiceEnumParser.parse_raw_output(
                    raw_path=pathlib.Path(s_res["raw_path"]),
                    service_name=s_tool,
                    scan_metadata=s_res,
                    schema_path=schema_file,
                )
                structured_path.write_text(json.dumps(structured_data, indent=2), encoding="utf-8")
                evidence_manifest["tools_executed"].append(s_tool)
                evidence_manifest["evidence_files"][s_tool] = {
                    "raw": s_res["raw_path"],
                    "structured": str(structured_path),
                    "commands": s_res["commands_log"],
                }
                print(f"        [OK] {s_tool} evidence and structured JSON saved.")
            else:
                evidence_manifest["tool_status"][s_tool] = s_res.get("error")
                print(f"        [!] {s_tool} skipped: {s_res.get('error')}")

    # --- Manual Proxy Workflows (Burp Suite, OWASP ZAP) ---
    for p_tool in ["burpsuite", "zap"]:
        if any(s.tool == p_tool for s in plan.steps):
            print(f"    --> Setting up {p_tool.upper()} manual testing workflow...")
            scan_output_dir = root / "toolkit" / "08-manual" / "scans" / target.target_id / p_tool
            p_res = run_proxy_manual_workflow(
                target_id=target.target_id,
                target_url=target.normalized_value if target.type.value == "url" else f"http://{target.host}",
                tool_name=p_tool,
                output_dir=scan_output_dir,
            )
            evidence_manifest["tools_executed"].append(p_tool)
            evidence_manifest["evidence_files"][p_tool] = {
                "raw": p_res["raw_path"],
                "structured": p_res["structured_path"],
                "commands": p_res["commands_log"],
            }
            print(f"        [OK] {p_tool} manual proxy workflow prepared.")

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
    parser.add_argument("--tools", default=None, help="Comma-separated requested tools")
    args = parser.parse_args()

    target_val = args.target or args.target_opt
    if not target_val:
        print("ERROR: Target input is required. Example: python pipeline_runner.py 192.168.56.101")
        sys.exit(1)

    req_tools = [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else None

    try:
        run_pipeline(raw_target=target_val, campaign_id=args.campaign, requested_tools=req_tools)
    except ScopeViolation:
        sys.exit(2)
    except Exception as e:
        print(f"[!] Pipeline Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
