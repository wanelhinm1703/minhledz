"""AI-Pentest Copilot - Tool Registry & Availability Detection.
Source of Truth for Original Toolset:
- Network: Nmap, Masscan, RustScan (Naabu preserved as secondary)
- Web: HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana
- Vulnerability: Nuclei, Nmap NSE, SearchSploit
- Web Proxy / Manual: Burp Suite, OWASP ZAP
- Service Enumeration: enum4linux, smbclient, snmpwalk, ldapsearch, database clients
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ToolDefinition(BaseModel):
    tool_id: str
    name: str
    category: str  # network, web, vulnerability, service_enum, proxy_manual
    binary: str
    version_command: List[str] = Field(default_factory=lambda: ["--version"])
    target_types: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    input_types: List[str] = Field(default_factory=list)
    output_formats: List[str] = Field(default_factory=list)
    risk_level: str = "safe"  # safe, controlled, manual
    requires_user_confirmation: bool = False
    parser: str
    evidence_directory: str
    enabled: bool = True
    binary_lookup_paths: List[str] = Field(default_factory=list)


class ToolAvailability(BaseModel):
    tool_id: str
    name: str
    category: str
    installed: bool
    binary_path: Optional[str] = None
    version: Optional[str] = None
    enabled: bool = True
    error: Optional[str] = None


class ToolRegistry:
    """Registry maintaining metadata and availability status for all supported tools."""

    DEFAULT_TOOLS: Dict[str, ToolDefinition] = {
        # --- Network Recon ---
        "nmap": ToolDefinition(
            tool_id="nmap",
            name="Nmap",
            category="network",
            binary="nmap",
            version_command=["--version"],
            target_types=["ipv4", "ipv6", "cidr", "domain", "hostname", "host_port"],
            capabilities=["port_scan", "service_detection", "version_detection", "nse"],
            input_types=["ip", "cidr", "hostname"],
            output_formats=["xml", "normal"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nmap.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\ProgramData\chocolatey\bin\nmap.exe",
                r"C:\tools\nmap\nmap.exe",
            ],
        ),
        "masscan": ToolDefinition(
            tool_id="masscan",
            name="Masscan",
            category="network",
            binary="masscan",
            version_command=["--version"],
            target_types=["ipv4", "cidr", "ipv6"],
            capabilities=["fast_port_discovery", "large_scale_scan"],
            input_types=["ip", "cidr"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_masscan.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\masscan\masscan.exe",
                r"C:\ProgramData\chocolatey\bin\masscan.exe",
            ],
        ),
        "rustscan": ToolDefinition(
            tool_id="rustscan",
            name="RustScan",
            category="network",
            binary="rustscan",
            version_command=["--version"],
            target_types=["ipv4", "domain", "hostname", "cidr"],
            capabilities=["fast_port_discovery", "nmap_pipe"],
            input_types=["ip", "hostname"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_rustscan.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\rustscan\rustscan.exe",
                r"C:\Users\DUC_THUAN\.cargo\bin\rustscan.exe",
            ],
        ),
        "naabu": ToolDefinition(
            tool_id="naabu",
            name="Naabu",
            category="network",
            binary="naabu",
            version_command=["-version"],
            target_types=["ipv4", "domain", "hostname", "cidr"],
            capabilities=["fast_port_discovery"],
            input_types=["ip", "hostname"],
            output_formats=["raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_naabu.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),

        # --- Web ---
        "httpx": ToolDefinition(
            tool_id="httpx",
            name="HTTPx",
            category="web",
            binary="httpx",
            version_command=["-version"],
            target_types=["url", "host_port", "domain", "hostname"],
            capabilities=["web_probing", "status_code", "title", "tech_detection"],
            input_types=["url", "host"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_httpx.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "whatweb": ToolDefinition(
            tool_id="whatweb",
            name="WhatWeb",
            category="web",
            binary="whatweb",
            version_command=["--version"],
            target_types=["url", "host_port", "domain"],
            capabilities=["technology_fingerprinting", "plugin_detection", "web_server_version"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_whatweb.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "nikto": ToolDefinition(
            tool_id="nikto",
            name="Nikto",
            category="web",
            binary="nikto",
            version_command=["-Version"],
            target_types=["url", "host_port", "domain"],
            capabilities=["web_security_audit", "misconfiguration_detection", "outdated_components"],
            input_types=["url", "host_port"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_nikto.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\ProgramData\chocolatey\bin\nikto.bat",
                r"C:\nikto\program\nikto.pl",
            ],
        ),
        "gobuster": ToolDefinition(
            tool_id="gobuster",
            name="Gobuster",
            category="web",
            binary="gobuster",
            version_command=["version"],
            target_types=["url", "host_port"],
            capabilities=["directory_discovery", "file_discovery", "dns_discovery"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_gobuster.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "ffuf": ToolDefinition(
            tool_id="ffuf",
            name="FFUF",
            category="web",
            binary="ffuf",
            version_command=["-V"],
            target_types=["url", "host_port"],
            capabilities=["content_discovery", "path_fuzzing", "parameter_discovery"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_ffuf.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "katana": ToolDefinition(
            tool_id="katana",
            name="Katana",
            category="web",
            binary="katana",
            version_command=["-version"],
            target_types=["url", "host_port"],
            capabilities=["web_crawling", "endpoint_discovery", "form_extraction"],
            input_types=["url"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_katana.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),

        # --- Vulnerability ---
        "nuclei": ToolDefinition(
            tool_id="nuclei",
            name="Nuclei",
            category="vulnerability",
            binary="nuclei",
            version_command=["-version"],
            target_types=["url", "host_port", "domain", "ipv4"],
            capabilities=["template_vulnerability_scan", "cve_detection", "misconfiguration_check"],
            input_types=["url", "host"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nuclei.py",
            evidence_directory="toolkit/05-vulnerability/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "nmap-nse": ToolDefinition(
            tool_id="nmap-nse",
            name="Nmap NSE",
            category="vulnerability",
            binary="nmap",
            version_command=["--version"],
            target_types=["ipv4", "ipv6", "domain", "host_port"],
            capabilities=["safe_nse_scripts", "vuln_check", "service_audit"],
            input_types=["ip", "hostname"],
            output_formats=["xml", "normal"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nmap.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ],
        ),
        "searchsploit": ToolDefinition(
            tool_id="searchsploit",
            name="SearchSploit",
            category="vulnerability",
            binary="searchsploit",
            version_command=["-h"],
            target_types=["custom"],
            capabilities=["exploit_db_lookup", "cve_reference_search", "offline_reference"],
            input_types=["product_version"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_searchsploit.py",
            evidence_directory="toolkit/05-vulnerability/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\ProgramData\chocolatey\bin\searchsploit.bat",
            ],
        ),

        # --- Service Enumeration ---
        "enum4linux": ToolDefinition(
            tool_id="enum4linux",
            name="enum4linux",
            category="service_enum",
            binary="enum4linux",
            version_command=["-h"],
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["smb_enumeration", "user_enumeration", "share_enumeration"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "smbclient": ToolDefinition(
            tool_id="smbclient",
            name="smbclient",
            category="service_enum",
            binary="smbclient",
            version_command=["--version"],
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["smb_share_listing", "null_session_check"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "snmpwalk": ToolDefinition(
            tool_id="snmpwalk",
            name="snmpwalk",
            category="service_enum",
            binary="snmpwalk",
            version_command=["-V"],
            target_types=["ipv4", "hostname"],
            capabilities=["snmp_oid_walk", "system_info_query"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "ldapsearch": ToolDefinition(
            tool_id="ldapsearch",
            name="ldapsearch",
            category="service_enum",
            binary="ldapsearch",
            version_command=["-VV"],
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["ldap_query", "directory_enumeration"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),
        "database": ToolDefinition(
            tool_id="database",
            name="Database Clients",
            category="service_enum",
            binary="mysql",
            version_command=["--version"],
            target_types=["ipv4", "host_port"],
            capabilities=["db_banner_probe", "anonymous_login_check", "ping_check"],
            input_types=["host_port"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            binary_lookup_paths=[],
        ),

        # --- Web Proxy / Manual Testing ---
        "burpsuite": ToolDefinition(
            tool_id="burpsuite",
            name="Burp Suite",
            category="proxy_manual",
            binary="burpsuite",
            version_command=["--help"],
            target_types=["url", "host_port"],
            capabilities=["traffic_interception", "controlled_manual_testing", "session_recording"],
            input_types=["url"],
            output_formats=["xml", "json"],
            risk_level="manual",
            requires_user_confirmation=True,
            parser="parse_manual_proxy.py",
            evidence_directory="toolkit/08-manual/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
                r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
            ],
        ),
        "zap": ToolDefinition(
            tool_id="zap",
            name="OWASP ZAP",
            category="proxy_manual",
            binary="zap.bat",
            version_command=["-version"],
            target_types=["url", "host_port"],
            capabilities=["proxy_workflow", "passive_analysis", "controlled_api_scan"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="manual",
            requires_user_confirmation=True,
            parser="parse_manual_proxy.py",
            evidence_directory="toolkit/08-manual/scans",
            enabled=True,
            binary_lookup_paths=[
                r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
                r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            ],
        ),
    }

    @classmethod
    def resolve_binary(cls, tool_def: ToolDefinition) -> Optional[str]:
        """Find the real executable path for a tool."""
        # 1. Standard PATH
        which_path = shutil.which(tool_def.binary)
        if which_path:
            return which_path

        # 2. Explicit Windows candidate locations
        for p in tool_def.binary_lookup_paths:
            if os.path.exists(p):
                return p

        return None

    @classmethod
    def get_version(cls, binary_path: str, version_cmd: List[str]) -> Optional[str]:
        """Attempt to extract version string from tool execution."""
        try:
            cmd = [binary_path] + version_cmd
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = (res.stdout or "") + (res.stderr or "")
            lines = [l.strip() for l in output.splitlines() if l.strip()]
            if lines:
                return lines[0][:80]
        except Exception:
            pass
        return None

    @classmethod
    def check_availability(cls, tool_id: str) -> ToolAvailability:
        """Check if a specific tool is installed and return its status."""
        tool_def = cls.DEFAULT_TOOLS.get(tool_id)
        if not tool_def:
            return ToolAvailability(
                tool_id=tool_id,
                name=tool_id,
                category="unknown",
                installed=False,
                error=f"Tool '{tool_id}' is not defined in ToolRegistry.",
            )

        bin_path = cls.resolve_binary(tool_def)
        if not bin_path:
            # Special check for database category: check if any DB client is installed
            if tool_id == "database":
                db_clients = ["mysql", "psql", "redis-cli", "mongosh", "sqlcmd"]
                for dbc in db_clients:
                    db_p = shutil.which(dbc)
                    if db_p:
                        ver = cls.get_version(db_p, ["--version"])
                        return ToolAvailability(
                            tool_id=tool_id,
                            name=f"Database ({dbc})",
                            category=tool_def.category,
                            installed=True,
                            binary_path=db_p,
                            version=ver,
                            enabled=tool_def.enabled,
                        )
            return ToolAvailability(
                tool_id=tool_id,
                name=tool_def.name,
                category=tool_def.category,
                installed=False,
                enabled=tool_def.enabled,
                error=f"Binary '{tool_def.binary}' was not found in PATH or standard install locations.",
            )

        ver = cls.get_version(bin_path, tool_def.version_command)
        return ToolAvailability(
            tool_id=tool_id,
            name=tool_def.name,
            category=tool_def.category,
            installed=True,
            binary_path=bin_path,
            version=ver,
            enabled=tool_def.enabled,
        )

    @classmethod
    def list_tools(cls, category: Optional[str] = None) -> List[ToolDefinition]:
        tools = list(cls.DEFAULT_TOOLS.values())
        if category:
            return [t for t in tools if t.category == category]
        return tools

    @classmethod
    def get_tool(cls, tool_id: str) -> Optional[ToolDefinition]:
        return cls.DEFAULT_TOOLS.get(tool_id)

    @classmethod
    def get_all_availability(cls) -> Dict[str, ToolAvailability]:
        """Returns availability status for all tools in registry."""
        return {tid: cls.check_availability(tid) for tid in cls.DEFAULT_TOOLS}


tool_registry = ToolRegistry()
