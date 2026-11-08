"""AI-Pentest Copilot - Tool Registry & Declarative YAML Catalog.
Source of Truth for Integrated Pentest Toolset:
- Network: Nmap, Masscan, RustScan, Naabu, TestSSL.sh, theHarvester
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
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ToolDockerConfig(BaseModel):
    image: str = "ai-pentest-tools:latest"
    binary: str = ""
    default_args: list[str] = Field(default_factory=list)


class ToolDefinition(BaseModel):
    tool_id: str
    name: str
    category: str  # network, web, vulnerability, service_enum, proxy_manual
    binary: str
    version_command: list[str] = Field(default_factory=lambda: ["--version"])
    target_types: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    input_types: list[str] = Field(default_factory=list)
    output_formats: list[str] = Field(default_factory=list)
    risk_level: str = "safe"  # safe, controlled, manual
    requires_user_confirmation: bool = False
    parser: str
    evidence_directory: str
    enabled: bool = True
    binary_lookup_paths: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    safe_flags: list[str] = Field(default_factory=list)
    docker: ToolDockerConfig | None = None


class ToolAvailability(BaseModel):
    tool_id: str
    name: str
    category: str
    installed: bool
    binary_path: str | None = None
    version: str | None = None
    enabled: bool = True
    error: str | None = None
    docker_available: bool = False
    docker_image: str | None = None
    tags: list[str] = Field(default_factory=list)


class ToolRegistry:
    """Registry maintaining metadata, YAML catalog definitions, and availability status for all tools."""

    CATALOG_DIR = pathlib.Path(__file__).resolve().parent.parent / "catalog" / "tools"

    # Built-in fallback definitions to ensure resilient operation even without filesystem catalog
    DEFAULT_TOOLS: dict[str, ToolDefinition] = {
        # --- Network Recon ---
        "nmap": ToolDefinition(
            tool_id="nmap",
            name="Nmap",
            category="network",
            binary="nmap",
            version_command=["--version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="nmap"),
            target_types=["ipv4", "ipv6", "cidr", "domain", "hostname", "host_port"],
            capabilities=["port_scan", "service_detection", "version_detection", "nse"],
            input_types=["ip", "cidr", "hostname"],
            output_formats=["xml", "normal"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nmap.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "port-scan", "service-fingerprint", "core", "nmap"],
            safe_flags=["-sV", "-Pn", "-T4", "-F", "--script=safe"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="masscan"),
            target_types=["ipv4", "cidr", "ipv6"],
            capabilities=["fast_port_discovery", "large_scale_scan"],
            input_types=["ip", "cidr"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_masscan.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "port-scan", "syn-scan", "fast"],
            safe_flags=["--rate", "1000"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="rustscan"),
            target_types=["ipv4", "domain", "hostname", "cidr"],
            capabilities=["fast_port_discovery", "nmap_pipe"],
            input_types=["ip", "hostname"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_rustscan.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "port-scan", "adaptive", "rust"],
            safe_flags=["--top", "-b", "500"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="naabu"),
            target_types=["ipv4", "domain", "hostname", "cidr"],
            capabilities=["fast_port_discovery"],
            input_types=["ip", "hostname"],
            output_formats=["raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_naabu.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "port-scan", "projectdiscovery"],
            safe_flags=["-rate", "1000"],
            binary_lookup_paths=[],
        ),
        "testssl": ToolDefinition(
            tool_id="testssl",
            name="TestSSL.sh",
            category="network",
            binary="testssl.sh",
            version_command=["--version"],
            docker=ToolDockerConfig(image="drwetter/testssl.sh:latest", binary="testssl.sh"),
            target_types=["domain", "hostname", "ipv4", "url"],
            capabilities=["ssl_tls_audit", "ciphersuite_check", "certificate_inspection"],
            input_types=["host_port", "url"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_testssl.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "ssl", "tls", "crypto", "audit", "compliance"],
            safe_flags=["--quiet", "--fast"],
            binary_lookup_paths=[],
        ),
        "theharvester": ToolDefinition(
            tool_id="theharvester",
            name="theHarvester",
            category="network",
            binary="theHarvester",
            version_command=["-h"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="theHarvester"),
            target_types=["domain", "hostname"],
            capabilities=["osint_recon", "subdomain_enumeration", "email_harvesting"],
            input_types=["domain"],
            output_formats=["json", "xml"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_theharvester.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["network", "osint", "subdomains", "recon"],
            safe_flags=["-l", "100", "-b", "duckduckgo"],
            binary_lookup_paths=[],
        ),
        # --- Web ---
        "httpx": ToolDefinition(
            tool_id="httpx",
            name="HTTPx",
            category="web",
            binary="httpx",
            version_command=["-version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="httpx"),
            target_types=["url", "host_port", "domain", "hostname"],
            capabilities=["web_probing", "status_code", "title", "tech_detection"],
            input_types=["url", "host"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_httpx.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "probe", "http", "tech-detection", "projectdiscovery"],
            safe_flags=["-silent", "-status-code", "-title", "-tech-detect"],
            binary_lookup_paths=[],
        ),
        "whatweb": ToolDefinition(
            tool_id="whatweb",
            name="WhatWeb",
            category="web",
            binary="whatweb",
            version_command=["--version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="whatweb"),
            target_types=["url", "host_port", "domain"],
            capabilities=[
                "technology_fingerprinting",
                "plugin_detection",
                "web_server_version",
            ],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_whatweb.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "fingerprint", "cms", "technology"],
            safe_flags=["-a", "1"],
            binary_lookup_paths=[],
        ),
        "nikto": ToolDefinition(
            tool_id="nikto",
            name="Nikto",
            category="web",
            binary="nikto",
            version_command=["-Version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="nikto"),
            target_types=["url", "host_port", "domain"],
            capabilities=[
                "web_security_audit",
                "misconfiguration_detection",
                "outdated_components",
            ],
            input_types=["url", "host_port"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_nikto.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "misconfiguration", "audit", "server-scan"],
            safe_flags=["-Tuning", "123b"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="gobuster"),
            target_types=["url", "host_port"],
            capabilities=["directory_discovery", "file_discovery", "dns_discovery"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_gobuster.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "content-discovery", "directory-bruteforce"],
            safe_flags=["--threads", "10"],
            binary_lookup_paths=[],
        ),
        "ffuf": ToolDefinition(
            tool_id="ffuf",
            name="FFUF",
            category="web",
            binary="ffuf",
            version_command=["-V"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="ffuf"),
            target_types=["url", "host_port"],
            capabilities=["content_discovery", "path_fuzzing", "parameter_discovery"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="controlled",
            requires_user_confirmation=True,
            parser="parse_ffuf.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "fuzzing", "content-discovery", "fast"],
            safe_flags=["-rate", "50"],
            binary_lookup_paths=[],
        ),
        "katana": ToolDefinition(
            tool_id="katana",
            name="Katana",
            category="web",
            binary="katana",
            version_command=["-version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="katana"),
            target_types=["url", "host_port"],
            capabilities=["web_crawling", "endpoint_discovery", "form_extraction"],
            input_types=["url"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_katana.py",
            evidence_directory="toolkit/04-web/scans",
            enabled=True,
            tags=["web", "crawler", "endpoints", "spider", "projectdiscovery"],
            safe_flags=["-depth", "2", "-rate-limit", "20"],
            binary_lookup_paths=[],
        ),
        # --- Vulnerability ---
        "nuclei": ToolDefinition(
            tool_id="nuclei",
            name="Nuclei",
            category="vulnerability",
            binary="nuclei",
            version_command=["-version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="nuclei"),
            target_types=["url", "host_port", "domain", "ipv4"],
            capabilities=[
                "template_vulnerability_scan",
                "cve_detection",
                "misconfiguration_check",
            ],
            input_types=["url", "host"],
            output_formats=["jsonl", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nuclei.py",
            evidence_directory="toolkit/05-vulnerability/scans",
            enabled=True,
            tags=["vulnerability", "templates", "cve", "dast", "projectdiscovery"],
            safe_flags=["-tags", "cve", "-severity", "low,medium,high,critical", "-rate-limit", "50"],
            binary_lookup_paths=[],
        ),
        "nmap-nse": ToolDefinition(
            tool_id="nmap-nse",
            name="Nmap NSE",
            category="vulnerability",
            binary="nmap",
            version_command=["--version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="nmap"),
            target_types=["ipv4", "ipv6", "domain", "host_port"],
            capabilities=["safe_nse_scripts", "vuln_check", "service_audit"],
            input_types=["ip", "hostname"],
            output_formats=["xml", "normal"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_nmap.py",
            evidence_directory="toolkit/03-network/scans",
            enabled=True,
            tags=["vulnerability", "nse", "nmap", "safe-scripts"],
            safe_flags=["--script=vuln and safe"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="searchsploit"),
            target_types=["custom"],
            capabilities=[
                "exploit_db_lookup",
                "cve_reference_search",
                "offline_reference",
            ],
            input_types=["product_version"],
            output_formats=["json", "raw"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_searchsploit.py",
            evidence_directory="toolkit/05-vulnerability/scans",
            enabled=True,
            tags=["vulnerability", "exploitdb", "offline", "cve-lookup"],
            safe_flags=["--json"],
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
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="enum4linux"),
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["smb_enumeration", "user_enumeration", "share_enumeration"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            tags=["service-enum", "smb", "windows", "shares"],
            safe_flags=["-a"],
            binary_lookup_paths=[],
        ),
        "smbclient": ToolDefinition(
            tool_id="smbclient",
            name="smbclient",
            category="service_enum",
            binary="smbclient",
            version_command=["--version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="smbclient"),
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["smb_share_listing", "null_session_check"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            tags=["service-enum", "smb", "samba", "shares"],
            safe_flags=["-N", "-L"],
            binary_lookup_paths=[],
        ),
        "snmpwalk": ToolDefinition(
            tool_id="snmpwalk",
            name="snmpwalk",
            category="service_enum",
            binary="snmpwalk",
            version_command=["-V"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="snmpwalk"),
            target_types=["ipv4", "hostname"],
            capabilities=["snmp_oid_walk", "system_info_query"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            tags=["service-enum", "snmp", "network-device", "oid"],
            safe_flags=["-v2c", "-c", "public"],
            binary_lookup_paths=[],
        ),
        "ldapsearch": ToolDefinition(
            tool_id="ldapsearch",
            name="ldapsearch",
            category="service_enum",
            binary="ldapsearch",
            version_command=["-VV"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="ldapsearch"),
            target_types=["ipv4", "domain", "hostname"],
            capabilities=["ldap_query", "directory_enumeration"],
            input_types=["ip", "hostname"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            tags=["service-enum", "ldap", "active-directory"],
            safe_flags=["-x", "-s", "base"],
            binary_lookup_paths=[],
        ),
        "database": ToolDefinition(
            tool_id="database",
            name="Database Clients",
            category="service_enum",
            binary="mysql",
            version_command=["--version"],
            docker=ToolDockerConfig(image="ai-pentest-tools:latest", binary="mysql"),
            target_types=["ipv4", "host_port"],
            capabilities=["db_banner_probe", "anonymous_login_check", "ping_check"],
            input_types=["host_port"],
            output_formats=["raw", "json"],
            risk_level="safe",
            requires_user_confirmation=False,
            parser="parse_service_enum.py",
            evidence_directory="toolkit/06-service-enum/scans",
            enabled=True,
            tags=["service-enum", "database", "mysql", "postgres"],
            safe_flags=["--connect-timeout=5"],
            binary_lookup_paths=[],
        ),
        # --- Web Proxy / Manual Testing ---
        "burpsuite": ToolDefinition(
            tool_id="burpsuite",
            name="Burp Suite",
            category="proxy_manual",
            binary="burpsuite",
            version_command=["--help"],
            docker=None,
            target_types=["url", "host_port"],
            capabilities=[
                "traffic_interception",
                "controlled_manual_testing",
                "session_recording",
            ],
            input_types=["url"],
            output_formats=["xml", "json"],
            risk_level="manual",
            requires_user_confirmation=True,
            parser="parse_manual_proxy.py",
            evidence_directory="toolkit/08-manual/scans",
            enabled=True,
            tags=["proxy", "manual", "burp", "gui"],
            safe_flags=[],
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
            docker=ToolDockerConfig(image="zaproxy/zap-stable:latest", binary="zap.sh"),
            target_types=["url", "host_port"],
            capabilities=["proxy_workflow", "passive_analysis", "controlled_api_scan"],
            input_types=["url"],
            output_formats=["json", "raw"],
            risk_level="manual",
            requires_user_confirmation=True,
            parser="parse_manual_proxy.py",
            evidence_directory="toolkit/08-manual/scans",
            enabled=True,
            tags=["proxy", "manual", "zap", "owasp"],
            safe_flags=["-cmd", "-quickscan"],
            binary_lookup_paths=[
                r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
                r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
            ],
        ),
    }

    _catalog_tools: dict[str, ToolDefinition] = {}

    @classmethod
    def load_catalog(cls) -> dict[str, ToolDefinition]:
        """Loads all YAML tool definitions from CATALOG_DIR."""
        tools: dict[str, ToolDefinition] = {}
        if cls.CATALOG_DIR.exists() and cls.CATALOG_DIR.is_dir():
            for yaml_file in cls.CATALOG_DIR.glob("*.y*ml"):
                try:
                    content = yaml_file.read_text(encoding="utf-8")
                    data = yaml.safe_load(content)
                    if not data or not isinstance(data, dict) or "tool_id" not in data:
                        continue
                    if data.get("docker") and isinstance(data["docker"], dict):
                        data["docker"] = ToolDockerConfig(**data["docker"])
                    tool_def = ToolDefinition(**data)
                    tools[tool_def.tool_id] = tool_def
                except Exception as e:
                    print(f"[!] Warning: Failed parsing YAML catalog tool {yaml_file.name}: {e}")

        # Fallback & merge: ensure any default tools not in catalog remain available
        merged = cls.DEFAULT_TOOLS.copy()
        merged.update(tools)
        cls._catalog_tools = merged
        # Also update DEFAULT_TOOLS so existing references get the full catalog
        cls.DEFAULT_TOOLS.update(tools)
        return cls._catalog_tools

    @classmethod
    def get_tools_dict(cls) -> dict[str, ToolDefinition]:
        if not cls._catalog_tools:
            cls.load_catalog()
        return cls._catalog_tools or cls.DEFAULT_TOOLS

    @classmethod
    def reload_catalog(cls) -> int:
        cls._catalog_tools.clear()
        cls.load_catalog()
        return len(cls._catalog_tools)

    @classmethod
    def resolve_binary(cls, tool_def: ToolDefinition) -> str | None:
        """Find the real executable path for a tool."""
        # 1. Standard PATH
        which_path = shutil.which(tool_def.binary)
        if which_path:
            return which_path

        # 2. Explicit candidate locations
        for p in tool_def.binary_lookup_paths:
            if os.path.exists(p):
                return p

        # 3. Alternate extensions and naming conventions
        alt_names: list[str] = []
        if tool_def.binary.endswith(".sh"):
            alt_names.append(tool_def.binary[:-3])
        elif tool_def.binary.endswith(".bat"):
            alt_names.append(tool_def.binary[:-4])
            if tool_def.tool_id == "zap":
                alt_names.extend(["zaproxy", "zap.sh", "zap"])
        elif tool_def.tool_id == "theharvester":
            alt_names.extend(["theHarvester", "theharvester.py"])
        elif tool_def.tool_id == "enum4linux":
            alt_names.extend(["enum4linux.pl", "enum4linux-ng"])
        elif tool_def.tool_id == "burpsuite":
            alt_names.extend(["BurpSuiteCommunity", "BurpSuitePro", "burpsuite"])

        for alt in alt_names:
            alt_path = shutil.which(alt)
            if alt_path:
                return alt_path

        return None

    @classmethod
    def get_version(cls, binary_path: str, version_cmd: list[str]) -> str | None:
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
        """Check if a specific tool is installed locally or accessible via Docker."""
        tools_dict = cls.get_tools_dict()
        tool_def = tools_dict.get(tool_id)
        if not tool_def:
            return ToolAvailability(
                tool_id=tool_id,
                name=tool_id,
                category="unknown",
                installed=False,
                error=f"Tool '{tool_id}' is not defined in ToolRegistry.",
            )

        docker_image = tool_def.docker.image if tool_def.docker else None
        docker_available = bool(docker_image)

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
                            docker_available=docker_available,
                            docker_image=docker_image,
                            tags=tool_def.tags,
                        )
            return ToolAvailability(
                tool_id=tool_id,
                name=tool_def.name,
                category=tool_def.category,
                installed=False,
                enabled=tool_def.enabled,
                error=f"Binary '{tool_def.binary}' was not found in PATH or standard install locations.",
                docker_available=docker_available,
                docker_image=docker_image,
                tags=tool_def.tags,
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
            docker_available=docker_available,
            docker_image=docker_image,
            tags=tool_def.tags,
        )

    @classmethod
    def list_tools(
        cls, category: str | None = None, tag: str | None = None
    ) -> list[ToolDefinition]:
        tools = list(cls.get_tools_dict().values())
        if category:
            tools = [t for t in tools if t.category == category]
        if tag:
            tag_lower = tag.lower().strip()
            tools = [t for t in tools if tag_lower in [x.lower() for x in t.tags]]
        return tools

    @classmethod
    def get_tool(cls, tool_id: str) -> ToolDefinition | None:
        return cls.get_tools_dict().get(tool_id)

    @classmethod
    def list_tags(cls) -> list[str]:
        """Returns a sorted deduplicated list of all tags present in the catalog."""
        tags_set: set[str] = set()
        for t in cls.get_tools_dict().values():
            tags_set.update(t.tags)
        return sorted(tags_set)

    @classmethod
    def list_compatible_tool_ids(cls, target_type: str) -> list[str]:
        """Returns list of tool_ids compatible with a given target type (e.g. 'ipv4', 'url')."""
        tt_lower = target_type.lower().strip()
        matched: list[str] = []
        for tid, tdef in cls.get_tools_dict().items():
            if not tdef.enabled:
                continue
            if any(tt_lower == tt.lower() for tt in tdef.target_types) or "custom" in tdef.target_types:
                matched.append(tid)
        return matched

    @classmethod
    def get_all_availability(cls) -> dict[str, ToolAvailability]:
        """Returns availability status for all tools in registry."""
        tools_dict = cls.get_tools_dict()
        return {tid: cls.check_availability(tid) for tid in tools_dict}


tool_registry = ToolRegistry()
# Preload catalog on module import
tool_registry.load_catalog()
