from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from backend.app.schemas.target import Target, TargetType


class ReconStep(BaseModel):
    step_number: int
    tool: str
    purpose: str
    command_template: str
    safety_constraints: list[str] = Field(default_factory=list)
    profile: str | None = None


class ReconPlan(BaseModel):
    target_id: str
    target_type: TargetType
    target_host: str
    capabilities: list[str]
    steps: list[ReconStep]
    estimated_duration_seconds: int = 120
    safety_summary: str = "Read-only non-destructive reconnaissance pipeline"


class ReconPlanner:
    """
    Maps Target Capabilities & Detected Services -> Multi-tool Recon Steps.
    Source of truth for Original Toolset:
    - Network: Nmap, Masscan, RustScan (Naabu preserved)
    - Web: HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana
    - Vulnerability: Nuclei, Nmap NSE, SearchSploit
    - Service Enumeration: enum4linux, smbclient, snmpwalk, ldapsearch, database clients
    - Web Proxy / Manual: Burp Suite, OWASP ZAP
    """

    @classmethod
    def plan(
        cls,
        target: Target,
        requested_tools: list[str] | None = None,
        detected_services: list[dict[str, Any]] | None = None,
    ) -> ReconPlan:
        capabilities = []
        steps = []
        step_idx = 1

        is_web = target.type == TargetType.URL or (
            target.port in [80, 443, 3000, 8080, 8443]
        )

        # 1. Base capabilities assignment
        if is_web:
            capabilities.extend(
                ["web", "http_probing", "vulnerability_detection", "service_discovery"]
            )
        elif target.type == TargetType.HOST_PORT:
            capabilities.extend(["network", "service_discovery"])
        elif target.type in (
            TargetType.IPV4,
            TargetType.IPV6,
            TargetType.DOMAIN,
            TargetType.HOSTNAME,
        ):
            capabilities.extend(["network", "port_discovery", "service_discovery"])
        elif target.type == TargetType.CIDR:
            capabilities.extend(["network", "host_discovery"])

        # 2. If explicit tools requested by user/workflow: prioritize them
        if requested_tools:
            expanded_requested = []
            for rt in requested_tools:
                rtl = rt.lower().strip()
                if rtl in ("all", "full"):
                    expanded_requested.extend([
                        "masscan", "rustscan", "naabu", "nmap", "httpx", "whatweb", "nikto", "gobuster", "ffuf", "katana", "nuclei", "searchsploit", "enum4linux", "smbclient", "snmpwalk", "ldapsearch"
                    ])
                elif rtl in ("network", "network-all"):
                    expanded_requested.extend(["masscan", "rustscan", "naabu", "nmap"])
                elif rtl in ("web", "web-all"):
                    expanded_requested.extend(["httpx", "whatweb", "nikto", "gobuster", "ffuf", "katana", "nuclei"])
                else:
                    expanded_requested.append(rtl)
            requested_tools = list(dict.fromkeys(expanded_requested))

            for req_tool in requested_tools:
                req_lower = req_tool.lower().strip()
                if req_lower == "masscan":
                    capabilities.append("fast_port_discovery")
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="masscan",
                            purpose="Fast large-scale TCP port discovery",
                            command_template=f"masscan -p1-1000 {target.host} --rate 1000",
                            safety_constraints=[
                                "Rate-limited to 1000 pps",
                                "Read-only SYN probe",
                            ],
                            profile="tcp-port-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower == "rustscan":
                    capabilities.append("fast_port_discovery")
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="rustscan",
                            purpose="Fast multi-threaded port discovery",
                            command_template=f"rustscan -a {target.host} --top",
                            safety_constraints=[
                                "Adaptive timeout",
                                "Safe non-intrusive probe",
                            ],
                            profile="fast-port-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower == "whatweb":
                    capabilities.append("web_fingerprinting")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="whatweb",
                            purpose="Web server and CMS technology fingerprinting",
                            command_template=f"whatweb -a 1 {url_val}",
                            safety_constraints=[
                                "Standard HTTP GET",
                                "No active exploit",
                            ],
                            profile="technology-fingerprint",
                        )
                    )
                    step_idx += 1

                elif req_lower == "nikto":
                    capabilities.append("web_security_audit")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="nikto",
                            purpose="Web server misconfiguration and security header check",
                            command_template=f"nikto -host {url_val} -Tuning 123b",
                            safety_constraints=["Recon tuning only", "No DoS checks"],
                            profile="web-security-check",
                        )
                    )
                    step_idx += 1

                elif req_lower == "gobuster":
                    capabilities.append("directory_discovery")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="gobuster",
                            purpose="Directory and file path enumeration",
                            command_template=f"gobuster dir -u {url_val} -w common.txt",
                            safety_constraints=[
                                "Standard wordlist only",
                                "Rate-limited",
                            ],
                            profile="directory-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower == "ffuf":
                    capabilities.append("content_discovery")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="ffuf",
                            purpose="Fuzzing web endpoints and files",
                            command_template=f"ffuf -u {url_val}/FUZZ -w common.txt -rate 50",
                            safety_constraints=[
                                "Rate-limited to 50 req/s",
                                "No credential brute force",
                            ],
                            profile="content-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower == "katana":
                    capabilities.append("web_crawling")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="katana",
                            purpose="Spidering and crawling web endpoints",
                            command_template=f"katana -u {url_val} -depth 2",
                            safety_constraints=[
                                "Depth limited to 2",
                                "Passive URL extraction",
                            ],
                            profile="crawl",
                        )
                    )
                    step_idx += 1

                elif req_lower == "searchsploit":
                    capabilities.append("vulnerability_reference_lookup")
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="searchsploit",
                            purpose="Lookup potential exploit references for detected software version",
                            command_template=f'searchsploit --json "{target.host}"',
                            safety_constraints=[
                                "Offline database lookup",
                                "No automated exploitation",
                            ],
                            profile="vulnerability-reference-search",
                        )
                    )
                    step_idx += 1

                elif req_lower in ("burpsuite", "zap"):
                    capabilities.append("manual_proxy")
                    url_val = (
                        target.normalized_value
                        if target.type == TargetType.URL
                        else f"http://{target.host}"
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool=req_lower,
                            purpose=f"Setup {req_lower.upper()} manual security testing proxy workflow",
                            command_template=f"proxy-workflow --tool {req_lower} --target {url_val}",
                            safety_constraints=[
                                "Manual workflow only",
                                "User confirmation required",
                            ],
                            profile="manual-workflow",
                        )
                    )
                    step_idx += 1

                elif req_lower == "naabu":
                    capabilities.append("fast_port_discovery")
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="naabu",
                            purpose="Fast TCP port discovery across top 100 ports",
                            command_template=f"naabu -host {target.host} -top-ports 100",
                            safety_constraints=["Syn/TCP connect probe only", "Rate-limited"],
                            profile="fast-port-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower in ("nmap", "nmap-nse"):
                    capabilities.extend(["port_discovery", "service_discovery"])
                    port_cmd = f"-p {target.port}" if target.port else "--top-ports 100"
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="nmap",
                            purpose="Service identification and version fingerprinting",
                            command_template=f"nmap -sV -sC -Pn -T4 {port_cmd} {target.host}",
                            safety_constraints=["Read-only", "No DoS"],
                            profile="service-detection",
                        )
                    )
                    step_idx += 1

                elif req_lower == "httpx":
                    capabilities.append("web_probing")
                    url_val = target.normalized_value if target.type == TargetType.URL else f"http://{target.host}"
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="httpx",
                            purpose="HTTP response headers, status code, title, and technology probing",
                            command_template=f"httpx -u {url_val} -status-code -title -tech-detect",
                            safety_constraints=["Non-destructive", "Standard HTTP GET"],
                            profile="web-probe",
                        )
                    )
                    step_idx += 1

                elif req_lower == "nuclei":
                    capabilities.append("vulnerability_detection")
                    url_val = target.normalized_value if target.type == TargetType.URL else f"http://{target.host}"
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="nuclei",
                            purpose="Template-based read-only CVE & misconfiguration assessment",
                            command_template=f"nuclei -u {url_val} -tags cve,misconfig,exposure",
                            safety_constraints=["Read-only audit templates", "No brute force"],
                            profile="approved-vulnerability-scan",
                        )
                    )
                    step_idx += 1

                elif req_lower in ("smbclient", "enum4linux"):
                    capabilities.extend(["smb", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool=req_lower,
                            purpose=f"SMB service enumeration using {req_lower}",
                            command_template=f"{req_lower} against {target.host}",
                            safety_constraints=["Standard query", "Read-only"],
                            profile="smb-enumeration",
                        )
                    )
                    step_idx += 1

                elif req_lower == "snmpwalk":
                    capabilities.extend(["snmp", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="snmpwalk",
                            purpose="Query SNMP system information and OID tree",
                            command_template=f"snmpwalk -v2c -c public {target.host}",
                            safety_constraints=["Public community probe", "Read-only"],
                            profile="snmp-discovery",
                        )
                    )
                    step_idx += 1

                elif req_lower == "ldapsearch":
                    capabilities.extend(["ldap", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="ldapsearch",
                            purpose="Query LDAP naming contexts and base tree",
                            command_template=f'ldapsearch -x -H ldap://{target.host} -b ""',
                            safety_constraints=["Anonymous bind", "Read-only"],
                            profile="ldap-base-query",
                        )
                    )
                    step_idx += 1

                elif req_lower == "testssl":
                    capabilities.extend(["ssl", "tls", "crypto_audit"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="testssl",
                            purpose="SSL/TLS cipher suite and vulnerability assessment",
                            command_template=f"testssl --fast {target.host}",
                            safety_constraints=["Standard TLS handshake", "Read-only"],
                            profile="ssl-audit",
                        )
                    )
                    step_idx += 1

                elif req_lower == "theharvester":
                    capabilities.extend(["osint", "subdomain_discovery"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="theharvester",
                            purpose="Passive OSINT and subdomain reconnaissance",
                            command_template=f"theHarvester -d {target.host} -b all",
                            safety_constraints=["Passive query", "Rate-limited"],
                            profile="osint-recon",
                        )
                    )
                    step_idx += 1

                elif req_lower == "database":
                    capabilities.extend(["database", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="database",
                            purpose="Database client banner query and connection probing",
                            command_template=f"mysql --host={target.host} --connect-timeout=5",
                            safety_constraints=["Banner query only", "Read-only"],
                            profile="database-enum",
                        )
                    )
                    step_idx += 1

        # 3. Default target-driven planning if no explicit tools were requested
        if not steps:
            if is_web:
                port_val = target.port or (443 if target.scheme == "https" else 80)

                # Step 1: Nmap service version
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="nmap",
                        purpose="Target port verification and service/version fingerprinting",
                        command_template=f"nmap -sV -sC -Pn -T4 -p {port_val} {target.host}",
                        safety_constraints=["Rate-limited", "Read-only", "No DoS"],
                        profile="safe-service-detection",
                    )
                )
                step_idx += 1

                # Step 2: Httpx probing
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="httpx",
                        purpose="HTTP response headers, status code, title, and technology probing",
                        command_template=f"httpx -u {target.normalized_value} -status-code -title -tech-detect",
                        safety_constraints=[
                            "Non-destructive",
                            "Standard HTTP GET requests",
                        ],
                        profile="web-probe",
                    )
                )
                step_idx += 1

                # Step 3: Nuclei read-only audit
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="nuclei",
                        purpose="Template-based read-only CVE & misconfiguration assessment",
                        command_template=f"nuclei -u {target.normalized_value} -tags cve,misconfig,exposure",
                        safety_constraints=[
                            "Read-only audit templates",
                            "No brute force",
                            "No automated exploitation",
                        ],
                        profile="approved-vulnerability-scan",
                    )
                )
                step_idx += 1

            elif target.type == TargetType.HOST_PORT:
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="nmap",
                        purpose=f"Specific port {target.port} service detection and version discovery",
                        command_template=f"nmap -sV -sC -Pn -T4 -p {target.port} {target.host}",
                        safety_constraints=["Rate-limited", "Read-only", "No exploit"],
                        profile="service-detection",
                    )
                )
                step_idx += 1

            elif target.type in (
                TargetType.IPV4,
                TargetType.IPV6,
                TargetType.DOMAIN,
                TargetType.HOSTNAME,
            ):
                # Step 1: Naabu fast port discovery
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="naabu",
                        purpose="Fast TCP port discovery across top 100 ports",
                        command_template=f"naabu -host {target.host} -top-ports 100",
                        safety_constraints=[
                            "Syn/TCP connect probe only",
                            "Rate-limited",
                        ],
                        profile="fast-port-discovery",
                    )
                )
                step_idx += 1

                # Step 2: Nmap service version
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="nmap",
                        purpose="Service identification and version fingerprinting on discovered ports",
                        command_template=f"nmap -sV -sC -Pn -T4 --top-ports 100 {target.host}",
                        safety_constraints=["Read-only", "Top 100 ports", "No DoS"],
                        profile="service-detection",
                    )
                )
                step_idx += 1

            elif target.type == TargetType.CIDR:
                steps.append(
                    ReconStep(
                        step_number=step_idx,
                        tool="nmap",
                        purpose="Subnet ping sweep and alive host discovery",
                        command_template=f"nmap -sn -T4 {target.host}",
                        safety_constraints=["ICMP/Ping sweep only", "No service scan"],
                        profile="host-discovery",
                    )
                )
                step_idx += 1

        # 4. Service-driven tool selection (when detected services are provided)
        if detected_services:
            for s in detected_services:
                port = int(s.get("port") or s.get("portid") or 0)
                name = str(s.get("service") or s.get("name") or "").lower()
                product = str(s.get("product") or "")
                version = str(s.get("version") or "")

                # Web Services (80, 443, 3000, 5000, 8000, 8080, 8443 or 'http' in name)
                if port in (80, 443, 3000, 5000, 8000, 8080, 8443) or any(
                    w in name for w in ["http", "https", "web", "ssl/http"]
                ):
                    proto = "https" if (port == 443 or "https" in name or "ssl" in name) else "http"
                    web_url = f"{proto}://{target.host}:{port}" if port not in (80, 443) else f"{proto}://{target.host}"
                    capabilities.extend(["web", "web_probing", "vulnerability_detection"])

                    if not any(st.tool == "httpx" for st in steps):
                        steps.append(
                            ReconStep(
                                step_number=step_idx,
                                tool="httpx",
                                purpose=f"Probe HTTP service headers, title and tech on port {port}",
                                command_template=f"httpx -u {web_url} -status-code -title -tech-detect",
                                safety_constraints=["Non-destructive", "Standard HTTP GET"],
                                profile="web-probe",
                            )
                        )
                        step_idx += 1

                    if not any(st.tool == "whatweb" for st in steps):
                        steps.append(
                            ReconStep(
                                step_number=step_idx,
                                tool="whatweb",
                                purpose=f"Fingerprint web framework and server on port {port}",
                                command_template=f"whatweb -a 1 {web_url}",
                                safety_constraints=["Standard HTTP GET", "Read-only"],
                                profile="web-fingerprint",
                            )
                        )
                        step_idx += 1

                    if not any(st.tool == "nuclei" for st in steps):
                        steps.append(
                            ReconStep(
                                step_number=step_idx,
                                tool="nuclei",
                                purpose=f"Run read-only vulnerability templates on port {port}",
                                command_template=f"nuclei -u {web_url} -tags cve,misconfig,exposure",
                                safety_constraints=["Read-only audit templates", "No brute force"],
                                profile="approved-vulnerability-scan",
                            )
                        )
                        step_idx += 1

                # SMB Enumeration (445, 139)
                elif port in (445, 139) or "smb" in name or "microsoft-ds" in name:
                    capabilities.extend(["smb", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="enum4linux",
                            purpose=f"SMB null session, user and share enumeration on port {port}",
                            command_template=f"enum4linux -a {target.host}",
                            safety_constraints=[
                                "Standard RPC/SMB query",
                                "No password cracking",
                            ],
                            profile="smb-enumeration",
                        )
                    )
                    step_idx += 1

                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="smbclient",
                            purpose=f"List accessible SMB shares anonymously on {target.host}",
                            command_template=f"smbclient -L //{target.host} -N",
                            safety_constraints=["Anonymous listing", "Read-only"],
                            profile="share-listing",
                        )
                    )
                    step_idx += 1

                # SNMP Enumeration (161)
                elif port == 161 or "snmp" in name:
                    capabilities.extend(["snmp", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="snmpwalk",
                            purpose=f"Query SNMP system information and OID tree on port {port}",
                            command_template=f"snmpwalk -v2c -c public {target.host}",
                            safety_constraints=["Public community probe", "Read-only"],
                            profile="snmp-discovery",
                        )
                    )
                    step_idx += 1

                # LDAP Enumeration (389, 636)
                elif port in (389, 636) or "ldap" in name:
                    capabilities.extend(["ldap", "service_enumeration"])
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="ldapsearch",
                            purpose=f"Query LDAP naming contexts and base tree on port {port}",
                            command_template=f'ldapsearch -x -H ldap://{target.host}:{port} -b ""',
                            safety_constraints=["Anonymous bind", "Read-only"],
                            profile="ldap-base-query",
                        )
                    )
                    step_idx += 1

                # Database Services
                elif port in (3306, 5432, 6379, 27017, 1433) or any(
                    db in name
                    for db in ["mysql", "postgres", "redis", "mongodb", "ms-sql"]
                ):
                    capabilities.extend(["database", "service_enumeration"])
                    db_type = (
                        "mysql"
                        if port == 3306
                        else (
                            "psql"
                            if port == 5432
                            else ("redis-cli" if port == 6379 else "mongosh")
                        )
                    )
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="database",
                            purpose=f"Probe database banner and connectivity for {db_type.upper()} on port {port}",
                            command_template=f"{db_type} connection check on {target.host}:{port}",
                            safety_constraints=[
                                "Connection probe only",
                                "No unauthorized data query",
                            ],
                            profile="db-probe",
                        )
                    )
                    step_idx += 1

                # If product and version detected, plan SearchSploit lookup
                if product and version:
                    capabilities.append("vulnerability_reference_lookup")
                    steps.append(
                        ReconStep(
                            step_number=step_idx,
                            tool="searchsploit",
                            purpose=f"Query exploit references for detected product '{product} {version}'",
                            command_template=f'searchsploit --json "{product} {version}"',
                            safety_constraints=[
                                "Offline lookup only",
                                "No exploit execution",
                            ],
                            profile="vulnerability-reference-search",
                        )
                    )
                    step_idx += 1

        # Deduplicate capabilities
        unique_capabilities = list(dict.fromkeys(capabilities))

        return ReconPlan(
            target_id=target.target_id,
            target_type=target.type,
            target_host=target.host,
            capabilities=unique_capabilities,
            steps=steps,
        )

    @classmethod
    def plan_service_enumeration(
        cls, target: Target, services: list[dict[str, Any]]
    ) -> list[ReconStep]:
        """Convenience method to generate service-specific enumeration steps."""
        full_plan = cls.plan(target, detected_services=services)
        return [
            s
            for s in full_plan.steps
            if s.profile
            in (
                "smb-enumeration",
                "share-listing",
                "snmp-discovery",
                "ldap-base-query",
                "db-probe",
                "vulnerability-reference-search",
            )
        ]

    @classmethod
    def plan_fast_port_discovery(
        cls, target: Target, tool: str = "masscan"
    ) -> ReconStep:
        """Generate a fast port discovery step using masscan or rustscan."""
        if tool == "rustscan":
            return ReconStep(
                step_number=1,
                tool="rustscan",
                purpose="Fast port discovery with RustScan",
                command_template=f"rustscan -a {target.host} --top",
                safety_constraints=["Adaptive timeout", "Safe probe"],
                profile="fast-port-discovery",
            )
        return ReconStep(
            step_number=1,
            tool="masscan",
            purpose="Fast port discovery with Masscan",
            command_template=f"masscan -p1-1000 {target.host} --rate 1000",
            safety_constraints=["Rate-limited to 1000 pps", "SYN probe"],
            profile="tcp-port-discovery",
        )
