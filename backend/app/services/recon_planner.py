from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field

from backend.app.schemas.target import Target, TargetType


class ReconStep(BaseModel):
    step_number: int
    tool: str
    purpose: str
    command_template: str
    safety_constraints: List[str] = Field(default_factory=list)


class ReconPlan(BaseModel):
    target_id: str
    target_type: TargetType
    target_host: str
    capabilities: List[str]
    steps: List[ReconStep]
    estimated_duration_seconds: int = 120
    safety_summary: str = "Read-only non-destructive reconnaissance pipeline"


class ReconPlanner:
    """
    Maps Target Capabilities -> Multi-tool Recon Steps:
    - Network Target (IP, CIDR): Naabu (fast port discovery) -> Nmap (version detection)
    - Web Target (URL, web ports): Nmap (port verification) -> Httpx (probing/tech) -> Nuclei (read-only audit)
    """

    @classmethod
    def plan(cls, target: Target) -> ReconPlan:
        capabilities = []
        steps = []
        step_idx = 1

        is_web = target.type == TargetType.URL or (target.port in [80, 443, 3000, 8080, 8443])

        if is_web:
            capabilities.extend(["web", "http_probing", "vulnerability_detection", "service_discovery"])
            port_val = target.port or (443 if target.scheme == "https" else 80)
            
            # Step 1: Nmap service version
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="nmap",
                    purpose="Target port verification and service/version fingerprinting",
                    command_template=f"nmap -sV -sC -Pn -T4 -p {port_val} {target.host}",
                    safety_constraints=["Rate-limited", "Read-only", "No DoS"],
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
                    safety_constraints=["Non-destructive", "Standard HTTP GET requests"],
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
                    safety_constraints=["Read-only audit templates", "No brute force", "No automated exploitation"],
                )
            )

        elif target.type == TargetType.HOST_PORT:
            capabilities.extend(["network", "service_discovery"])
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="nmap",
                    purpose=f"Specific port {target.port} service detection and version discovery",
                    command_template=f"nmap -sV -sC -Pn -T4 -p {target.port} {target.host}",
                    safety_constraints=["Rate-limited", "Read-only", "No exploit"],
                )
            )

        elif target.type in (TargetType.IPV4, TargetType.IPV6, TargetType.DOMAIN, TargetType.HOSTNAME):
            capabilities.extend(["network", "port_discovery", "service_discovery"])
            # Step 1: Naabu fast port discovery
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="naabu",
                    purpose="Fast TCP port discovery across top 100 ports",
                    command_template=f"naabu -host {target.host} -top-ports 100",
                    safety_constraints=["Syn/TCP connect probe only", "Rate-limited"],
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
                )
            )

        elif target.type == TargetType.CIDR:
            capabilities.extend(["network", "host_discovery"])
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="nmap",
                    purpose="Subnet ping sweep and alive host discovery",
                    command_template=f"nmap -sn -T4 {target.host}",
                    safety_constraints=["ICMP/Ping sweep only", "No service scan"],
                )
            )

        return ReconPlan(
            target_id=target.target_id,
            target_type=target.type,
            target_host=target.host,
            capabilities=capabilities,
            steps=steps,
        )
