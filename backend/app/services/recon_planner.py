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
    estimated_duration_seconds: int = 60
    safety_summary: str = "Read-only non-destructive reconnaissance plan"


class ReconPlanner:
    @classmethod
    def plan(cls, target: Target) -> ReconPlan:
        capabilities = []
        steps = []
        step_idx = 1

        if target.type == TargetType.URL:
            capabilities.extend(["web", "http_probing", "service_discovery"])
            port_arg = f"-p {target.port}" if target.port else ""
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="nmap",
                    purpose="Target port verification and service/version fingerprinting",
                    command_template=f"nmap -sV -sC -Pn -T4 {port_arg} {target.host}".strip(),
                    safety_constraints=["Rate-limited", "Read-only", "No DoS"],
                )
            )
            step_idx += 1
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="httpx",
                    purpose="HTTP header probing and status verification",
                    command_template=f"httpx -u {target.normalized_value} -status-code -title -tech-detect",
                    safety_constraints=["Non-destructive", "Standard HTTP GET requests"],
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
            steps.append(
                ReconStep(
                    step_number=step_idx,
                    tool="nmap",
                    purpose="Standard network port scanning and service enumeration",
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
