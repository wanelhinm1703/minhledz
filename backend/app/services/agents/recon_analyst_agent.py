"""AI-Pentest Copilot - Recon Analyst Sub-Agent.
Specializes in parsing scan evidence, normalizing discovered ports/services,
and detecting discrepancies/conflicts across multiple reconnaissance tools.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from pydantic import BaseModel, Field

from backend.app.core.context import ContextEngine


class DiscoveredService(BaseModel):
    tool: str
    port: int | None = None
    protocol: str = "tcp"
    service_name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    is_simulated: bool = False


class ReconAnalystResult(BaseModel):
    target_id: str
    discovered_services: list[DiscoveredService] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    tools_analyzed: list[str] = Field(default_factory=list)
    summary: str = ""
    confidence: float = 1.0


class ReconAnalystAgent:
    """Specialist sub-agent dedicated to raw reconnaissance analysis and cross-tool conflict detection."""

    def __init__(self, root_dir: pathlib.Path | None = None):
        self.root_dir = (
            root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent.parent
        )

    def analyze(
        self,
        target_id: str,
        scans_data: list[dict[str, Any]] | None = None,
    ) -> ReconAnalystResult:
        """Analyze reconnaissance results for a target, extract services, and detect tool conflicts."""
        scans = scans_data or ContextEngine.discover_target_scans(target_id, self.root_dir)

        services: list[DiscoveredService] = []
        tools_analyzed = []

        for sc in scans:
            tool_name = sc.get("tool", "unknown")
            if tool_name not in tools_analyzed:
                tools_analyzed.append(tool_name)
            is_sim = sc.get("is_simulated", False)

            # Nmap scan parsing
            if tool_name == "nmap":
                for p in sc.get("ports", []):
                    if isinstance(p, dict):
                        port_id = p.get("port") or p.get("portid")
                        if port_id is not None:
                            try:
                                port_id = int(port_id)
                            except (ValueError, TypeError):
                                pass
                        services.append(
                            DiscoveredService(
                                tool="nmap",
                                port=port_id,
                                protocol=p.get("protocol", "tcp"),
                                service_name=p.get("service", ""),
                                product=p.get("product", ""),
                                version=p.get("version", ""),
                                is_simulated=is_sim,
                            )
                        )
                    else:
                        try:
                            port_id = int(p)
                        except (ValueError, TypeError):
                            port_id = 0
                        services.append(
                            DiscoveredService(
                                tool="nmap",
                                port=port_id,
                                protocol="tcp",
                                service_name="",
                                product="",
                                version="",
                                is_simulated=is_sim,
                            )
                        )


            # HTTPx scan parsing
            elif tool_name == "httpx":
                port = sc.get("port", 80)
                techs = sc.get("technologies", [])
                services.append(
                    DiscoveredService(
                        tool="httpx",
                        port=port,
                        service_name="http",
                        product=", ".join(techs) if techs else "HTTP Service",
                        banner=sc.get("title", ""),
                        is_simulated=is_sim,
                    )
                )

            # WhatWeb scan parsing
            elif tool_name == "whatweb":
                for tech in sc.get("technologies", []):
                    services.append(
                        DiscoveredService(
                            tool="whatweb",
                            service_name="http",
                            product=tech.get("name", ""),
                            version=tech.get("version", ""),
                            is_simulated=is_sim,
                        )
                    )

        # Cross-Tool Conflict Detection
        conflicts = ContextEngine.detect_conflicts(scans)

        # Confidence calculation
        confidence = 0.95
        if conflicts:
            confidence = 0.75  # reduced due to discrepancy requiring manual verification probe
        if any(s.is_simulated for s in services):
            confidence = min(confidence, 0.60)

        # Build descriptive summary
        if services:
            summary = (
                f"Recon Analyst: Phân tích thành công {len(services)} dịch vụ từ {len(tools_analyzed)} công cụ "
                f"({', '.join(tools_analyzed)})."
            )
            if conflicts:
                summary += f" [CẢNH BÁO: Phát hiện {len(conflicts)} điểm mâu thuẫn cần probe kiểm chứng!]"
        else:
            summary = f"Recon Analyst: Chưa tìm thấy dữ liệu scan thô cho target '{target_id}'."

        return ReconAnalystResult(
            target_id=target_id,
            discovered_services=services,
            conflicts=conflicts,
            tools_analyzed=tools_analyzed,
            summary=summary,
            confidence=confidence,
        )


recon_analyst_agent = ReconAnalystAgent()
