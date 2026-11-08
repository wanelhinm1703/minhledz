"""Graph Builder: constructs hierarchical Attack Surface Topology Graph and Attack Paths from scan artifacts and findings."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

from backend.app.schemas.graph import (
    AttackPath,
    AttackPathStep,
    GraphDataResponse,
    GraphEdge,
    GraphNode,
    GraphStats,
    NodeRiskLevel,
    NodeType,
    RelationType,
)
from backend.app.storage.db import db
from backend.app.storage.findings_db import findings_db
from backend.app.storage.graph_db import graph_db


def sev_to_risk(sev: str | None) -> NodeRiskLevel:
    if not sev:
        return NodeRiskLevel.INFO
    s = sev.upper()
    if s == "CRITICAL":
        return NodeRiskLevel.CRITICAL
    if s == "HIGH":
        return NodeRiskLevel.HIGH
    if s == "MEDIUM":
        return NodeRiskLevel.MEDIUM
    if s == "LOW":
        return NodeRiskLevel.LOW
    return NodeRiskLevel.INFO


RISK_ORDER = {
    NodeRiskLevel.CRITICAL: 5,
    NodeRiskLevel.HIGH: 4,
    NodeRiskLevel.MEDIUM: 3,
    NodeRiskLevel.LOW: 2,
    NodeRiskLevel.INFO: 1,
    NodeRiskLevel.SAFE: 0,
}


def _risk_rank(risk: NodeRiskLevel | str) -> int:
    risk_str = risk.value if hasattr(risk, "value") else str(risk)
    ranks = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
        "SAFE": 0,
    }
    return ranks.get(risk_str.upper(), 0)


def build_attack_paths(nodes: list[GraphNode], edges: list[GraphEdge], target_id: str) -> list[AttackPath]:
    """Identify, extract, and consolidate causal attack paths.
    
    Paths with identical infrastructural steps (same entry target, port, service, and impact vector)
    are merged into a single Attack Path with detailed annotations and linked CVEs/findings.
    """
    nodes_by_id = {n.id: n for n in nodes}
    in_edges_map: dict[str, list[GraphEdge]] = {}
    out_edges_map: dict[str, list[GraphEdge]] = {}
    for e in edges:
        in_edges_map.setdefault(e.target, []).append(e)
        out_edges_map.setdefault(e.source, []).append(e)

    vuln_nodes = [
        n for n in nodes
        if n.type == NodeType.VULNERABILITY
        and n.properties.get("port_status") != "closed"
    ]
    if not vuln_nodes:
        vuln_nodes = [
            n for n in nodes
            if n.type == NodeType.FINDING
            and n.properties.get("port_status") != "closed"
        ]
    if not vuln_nodes:
        vuln_nodes = [
            n for n in nodes
            if n.type not in (NodeType.TARGET, NodeType.PORT, NodeType.IMPACT, NodeType.LATERAL_MOVEMENT)
            and n.risk_level in (NodeRiskLevel.CRITICAL, NodeRiskLevel.HIGH)
            and n.properties.get("port_status") != "closed"
        ]

    # Step 1: Trace candidate chains for each vulnerability node
    candidate_items: list[dict[str, Any]] = []
    for v_node in vuln_nodes:
        chain_nodes: list[str] = [v_node.id]
        chain_edges: list[str] = []

        # Trace backward to reach entry point (Port / Service / Target)
        curr = v_node.id
        visited_back = {curr}
        while True:
            parents = in_edges_map.get(curr, [])
            parent_edge = None
            for pe in parents:
                p_node = nodes_by_id.get(pe.source)
                if p_node and p_node.type in (NodeType.SERVICE, NodeType.PORT, NodeType.TARGET) and pe.source not in visited_back:
                    parent_edge = pe
                    break
            if not parent_edge and parents:
                for pe in parents:
                    if pe.source not in visited_back:
                        parent_edge = pe
                        break
            if parent_edge:
                visited_back.add(parent_edge.source)
                chain_nodes.insert(0, parent_edge.source)
                chain_edges.insert(0, parent_edge.id)
                curr = parent_edge.source
                if nodes_by_id.get(curr) and nodes_by_id[curr].type == NodeType.TARGET:
                    break
            else:
                break

        # Trace forward to find IMPACT and LATERAL_MOVEMENT
        curr = v_node.id
        visited_fwd = {curr}
        while True:
            children = out_edges_map.get(curr, [])
            child_edge = None
            for ce in children:
                c_node = nodes_by_id.get(ce.target)
                if c_node and c_node.type in (NodeType.IMPACT, NodeType.LATERAL_MOVEMENT) and ce.target not in visited_fwd:
                    child_edge = ce
                    break
            if child_edge:
                visited_fwd.add(child_edge.target)
                chain_nodes.append(child_edge.target)
                chain_edges.append(child_edge.id)
                curr = child_edge.target
            else:
                break

        if len(chain_nodes) >= 3:
            target_node = next((nodes_by_id[nid] for nid in chain_nodes if nodes_by_id.get(nid) and nodes_by_id[nid].type == NodeType.TARGET), None)
            port_node = next((nodes_by_id[nid] for nid in chain_nodes if nodes_by_id.get(nid) and nodes_by_id[nid].type == NodeType.PORT), None)
            service_node = next((nodes_by_id[nid] for nid in chain_nodes if nodes_by_id.get(nid) and nodes_by_id[nid].type == NodeType.SERVICE), None)
            impact_node = next((nodes_by_id[nid] for nid in chain_nodes if nodes_by_id.get(nid) and nodes_by_id[nid].type == NodeType.IMPACT), None)
            lateral_node = next((nodes_by_id[nid] for nid in chain_nodes if nodes_by_id.get(nid) and nodes_by_id[nid].type == NodeType.LATERAL_MOVEMENT), None)

            clean_cve = v_node.properties.get("cve_id") or v_node.label.replace("Finding: ", "").replace("[DUAL]", "").strip()
            remediation = v_node.properties.get("remediation") or "Áp dụng bản vá từ nhà cung cấp, cô lập dịch vụ và hạn chế truy cập mạng."
            cvss = float(v_node.properties.get("cvss_score") or (9.8 if v_node.risk_level == NodeRiskLevel.CRITICAL else (7.5 if v_node.risk_level == NodeRiskLevel.HIGH else 5.0)))
            is_kev = bool(v_node.properties.get("is_cisa_kev") or v_node.properties.get("in_cisa_kev"))
            epss_val = v_node.properties.get("epss_score")

            candidate_items.append({
                "v_node": v_node,
                "chain_nodes": chain_nodes,
                "chain_edges": chain_edges,
                "target_node": target_node,
                "port_node": port_node,
                "service_node": service_node,
                "impact_node": impact_node,
                "lateral_node": lateral_node,
                "clean_cve": clean_cve,
                "remediation": remediation,
                "cvss": cvss,
                "is_kev": is_kev,
                "epss": epss_val,
            })

    # Step 2: Group candidate paths by structural identity (same entry target, port, service, and lateral presence)
    groups: dict[tuple, list[dict[str, Any]]] = {}
    for item in candidate_items:
        t_key = item["target_node"].id if item["target_node"] else f"target:{target_id}"
        p_key = item["port_node"].id if item["port_node"] else "no-port"
        s_key = item["service_node"].id if item["service_node"] else "no-service"
        l_key = bool(item["lateral_node"])
        group_key = (t_key, p_key, s_key, l_key)
        groups.setdefault(group_key, []).append(item)

    # Step 3: Consolidate each group into a unified AttackPath with annotations
    paths: list[AttackPath] = []
    for g_items in groups.values():
        # Sort items in group to pick primary representative
        g_items.sort(
            key=lambda it: (
                -_risk_rank(it["v_node"].risk_level),
                -it["cvss"],
                -1 if it["is_kev"] else 0,
                -(it["epss"] or 0),
            )
        )
        primary = g_items[0]

        # Gather all unique CVEs
        all_cves: list[str] = []
        for it in g_items:
            cve = it["clean_cve"]
            if cve and cve not in all_cves:
                all_cves.append(cve)
        findings_count = len(all_cves) or len(g_items)

        max_severity = primary["v_node"].risk_level
        max_cvss = max(it["cvss"] for it in g_items)
        any_kev = any(it["is_kev"] for it in g_items)
        max_epss = max((it["epss"] for it in g_items if it["epss"] is not None), default=None)

        t_node = primary["target_node"]
        p_node = primary["port_node"]
        s_node = primary["service_node"]
        i_node = primary["impact_node"]
        l_node = primary["lateral_node"]

        target_label = t_node.label if t_node else target_id
        port_label = p_node.label if p_node else "Cổng mạng"
        
        service_label = ""
        if s_node:
            service_label = s_node.label.replace("Finding: ", "").replace("[DUAL]", "").strip()
        if not service_label:
            service_label = f"Dịch vụ cổng {port_label}"

        impact_label = ""
        if i_node:
            impact_label = i_node.label.replace("Finding: ", "").replace("[DUAL]", "").strip()
        if not impact_label:
            impact_label = "Chiếm quyền điều khiển & Trích xuất dữ liệu"

        primary_cve = all_cves[0] if all_cves else "Lỗ hổng bảo mật"

        if findings_count > 1:
            path_title = f"Xác minh {service_label} ({port_label}) ➔ {impact_label}"
            goal = f"Kẻ tấn công thăm dò cổng {port_label}, tiếp cận {service_label} và khai thác các lỗ hổng ({', '.join(all_cves[:3])}) để {impact_label}."
            annotation = f"{service_label} ({port_label}): {findings_count} CVEs"
        else:
            path_title = f"Xác minh {service_label} ({port_label}) — {primary_cve} ➔ {impact_label}"
            goal = f"Kẻ tấn công thăm dò cổng {port_label}, lợi dụng {primary_cve} trên {service_label} để đạt được: {impact_label}."
            annotation = f"{service_label} ({port_label}): {primary_cve}"

        # Construct consolidated 5/6 steps
        steps: list[AttackPathStep] = []
        step_idx = 1

        # Step 1: Target
        steps.append(
            AttackPathStep(
                step_number=step_idx,
                phase="Mục tiêu (Target)",
                node_id=t_node.id if t_node else f"target:{target_id}",
                title=target_label,
                node_label=target_label,
                node_type=NodeType.TARGET.value,
                description=f"Xác định mục tiêu tấn công trên mạng: {target_label}",
                technical_detail=f"Target ID: {target_id}",
                mitre_tactic="Reconnaissance",
                mitre_technique="T1595 - Active Scanning",
            )
        )
        step_idx += 1

        # Step 2: Port
        if p_node:
            steps.append(
                AttackPathStep(
                    step_number=step_idx,
                    phase="Trinh sát cổng (Port Discovery)",
                    node_id=p_node.id,
                    title=port_label,
                    node_label=port_label,
                    node_type=NodeType.PORT.value,
                    description=f"Phát hiện cổng mạng mở chấp nhận kết nối công khai: {port_label}",
                    technical_detail=f"Protocol: {p_node.properties.get('protocol', 'tcp')}, Port: {p_node.properties.get('port')}",
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 - Network Service Discovery",
                )
            )
            step_idx += 1

        # Step 3: Service
        if s_node:
            steps.append(
                AttackPathStep(
                    step_number=step_idx,
                    phase="Nhận diện dịch vụ (Service Recon)",
                    node_id=s_node.id,
                    title=service_label,
                    node_label=service_label,
                    node_type=NodeType.SERVICE.value,
                    description=f"Dịch vụ đang hoạt động trên cổng: {service_label}",
                    technical_detail=s_node.properties.get("version") or s_node.properties.get("service"),
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 - Service Enumeration",
                )
            )
            step_idx += 1

        # Step 4: Vulnerability (Exploitation) - Consolidated
        ti_str = ""
        if any_kev:
            ti_str += " [🔥 CISA KEV: Khai thác thực tế]"
        if max_epss is not None:
            ti_str += f" [EPSS: {max_epss*100:.1f}%]"

        if findings_count > 1:
            vuln_title = f"Xác minh {findings_count} Lỗ hổng: {service_label}"
            vuln_desc = f"Phát hiện {findings_count} lỗ hổng bảo mật liên đới: {', '.join(all_cves[:5])}{'...' if findings_count > 5 else ''}.{ti_str} Cần chạy Safe Verification Probe để đối chiếu tính khả thi."
            tech_detail = f"Danh sách CVE liên đới: {', '.join(all_cves)}. Khuyến nghị khắc phục chung: {primary['remediation']}"
        else:
            vuln_title = f"Xác minh Lỗ hổng: {primary_cve}"
            vuln_desc = f"Lỗ hổng bảo mật: {primary_cve}{ti_str}"
            tech_detail = primary["remediation"]

        steps.append(
            AttackPathStep(
                step_number=step_idx,
                phase="Khai thác lỗ hổng (Exploitation)",
                node_id=primary["v_node"].id,
                title=vuln_title,
                node_label=vuln_title,
                node_type=NodeType.VULNERABILITY.value,
                description=vuln_desc,
                technical_detail=tech_detail,
                annotation=annotation,
                related_cves=all_cves,
                mitre_tactic="Initial Access",
                mitre_technique="T1190 - Exploit Public-Facing Application",
            )
        )
        step_idx += 1

        # Step 5: Impact
        if i_node:
            steps.append(
                AttackPathStep(
                    step_number=step_idx,
                    phase="Tác động dữ liệu (Impact & Exposure)",
                    node_id=i_node.id,
                    title=impact_label,
                    node_label=impact_label,
                    node_type=NodeType.IMPACT.value,
                    description=f"Hệ quả khai thác: {impact_label}",
                    technical_detail=i_node.properties.get("description"),
                    mitre_tactic="Impact",
                    mitre_technique="T1005 - Data from Local System",
                )
            )
            step_idx += 1

        # Step 6: Lateral Movement
        if l_node:
            steps.append(
                AttackPathStep(
                    step_number=step_idx,
                    phase="Di chuyển ngang (Lateral Movement)",
                    node_id=l_node.id,
                    title=l_node.label,
                    node_label=l_node.label,
                    node_type=NodeType.LATERAL_MOVEMENT.value,
                    description=f"Mở rộng phạm vi kiểm soát sang các dịch vụ nội bộ: {l_node.label}",
                    technical_detail=l_node.properties.get("description"),
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021 - Remote Services",
                )
            )
            step_idx += 1

        # Merge all node_ids and edge_ids across items in the group
        merged_node_ids: list[str] = []
        for it in g_items:
            for nid in it["chain_nodes"]:
                if nid not in merged_node_ids:
                    merged_node_ids.append(nid)

        merged_edge_ids: list[str] = []
        for it in g_items:
            for eid in it["chain_edges"]:
                if eid not in merged_edge_ids:
                    merged_edge_ids.append(eid)

        path_id = f"path:{target_id}:{s_node.id if s_node else (p_node.id if p_node else primary['v_node'].id)}"
        if l_node:
            path_id += f":{l_node.id}"

        paths.append(
            AttackPath(
                id=path_id,
                title=path_title,
                severity=max_severity,
                attacker_goal=goal,
                remediation_summary=primary["remediation"],
                node_ids=merged_node_ids,
                edge_ids=merged_edge_ids,
                steps=steps,
                cvss_score=max_cvss,
                cve_id=primary_cve,
                related_cves=all_cves,
                findings_count=findings_count,
                annotation=annotation,
                service_name=service_label,
                port_name=port_label,
                is_cisa_kev=any_kev,
                epss_score=max_epss,
                mitigation_steps=[primary["remediation"]] if primary["remediation"] else ["Áp dụng bản vá từ nhà cung cấp, cô lập dịch vụ và hạn chế truy cập mạng."],
                verification_plan_id=f"plan:chain:{primary['v_node'].id}",
            )
        )

    # Sort paths with highest risk and severity first
    paths.sort(
        key=lambda p: (
            -_risk_rank(p.severity),
            -p.cvss_score,
            -p.findings_count,
        )
    )

    return paths


class GraphBuilder:
    def __init__(self, root_dir: pathlib.Path | None = None):
        self.root_dir = (
            root_dir or pathlib.Path(__file__).resolve().parent.parent.parent.parent
        )

    def _resolve_tool_dirs(self, target_id: str, tool_name: str) -> list[pathlib.Path]:
        """Find matching tool directories across categories."""
        clean_target = target_id.replace(":", "-")
        categories = ["03-network", "04-web", "05-vulnerability", "06-service-enum", "08-manual"]
        found: list[pathlib.Path] = []
        for cat in categories:
            candidates = [
                self.root_dir / "toolkit" / cat / "scans" / f"target-{clean_target}" / tool_name,
                self.root_dir / "toolkit" / cat / "scans" / clean_target / tool_name,
                self.root_dir / "toolkit" / cat / "scans" / target_id / tool_name,
            ]
            if target_id.startswith("target-"):
                raw_id = target_id[7:]
                candidates.append(self.root_dir / "toolkit" / cat / "scans" / raw_id / tool_name)
            for c in candidates:
                if c.exists() and c.is_dir() and c not in found:
                    found.append(c)
        return found

    def build_graph_for_target(self, target_id: str, target_name: str | None = None) -> GraphDataResponse:
        now = datetime.now(timezone.utc).isoformat()
        nodes_map: dict[str, GraphNode] = {}
        edges_map: dict[str, GraphEdge] = {}

        # 1. Root Target Node
        root_id = f"target:{target_id}"
        display_name = target_name or target_id
        nodes_map[root_id] = GraphNode(
            id=root_id,
            target_id=target_id,
            type=NodeType.TARGET,
            label=display_name,
            risk_level=NodeRiskLevel.SAFE,
            properties={"target_id": target_id, "name": display_name},
            created_at=now,
            updated_at=now,
        )

        # 2. Extract Ports and Services from Nmap / Naabu
        port_to_service_nodes: dict[int, list[str]] = {}

        nmap_dirs = self._resolve_tool_dirs(target_id, "nmap")
        for n_dir in nmap_dirs:
            json_candidates = [
                n_dir / "structured" / "nmap_result.json",
                n_dir / "simulated" / "nmap_result.json",
            ]
            for jf in json_candidates:
                if not jf.exists():
                    continue
                try:
                    data = json.loads(jf.read_text(encoding="utf-8"))
                    ports = []
                    hosts = data.get("hosts", [])
                    for h in hosts:
                        ports.extend(h.get("ports", []))
                    if not ports:
                        ports = data.get("open_ports") or data.get("ports") or []

                    for p in ports:
                        if isinstance(p, dict):
                            port_num = int(p.get("port") or p.get("portid") or 0)
                            proto = p.get("protocol") or "tcp"
                            svc_obj = p.get("service", {})
                            if isinstance(svc_obj, dict):
                                svc_name = svc_obj.get("name", "")
                                prod = svc_obj.get("product", "")
                                ver = svc_obj.get("version", "")
                            else:
                                svc_name = str(svc_obj)
                                prod = p.get("product", "")
                                ver = p.get("version", "")
                            if prod and not svc_name:
                                svc_name = prod
                            elif prod and svc_name:
                                svc_name = f"{svc_name} ({prod})"
                        else:
                            port_num = int(p)
                            proto = "tcp"
                            svc_name = "unknown"
                            ver = ""

                        if port_num <= 0:
                            continue

                        # Add Port Node
                        port_node_id = f"port:{target_id}:{proto}-{port_num}"
                        if port_node_id not in nodes_map:
                            nodes_map[port_node_id] = GraphNode(
                                id=port_node_id,
                                target_id=target_id,
                                type=NodeType.PORT,
                                label=f"{port_num}/{proto}",
                                risk_level=NodeRiskLevel.INFO,
                                properties={"port": port_num, "protocol": proto},
                                created_at=now,
                                updated_at=now,
                            )
                            edge_id = f"edge:{root_id}->{port_node_id}"
                            edges_map[edge_id] = GraphEdge(
                                id=edge_id,
                                target_id=target_id,
                                source=root_id,
                                target=port_node_id,
                                relation=RelationType.EXPOSES,
                                label="open port",
                                properties={"port": port_num, "protocol": proto},
                                created_at=now,
                            )

                        # Add Service Node
                        svc_label = f"{svc_name} {ver}".strip() if ver else svc_name
                        svc_node_id = f"svc:{target_id}:{proto}-{port_num}:{svc_name}"
                        if svc_node_id not in nodes_map:
                            nodes_map[svc_node_id] = GraphNode(
                                id=svc_node_id,
                                target_id=target_id,
                                type=NodeType.SERVICE,
                                label=svc_label,
                                risk_level=NodeRiskLevel.INFO,
                                properties={"service": svc_name, "version": ver, "port": port_num},
                                created_at=now,
                                updated_at=now,
                            )
                            edge_id = f"edge:{port_node_id}->{svc_node_id}"
                            edges_map[edge_id] = GraphEdge(
                                id=edge_id,
                                target_id=target_id,
                                source=port_node_id,
                                target=svc_node_id,
                                relation=RelationType.RUNS_SERVICE,
                                label="service",
                                properties={},
                                created_at=now,
                            )
                            port_to_service_nodes.setdefault(port_num, []).append(svc_node_id)
                except Exception:
                    pass

        # 2b. Extract Ports and Services from RustScan
        rustscan_dirs = self._resolve_tool_dirs(target_id, "rustscan")
        for r_dir in rustscan_dirs:
            for jf in [r_dir / "structured" / "rustscan_result.json", r_dir / "simulated" / "rustscan_result.json"]:
                if not jf.exists():
                    continue
                try:
                    rdata = json.loads(jf.read_text(encoding="utf-8"))
                    for p in rdata.get("open_ports", []):
                        try:
                            port_num = int(p)
                        except Exception:
                            continue
                        if port_num <= 0 or port_num in port_to_service_nodes:
                            continue

                        port_node_id = f"port:{target_id}:tcp-{port_num}"
                        if port_node_id not in nodes_map:
                            nodes_map[port_node_id] = GraphNode(
                                id=port_node_id,
                                target_id=target_id,
                                type=NodeType.PORT,
                                label=f"{port_num}/tcp",
                                risk_level=NodeRiskLevel.INFO,
                                properties={"port": port_num, "protocol": "tcp"},
                                created_at=now,
                                updated_at=now,
                            )
                            edge_id = f"edge:{root_id}->{port_node_id}"
                            edges_map[edge_id] = GraphEdge(
                                id=edge_id,
                                target_id=target_id,
                                source=root_id,
                                target=port_node_id,
                                relation=RelationType.EXPOSES,
                                label="open port",
                                properties={"port": port_num, "protocol": "tcp"},
                                created_at=now,
                            )

                        if port_num == 902:
                            svc_name = "vmware-auth"
                            svc_label = "VMware Authentication Daemon"
                        elif port_num == 5173:
                            svc_name = "http"
                            svc_label = "Vite Dev Server"
                        elif port_num == 3000:
                            svc_name = "http"
                            svc_label = "Node.js"
                        else:
                            svc_name = f"tcp-{port_num}"
                            svc_label = f"TCP Service {port_num}"

                        svc_node_id = f"svc:{target_id}:tcp-{port_num}:{svc_name}"
                        if svc_node_id not in nodes_map:
                            nodes_map[svc_node_id] = GraphNode(
                                id=svc_node_id,
                                target_id=target_id,
                                type=NodeType.SERVICE,
                                label=svc_label,
                                risk_level=NodeRiskLevel.INFO,
                                properties={"service": svc_name, "version": "", "port": port_num},
                                created_at=now,
                                updated_at=now,
                            )
                            edge_id = f"edge:{port_node_id}->{svc_node_id}"
                            edges_map[edge_id] = GraphEdge(
                                id=edge_id,
                                target_id=target_id,
                                source=port_node_id,
                                target=svc_node_id,
                                relation=RelationType.RUNS_SERVICE,
                                label="service",
                                properties={},
                                created_at=now,
                            )
                            port_to_service_nodes.setdefault(port_num, []).append(svc_node_id)
                except Exception:
                    pass

        # 2c. Extract Ports from Naabu
        naabu_dirs = self._resolve_tool_dirs(target_id, "naabu")
        for nb_dir in naabu_dirs:
            raw_nb = nb_dir / "raw" / "naabu_raw.txt"
            if raw_nb.exists():
                try:
                    for line in raw_nb.read_text(encoding="utf-8").splitlines():
                        if ":" in line:
                            try:
                                port_num = int(line.strip().split(":")[-1])
                            except Exception:
                                continue
                            if port_num <= 0 or port_num in port_to_service_nodes:
                                continue
                            port_node_id = f"port:{target_id}:tcp-{port_num}"
                            if port_node_id not in nodes_map:
                                nodes_map[port_node_id] = GraphNode(
                                    id=port_node_id,
                                    target_id=target_id,
                                    type=NodeType.PORT,
                                    label=f"{port_num}/tcp",
                                    risk_level=NodeRiskLevel.INFO,
                                    properties={"port": port_num, "protocol": "tcp"},
                                    created_at=now,
                                    updated_at=now,
                                )
                                edge_id = f"edge:{root_id}->{port_node_id}"
                                edges_map[edge_id] = GraphEdge(
                                    id=edge_id,
                                    target_id=target_id,
                                    source=root_id,
                                    target=port_node_id,
                                    relation=RelationType.EXPOSES,
                                    label="open port",
                                    properties={"port": port_num, "protocol": "tcp"},
                                    created_at=now,
                                )
                            svc_name = f"tcp-{port_num}"
                            svc_node_id = f"svc:{target_id}:tcp-{port_num}:{svc_name}"
                            if svc_node_id not in nodes_map:
                                nodes_map[svc_node_id] = GraphNode(
                                    id=svc_node_id,
                                    target_id=target_id,
                                    type=NodeType.SERVICE,
                                    label=f"Port {port_num}/tcp",
                                    risk_level=NodeRiskLevel.INFO,
                                    properties={"service": svc_name, "version": "", "port": port_num},
                                    created_at=now,
                                    updated_at=now,
                                )
                                edge_id = f"edge:{port_node_id}->{svc_node_id}"
                                edges_map[edge_id] = GraphEdge(
                                    id=edge_id,
                                    target_id=target_id,
                                    source=port_node_id,
                                    target=svc_node_id,
                                    relation=RelationType.RUNS_SERVICE,
                                    label="service",
                                    properties={},
                                    created_at=now,
                                )
                                port_to_service_nodes.setdefault(port_num, []).append(svc_node_id)
                except Exception:
                    pass

        network_scans_performed = bool(nmap_dirs or rustscan_dirs or naabu_dirs)

        # 3. Extract Technologies from HTTPx
        httpx_dirs = self._resolve_tool_dirs(target_id, "httpx")
        for h_dir in httpx_dirs:
            json_candidates = [
                h_dir / "structured" / "httpx_result.json",
                h_dir / "simulated" / "httpx_result.json",
            ]
            for jf in json_candidates:
                if not jf.exists():
                    continue
                try:
                    h_data = json.loads(jf.read_text(encoding="utf-8"))
                    if isinstance(h_data, dict):
                        entries = h_data.get("results", [])
                    elif isinstance(h_data, list):
                        entries = h_data
                    else:
                        entries = []

                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        raw_port = entry.get("port")
                        if not raw_port:
                            continue
                        try:
                            port_num = int(raw_port)
                        except Exception:
                            continue

                        # If network port scans ran, do not accept HTTPX port if network scans proved it is closed
                        if network_scans_performed and port_num not in port_to_service_nodes:
                            continue

                        tech_list = entry.get("tech") or entry.get("technologies") or []
                        if isinstance(tech_list, str):
                            tech_list = [t.strip() for t in tech_list.split(",") if t.strip()]

                        port_node_id = f"port:{target_id}:tcp-{port_num}"
                        if port_node_id not in nodes_map:
                            nodes_map[port_node_id] = GraphNode(
                                id=port_node_id,
                                target_id=target_id,
                                type=NodeType.PORT,
                                label=f"{port_num}/tcp",
                                risk_level=NodeRiskLevel.INFO,
                                properties={"port": port_num, "protocol": "tcp"},
                                created_at=now,
                                updated_at=now,
                            )
                            edge_id = f"edge:{root_id}->{port_node_id}"
                            edges_map[edge_id] = GraphEdge(
                                id=edge_id,
                                target_id=target_id,
                                source=root_id,
                                target=port_node_id,
                                relation=RelationType.EXPOSES,
                                label="open port",
                                properties={},
                                created_at=now,
                            )

                        for tname in tech_list:
                            t_slug = tname.replace(" ", "_").replace("/", "_").lower()
                            t_id = f"tech:{target_id}:{port_num}:{t_slug}"
                            if t_id not in nodes_map:
                                nodes_map[t_id] = GraphNode(
                                    id=t_id,
                                    target_id=target_id,
                                    type=NodeType.TECHNOLOGY,
                                    label=tname,
                                    risk_level=NodeRiskLevel.INFO,
                                    properties={"technology": tname, "port": port_num},
                                    created_at=now,
                                    updated_at=now,
                                )
                                source_for_tech = (
                                    port_to_service_nodes[port_num][0]
                                    if port_num in port_to_service_nodes
                                    else port_node_id
                                )
                                edge_id = f"edge:{source_for_tech}->{t_id}"
                                edges_map[edge_id] = GraphEdge(
                                    id=edge_id,
                                    target_id=target_id,
                                    source=source_for_tech,
                                    target=t_id,
                                    relation=RelationType.USES_TECH,
                                    label="tech",
                                    properties={},
                                    created_at=now,
                                    )
                except Exception:
                    pass

        # 4. Ingest Findings & Vulnerabilities with Threat Intelligence
        findings = findings_db.list_findings(target_id=target_id)
        if not findings and target_id.startswith("target-"):
            findings = findings_db.list_findings(target_id=target_id[7:])
        if not findings:
            clean = target_id.replace("target-", "")
            findings = findings_db.list_findings(target_id=clean)

        for f in findings:
            risk = sev_to_risk(f.cvss_severity.value)
            vuln_key = f.cve_id or f.id
            vuln_node_id = f"vuln:{target_id}:{vuln_key}"

            # Query Threat Intelligence from DB
            ti_data: dict[str, Any] = {}
            if f.cve_id:
                try:
                    with db.get_connection() as conn:
                        c_row = conn.cursor().execute(
                            "SELECT is_cisa_kev, epss_score, epss_percentile, cvss_v4_score, cvss_v4_vector, cvss_v4_severity FROM cve WHERE cve_id = ?",
                            (f.cve_id.upper(),)
                        ).fetchone()
                        if c_row:
                            ti_data = dict(c_row)
                except Exception:
                    pass

            is_kev = bool(ti_data.get("is_cisa_kev", 0) or getattr(f, "is_cisa_kev", False))
            epss_score = ti_data.get("epss_score") or getattr(f, "epss_score", None)
            epss_percentile = ti_data.get("epss_percentile") or getattr(f, "epss_percentile", None)
            cvss_v4_score = ti_data.get("cvss_v4_score") or getattr(f, "cvss_v4_score", None)
            cvss_v4_vector = ti_data.get("cvss_v4_vector") or getattr(f, "cvss_v4_vector", None)
            cvss_v4_severity = ti_data.get("cvss_v4_severity") or getattr(f, "cvss_v4_severity", None)

            source_tools = list(
                {e.tool for e in f.evidence_chain if getattr(e, "tool", None)}
            )

            # Create or update Vulnerability Node
            if vuln_node_id not in nodes_map:
                v_label = f"{f.cve_id or f.title} [{f.cvss_score} {f.cvss_severity.value}]"
                nodes_map[vuln_node_id] = GraphNode(
                    id=vuln_node_id,
                    target_id=target_id,
                    type=NodeType.VULNERABILITY,
                    label=v_label,
                    risk_level=risk,
                    properties={
                        "cve_id": f.cve_id,
                        "cwe_id": f.cwe_id,
                        "cvss_score": f.cvss_score,
                        "cvss_severity": f.cvss_severity.value,
                        "cvss_v4_score": cvss_v4_score,
                        "cvss_v4_vector": cvss_v4_vector,
                        "cvss_v4_severity": cvss_v4_severity,
                        "is_cisa_kev": is_kev,
                        "epss_score": epss_score,
                        "epss_percentile": epss_percentile,
                        "status": f.status.value,
                        "remediation": f.remediation,
                        "trustworthy": f.trustworthy,
                        "is_simulated": f.is_simulated,
                        "source_tools": source_tools,
                    },
                    created_at=now,
                    updated_at=now,
                )
            else:
                existing_node = nodes_map[vuln_node_id]
                existing_tools = set(existing_node.properties.get("source_tools", []))
                existing_tools.update(source_tools)
                existing_node.properties["source_tools"] = sorted(list(existing_tools))
                if f.trustworthy:
                    existing_node.properties["trustworthy"] = True
                    existing_node.properties["is_simulated"] = False

            # Connect Vulnerability to Port or Service
            connected = False
            affected = f.affected_asset
            if ":" in affected:
                try:
                    port_str = affected.split(":")[-1].split("/")[0]
                    p_num = int(port_str)
                    if p_num in port_to_service_nodes:
                        for svc_id in port_to_service_nodes[p_num]:
                            e_id = f"edge:{svc_id}->{vuln_node_id}"
                            edges_map[e_id] = GraphEdge(
                                id=e_id,
                                target_id=target_id,
                                source=svc_id,
                                target=vuln_node_id,
                                relation=RelationType.VULNERABLE_TO,
                                label="vulnerable",
                                properties={"severity": f.cvss_severity.value},
                                created_at=now,
                            )
                            connected = True
                    else:
                        if network_scans_performed:
                            # Port is confirmed CLOSED by active network scans!
                            # Do NOT create fake open port node or active attack path
                            if vuln_node_id in nodes_map:
                                nodes_map[vuln_node_id].properties["port_status"] = "closed"
                                nodes_map[vuln_node_id].properties["trustworthy"] = False
                            e_id = f"edge:{root_id}->{vuln_node_id}"
                            edges_map[e_id] = GraphEdge(
                                id=e_id,
                                target_id=target_id,
                                source=root_id,
                                target=vuln_node_id,
                                relation=RelationType.VULNERABLE_TO,
                                label="unverified (closed port)",
                                properties={"severity": f.cvss_severity.value, "closed_port": p_num},
                                created_at=now,
                            )
                            connected = True
                        else:
                            port_id = f"port:{target_id}:tcp-{p_num}"
                            if port_id not in nodes_map:
                                nodes_map[port_id] = GraphNode(
                                    id=port_id,
                                    target_id=target_id,
                                    type=NodeType.PORT,
                                    label=f"{p_num}/tcp",
                                    risk_level=NodeRiskLevel.INFO,
                                    properties={"port": p_num, "protocol": "tcp"},
                                    created_at=now,
                                    updated_at=now,
                                )
                                edge_id = f"edge:{root_id}->{port_id}"
                                edges_map[edge_id] = GraphEdge(
                                    id=edge_id,
                                    target_id=target_id,
                                    source=root_id,
                                    target=port_id,
                                    relation=RelationType.EXPOSES,
                                    label="open port",
                                    properties={},
                                    created_at=now,
                                )
                            e_id = f"edge:{port_id}->{vuln_node_id}"
                            edges_map[e_id] = GraphEdge(
                                id=e_id,
                                target_id=target_id,
                                source=port_id,
                                target=vuln_node_id,
                                relation=RelationType.VULNERABLE_TO,
                                label="vulnerable",
                                properties={"severity": f.cvss_severity.value},
                                created_at=now,
                            )
                            connected = True
                except Exception:
                    pass

            if not connected:
                e_id = f"edge:{root_id}->{vuln_node_id}"
                edges_map[e_id] = GraphEdge(
                    id=e_id,
                    target_id=target_id,
                    source=root_id,
                    target=vuln_node_id,
                    relation=RelationType.VULNERABLE_TO,
                    label="vulnerable",
                    properties={"severity": f.cvss_severity.value},
                    created_at=now,
                )

            # Generate Causal IMPACT & LATERAL_MOVEMENT nodes for significant vulnerabilities
            if risk in (NodeRiskLevel.CRITICAL, NodeRiskLevel.HIGH) or is_kev:
                title_lower = (f.title or "").lower() + " " + (f.description or "").lower()
                if "traversal" in title_lower or "41773" in vuln_key or "42013" in vuln_key:
                    imp_label = "Lộ /etc/passwd & tệp cấu hình hệ thống"
                    imp_desc = "Khai thác Path Traversal đọc tuỳ ý các file nhạy cảm và source code ứng dụng."
                    lat_label = "Đánh cắp tài khoản & Pivot sang dịch vụ nội bộ"
                    lat_desc = "Kẻ tấn công dùng credentials tìm được để xác thực vào SSH/SMB nội bộ."
                elif "rce" in title_lower or "remote code" in title_lower or "log4j" in title_lower or "44228" in vuln_key:
                    imp_label = "Thực thi mã từ xa (RCE) trên tiến trình máy chủ"
                    imp_desc = "Chạy mã lệnh tuỳ ý với quyền của tiến trình dịch vụ."
                    lat_label = "Kiểm soát toàn diện máy chủ (Full Compromise)"
                    lat_desc = "Thiết lập reverse shell, leo thang đặc quyền root và quét mạng nội bộ."
                elif "sql" in title_lower or "injection" in title_lower:
                    imp_label = "Rò rỉ toàn bộ cơ sở dữ liệu & bảng người dùng"
                    imp_desc = "Trích xuất tài khoản, bảng mật khẩu và dữ liệu khách hàng."
                    lat_label = "Lạm dụng tài khoản quản trị hệ thống"
                    lat_desc = "Đăng nhập giao diện admin để can thiệp sâu vào cấu hình máy chủ."
                elif "ssh" in title_lower or "6387" in vuln_key:
                    imp_label = "Chiếm phiên dịch vụ từ xa qua sshd"
                    imp_desc = "Tận dụng race condition chiếm quyền thực thi trong tiến trình sshd."
                    lat_label = "Quyền root trên máy chủ & Pivot mạng nội bộ"
                    lat_desc = "Toàn quyền điều khiển máy chủ Linux và mở cổng pivot sang subnet bên trong."
                else:
                    imp_label = f"Hệ quả khai thác dữ liệu trên {f.affected_asset}"
                    imp_desc = f.description[:120] if f.description else "Lỗ hổng bị khai thác làm suy giảm an ninh nghiêm trọng."
                    lat_label = "Mở rộng bề mặt tấn công nội bộ"
                    lat_desc = "Kẻ tấn công tận dụng vị trí xâm nhập để trinh sát và leo thang quyền."

                impact_node_id = f"impact:{target_id}:{vuln_key}"
                if impact_node_id not in nodes_map:
                    nodes_map[impact_node_id] = GraphNode(
                        id=impact_node_id,
                        target_id=target_id,
                        type=NodeType.IMPACT,
                        label=imp_label,
                        risk_level=NodeRiskLevel.HIGH,
                        properties={"description": imp_desc, "impact_scope": "Data / Execution"},
                        created_at=now,
                        updated_at=now,
                    )
                    e_v_to_i = f"edge:{vuln_node_id}->{impact_node_id}"
                    edges_map[e_v_to_i] = GraphEdge(
                        id=e_v_to_i,
                        target_id=target_id,
                        source=vuln_node_id,
                        target=impact_node_id,
                        relation=RelationType.LEADS_TO,
                        label="dẫn đến hệ quả",
                        properties={},
                        created_at=now,
                    )

                lateral_node_id = f"lateral:{target_id}:{vuln_key}"
                if lateral_node_id not in nodes_map:
                    nodes_map[lateral_node_id] = GraphNode(
                        id=lateral_node_id,
                        target_id=target_id,
                        type=NodeType.LATERAL_MOVEMENT,
                        label=lat_label,
                        risk_level=NodeRiskLevel.CRITICAL,
                        properties={"description": lat_desc, "mitre_tactic": "Lateral Movement (TA0008)"},
                        created_at=now,
                        updated_at=now,
                    )
                    e_i_to_l = f"edge:{impact_node_id}->{lateral_node_id}"
                    edges_map[e_i_to_l] = GraphEdge(
                        id=e_i_to_l,
                        target_id=target_id,
                        source=impact_node_id,
                        target=lateral_node_id,
                        relation=RelationType.ENABLES_PIVOT,
                        label="nguy cơ leo thang",
                        properties={},
                        created_at=now,
                    )

            # Create Finding Node (Evidence)
            finding_node_id = f"finding:{target_id}:{f.id}"
            if finding_node_id not in nodes_map:
                f_evidence = [ev.model_dump() for ev in f.evidence_chain] if f.evidence_chain else []
                nodes_map[finding_node_id] = GraphNode(
                    id=finding_node_id,
                    target_id=target_id,
                    type=NodeType.FINDING,
                    label=f"Finding: {f.title[:28]}...",
                    risk_level=risk,
                    properties={
                        "finding_id": f.id,
                        "description": f.description,
                        "remediation": f.remediation,
                        "evidence_count": len(f_evidence),
                        "evidence_chain": f_evidence,
                    },
                    created_at=now,
                    updated_at=now,
                )
                e_id = f"edge:{vuln_node_id}->{finding_node_id}"
                edges_map[e_id] = GraphEdge(
                    id=e_id,
                    target_id=target_id,
                    source=vuln_node_id,
                    target=finding_node_id,
                    relation=RelationType.HAS_EVIDENCE,
                    label="evidence",
                    properties={},
                    created_at=now,
                )

        # Remove redundant direct root -> vuln edges if the vuln is already reachable via port/service
        vulns_with_port_or_svc = {
            e.target
            for e in edges_map.values()
            if e.relation == RelationType.VULNERABLE_TO and (e.source.startswith("port:") or e.source.startswith("svc:"))
        }
        for v_id in vulns_with_port_or_svc:
            redundant_edge_id = f"edge:{root_id}->{v_id}"
            if redundant_edge_id in edges_map:
                del edges_map[redundant_edge_id]

        # 5. Risk Propagation
        for e in list(edges_map.values()):
            if e.relation == RelationType.VULNERABLE_TO:
                vuln_node = nodes_map.get(e.target)
                source_node = nodes_map.get(e.source)
                if vuln_node and source_node:
                    v_val = RISK_ORDER.get(vuln_node.risk_level, 0)
                    s_val = RISK_ORDER.get(source_node.risk_level, 0)
                    if v_val > s_val:
                        source_node.risk_level = vuln_node.risk_level

        for e in list(edges_map.values()):
            if e.relation == RelationType.RUNS_SERVICE:
                svc_node = nodes_map.get(e.target)
                port_node = nodes_map.get(e.source)
                if svc_node and port_node:
                    svc_val = RISK_ORDER.get(svc_node.risk_level, 0)
                    port_val = RISK_ORDER.get(port_node.risk_level, 0)
                    if svc_val > port_val:
                        port_node.risk_level = svc_node.risk_level

        max_risk = NodeRiskLevel.SAFE
        max_val = 0
        for n in nodes_map.values():
            if n.type != NodeType.TARGET:
                val = RISK_ORDER.get(n.risk_level, 0)
                if val > max_val:
                    max_val = val
                    max_risk = n.risk_level
        if root_id in nodes_map:
            nodes_map[root_id].risk_level = max_risk

        # 6. Save to SQLite database
        final_nodes = list(nodes_map.values())
        final_edges = list(edges_map.values())
        graph_db.bulk_save(target_id, final_nodes, final_edges)

        # 7. Calculate Stats
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        crit_count = 0
        for n in final_nodes:
            t = n.type.value if hasattr(n.type, "value") else str(n.type)
            r = n.risk_level.value if hasattr(n.risk_level, "value") else str(n.risk_level)
            by_type[t] = by_type.get(t, 0) + 1
            by_risk[r] = by_risk.get(r, 0) + 1
            if r in ("CRITICAL", "HIGH"):
                crit_count += 1

        # 8. Compute Attack Paths
        attack_paths = build_attack_paths(final_nodes, final_edges, target_id)

        stats = GraphStats(
            total_nodes=len(final_nodes),
            total_edges=len(final_edges),
            by_type=by_type,
            by_risk=by_risk,
            critical_path_count=len(attack_paths) if attack_paths else crit_count,
        )

        return GraphDataResponse(
            target_id=target_id,
            nodes=final_nodes,
            edges=final_edges,
            stats=stats,
            attack_paths=attack_paths,
        )


graph_builder = GraphBuilder()
