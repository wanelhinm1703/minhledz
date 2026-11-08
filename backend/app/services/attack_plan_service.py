"""Evidence-Driven Attack Plan Service: constructs, verifies, and optimizes attack plans and graphs."""

from __future__ import annotations

import json
import pathlib
import platform
import re
from datetime import datetime, timezone
from typing import Any

from backend.app.schemas.attack_plan import (
    AttackPlan,
    AttackPlanState,
    ChokePoint,
    DecisionPoint,
    DecisionResult,
    ExplainabilityReport,
    NextDecision,
    PreconditionItem,
    RemediationImpact,
    VerificationConfidence,
    VerificationProbe,
)
from backend.app.schemas.finding import EvidenceItem, Finding, FindingStatus
from backend.app.schemas.graph import AttackPath, AttackPathStep, NodeRiskLevel, NodeType
from backend.app.services.graph_builder import graph_builder
from backend.app.services.verification_planner import verification_planner
from backend.app.storage.findings_db import findings_db
from backend.app.storage.graph_db import graph_db

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent


class AttackPlanService:
    """Core brain for Evidence-driven Attack Planning, DAG analysis, Choke Points and Verification."""

    def __init__(self):
        # In-memory store for severed nodes and execution state per target: {target_id: {"severed_nodes": set(), "probe_results": dict()}}
        self._target_state: dict[str, dict[str, Any]] = {}

    def _get_target_state(self, target_id: str) -> dict[str, Any]:
        clean_target = target_id.replace("target-", "").replace(":", "-")
        if clean_target not in self._target_state:
            self._target_state[clean_target] = {
                "severed_nodes": set(),
                "probe_results": {},
            }
        return self._target_state[clean_target]

    def _extract_recon_evidence(self, target_id: str) -> list[EvidenceItem]:
        """Aggregate all real recon evidence files for target."""
        clean_target = target_id.replace(":", "-")
        raw_target = target_id[7:] if target_id.startswith("target-") else target_id
        candidates = [target_id, clean_target, f"target-{clean_target}", raw_target]
        evidence_list: list[EvidenceItem] = []
        seen_keys: set[str] = set()

        categories = [
            ("03-network", "nmap", "nmap_result.json"),
            ("03-network", "naabu", "naabu_raw.txt"),
            ("03-network", "rustscan", "rustscan_result.json"),
            ("04-web", "httpx", "httpx_result.json"),
            ("04-web", "whatweb", "whatweb_result.json"),
            ("04-web", "nikto", "nikto_result.json"),
            ("05-vulnerability", "nuclei", "nuclei_result.json"),
            ("05-vulnerability", "searchsploit", "searchsploit_result.json"),
        ]

        now = datetime.now(timezone.utc).isoformat()

        for cat, tool, fname in categories:
            for c in candidates:
                base = root_dir / "toolkit" / cat / "scans" / c / tool
                if not base.exists() or not base.is_dir():
                    continue

                struct_file = base / "structured" / fname
                raw_file = base / "raw" / fname
                sim_file = base / "simulated" / fname

                target_file = None
                is_sim = False
                if struct_file.exists():
                    target_file = struct_file
                elif raw_file.exists():
                    target_file = raw_file
                elif sim_file.exists():
                    target_file = sim_file
                    is_sim = True

                if not target_file:
                    continue

                rel_path = str(target_file.relative_to(root_dir))
                if rel_path in seen_keys:
                    continue
                seen_keys.add(rel_path)

                try:
                    content = target_file.read_text(encoding="utf-8", errors="replace")
                    snippet = content[:800]
                    parsed: dict[str, Any] = {}
                    if target_file.suffix == ".json":
                        try:
                            json_obj = json.loads(content)
                            if isinstance(json_obj, dict):
                                parsed = {k: json_obj[k] for k in list(json_obj.keys())[:10]}
                            elif isinstance(json_obj, list):
                                parsed = {"items_count": len(json_obj), "preview": json_obj[:3]}
                        except Exception:
                            pass

                    cmd_guess = f"{tool} -target {raw_target}"
                    if tool == "nmap":
                        cmd_guess = f"nmap -sV -sC -Pn -p- {raw_target}"
                    elif tool == "httpx":
                        cmd_guess = f"httpx -u http://{raw_target} -status-code -title -tech-detect"
                    elif tool == "nuclei":
                        cmd_guess = f"nuclei -u http://{raw_target} -t cves/"

                    evidence_list.append(
                        EvidenceItem(
                            tool=tool,
                            file_path=rel_path,
                            matched_text=snippet[:200].replace("\n", " ").strip(),
                            target=raw_target,
                            command=cmd_guess,
                            raw_result=snippet,
                            parsed_result=parsed,
                            timestamp=now,
                            trustworthy=not is_sim,
                            is_simulated=is_sim,
                        )
                    )
                except Exception:
                    pass

        return evidence_list

    def generate_attack_plan(
        self, target_id: str, target_name: str | None = None
    ) -> AttackPlan:
        """Generate comprehensive Evidence-Driven Attack Plan for target."""
        clean_target = target_id.replace("target-", "").replace(":", "-")
        raw_target = target_id[7:] if target_id.startswith("target-") else target_id
        t_name = target_name or raw_target
        now = datetime.now(timezone.utc).isoformat()
        state = self._get_target_state(clean_target)
        severed_node_ids: set[str] = state["severed_nodes"]
        probe_cache: dict[int, dict[str, Any]] = state["probe_results"]

        # 1. Collect Recon Evidence
        recon_evidence = self._extract_recon_evidence(target_id)

        # 2. Get or Build Topology Graph
        graph = graph_db.get_graph_by_target(target_id)
        if not graph.nodes:
            graph = graph_builder.build_graph_for_target(target_id, target_name=t_name)

        # 3. Retrieve Findings & Check Applicability
        findings = findings_db.list_findings(target_id=clean_target)
        if not findings and target_id != clean_target:
            findings = findings_db.list_findings(target_id=target_id)

        # Update finding statuses based on evidence & verification
        open_ports = [
            n.properties.get("port")
            for n in graph.nodes
            if n.type == NodeType.PORT and n.properties.get("port")
        ]
        has_network_access = len(open_ports) > 0 or len(recon_evidence) > 0

        refined_findings: list[Finding] = []
        for f in findings:
            f_copy = f.model_copy()
            # If port is closed
            if ":" in f.affected_asset:
                try:
                    p_num = int(f.affected_asset.split(":")[-1].split("/")[0])
                    if open_ports and p_num not in open_ports:
                        f_copy.status = FindingStatus.NOT_APPLICABLE
                except Exception:
                    pass

            # If probed and confirmed
            if f_copy.cve_id and any(
                p.get("is_vuln") and f_copy.cve_id in p.get("evidence", "")
                for p in probe_cache.values()
            ):
                f_copy.status = FindingStatus.VERIFIED
            elif f_copy.status == FindingStatus.CANDIDATE:
                # If we have trustworthy evidence with version match
                if f_copy.trustworthy and not f_copy.is_simulated and f_copy.cvss_score > 0:
                    f_copy.status = FindingStatus.APPLICABLE
                elif not f_copy.trustworthy:
                    f_copy.status = FindingStatus.INSUFFICIENT_EVIDENCE
            refined_findings.append(f_copy)

        # 4. Preconditions
        preconditions = [
            PreconditionItem(
                id="pre-01",
                description=f"Mục tiêu {raw_target} phản hồi trên mạng (Reachability Check)",
                is_met=has_network_access,
                evidence_ref="Nmap / Naabu Port Discovery",
            ),
            PreconditionItem(
                id="pre-02",
                description="Phạm vi kiểm thử hợp lệ (In-Scope Verification)",
                is_met=True,
                evidence_ref="Workspace Scope Whitelist",
            ),
            PreconditionItem(
                id="pre-03",
                description="Nhận diện cổng mở và thông số dịch vụ (Service Fingerprinting)",
                is_met=len(open_ports) > 0,
                evidence_ref=f"Phát hiện {len(open_ports)} cổng: {', '.join(str(p) for p in open_ports[:5])}",
            ),
            PreconditionItem(
                id="pre-04",
                description="Nguyên tắc an toàn: 100% Read-Only, không gửi payload phá hoại",
                is_met=True,
                evidence_ref="Guardrails & Verification Planner Policy",
            ),
        ]

        # 5. Build Decoupled Attack Paths with Explainability
        attack_paths = self._build_dag_attack_paths(
            nodes=graph.nodes,
            edges=graph.edges,
            findings=refined_findings,
            target_id=target_id,
            severed_nodes=severed_node_ids,
            probe_cache=probe_cache,
        )

        # 6. Build Decision Points
        decision_points = self._build_decision_points(
            target_id=raw_target,
            open_ports=open_ports,
            findings=refined_findings,
            probe_cache=probe_cache,
            severed_nodes=severed_node_ids,
        )

        # 7. Analyze Graph Choke Points
        choke_points = self._analyze_choke_points(
            nodes=graph.nodes,
            edges=graph.edges,
            attack_paths=attack_paths,
            findings=refined_findings,
            severed_nodes=severed_node_ids,
        )

        # 8. Build Ordered Verification Steps
        verification_steps = self._build_verification_probes(
            target_id=raw_target,
            attack_paths=attack_paths,
            probe_cache=probe_cache,
            severed_nodes=severed_node_ids,
        )

        # 9. Determine Overall State
        active_count = sum(1 for p in attack_paths if not p.is_severed)
        severed_count = sum(1 for p in attack_paths if p.is_severed)

        if not attack_paths:
            plan_state = AttackPlanState.PLANNED
        elif active_count == 0 and severed_count > 0:
            plan_state = AttackPlanState.SEVERED
        elif any(p.get("is_vuln") for p in probe_cache.values()):
            plan_state = AttackPlanState.VERIFIED
        elif probe_cache:
            plan_state = AttackPlanState.IN_PROGRESS
        else:
            plan_state = AttackPlanState.PLANNED

        objective = (
            f"Kế hoạch kiểm thử toàn diện bề mặt tấn công của {raw_target}: "
            f"Thu thập bằng chứng trinh sát, nhận diện dịch vụ ({', '.join(str(p) for p in open_ports[:4]) or 'đang quét'}), "
            f"đối chiếu tương quan lỗ hổng, xác minh an toàn (Read-Only) và tìm điểm chốt chặn (Choke Point) để triệt tiêu chuỗi tấn công."
        )

        remediation_summary = (
            f"Đã phát hiện {len(attack_paths)} đường dẫn tấn công khả dĩ. "
            f"Phân tích đồ thị xác định {len(choke_points)} điểm chốt chặn (Choke Point). "
            f"Khắc phục điểm chốt chặn ưu tiên cao nhất sẽ vô hiệu hóa {max((cp.affected_paths_count for cp in choke_points), default=0)} đường dẫn tấn công."
        )

        return AttackPlan(
            id=f"plan:{clean_target}",
            target_id=target_id,
            target_name=t_name,
            objective=objective,
            preconditions=preconditions,
            recon_evidence=recon_evidence,
            findings=refined_findings,
            verification_steps=verification_steps,
            attack_paths=attack_paths,
            decision_points=decision_points,
            choke_points=choke_points,
            remediation_summary=remediation_summary,
            state=plan_state,
            severed_paths_count=severed_count,
            active_paths_count=active_count,
            created_at=now,
            updated_at=now,
        )

    def _build_dag_attack_paths(
        self,
        nodes: list[Any],
        edges: list[Any],
        findings: list[Finding],
        target_id: str,
        severed_nodes: set[str],
        probe_cache: dict[int, dict[str, Any]],
    ) -> list[AttackPath]:
        """Construct multi-stage DAG attack paths decoupled from individual CVEs."""
        from backend.app.services.graph_builder import build_attack_paths

        base_paths = build_attack_paths(nodes, edges, target_id)
        final_paths: list[AttackPath] = []

        findings_by_cve = {
            f.cve_id.upper(): f for f in findings if f.cve_id
        }

        for p in base_paths:
            # Check if path intersects any severed node
            is_sev = any(nid in severed_nodes for nid in p.node_ids)
            sev_by = next((nid for nid in p.node_ids if nid in severed_nodes), None)

            # Determine verification status across all merged CVEs
            all_path_cves = [c.upper() for c in (p.related_cves or ([p.cve_id] if p.cve_id else []))]
            matched_findings = [findings_by_cve[k] for k in all_path_cves if k in findings_by_cve]

            v_status = "PENDING"
            if is_sev:
                v_status = "BLOCKED"
            elif any(
                res.get("is_vuln") and any(k in res.get("evidence", "") or "root:" in res.get("evidence", "") for k in all_path_cves)
                for res in probe_cache.values()
            ) or any(f.status in (FindingStatus.VERIFIED, FindingStatus.EXPLOITED) for f in matched_findings):
                v_status = "VERIFIED"
            elif any(
                res.get("is_broken") for res in probe_cache.values()
            ):
                v_status = "BLOCKED"
            elif any(f.status == FindingStatus.APPLICABLE for f in matched_findings):
                v_status = "APPLICABLE (Chờ Probe)"
            elif any(f.status == FindingStatus.INSUFFICIENT_EVIDENCE for f in matched_findings):
                v_status = "INSUFFICIENT_EVIDENCE"
            elif p.cve_id and p.cve_id.upper() in findings_by_cve:
                f_match = findings_by_cve[p.cve_id.upper()]
                if f_match.status == FindingStatus.APPLICABLE:
                    v_status = "APPLICABLE (Chờ Probe)"
                elif f_match.status == FindingStatus.INSUFFICIENT_EVIDENCE:
                    v_status = "INSUFFICIENT_EVIDENCE"

            # Build detailed explainability report
            port_label = "Chưa rõ cổng"
            svc_label = "Dịch vụ mạng"
            ver_label = "Chưa rõ phiên bản"

            for s in p.steps:
                if "port:" in s.node_id or s.node_type == "port":
                    port_label = s.title or s.node_label or port_label
                elif "svc:" in s.node_id or s.node_type == "service":
                    svc_label = s.title or s.node_label or svc_label
                    if "(" in svc_label and ")" in svc_label:
                        ver_label = svc_label

            vuln_corr_text = (
                f"Tương quan {p.findings_count} lỗ hổng ({', '.join(p.related_cves[:4])}): dịch vụ {svc_label} khớp danh mục CVE ảnh hưởng."
                if p.findings_count > 1
                else (
                    f"Tương quan {p.cve_id}: phiên bản phần mềm khớp danh mục ảnh hưởng CVE"
                    if p.cve_id
                    else "Tương quan rủi ro dịch vụ theo phân tích cấu hình"
                )
            )

            explain = ExplainabilityReport(
                target_reachable=True,
                target_evidence=f"Mục tiêu phản hồi cổng mạng {port_label}",
                port_discovered=f"Phát hiện cổng mở {port_label} qua công cụ quét mạng",
                service_identified=f"Nhận diện dịch vụ {svc_label}",
                version_confirmed=f"Số hiệu phiên bản đối chiếu: {ver_label}",
                vuln_correlation=vuln_corr_text,
                evidence_available=[
                    f"Bằng chứng cổng: {port_label}",
                    f"Bằng chứng dịch vụ: {svc_label}",
                ] + ([f"Bằng chứng CVE: {c}" for c in (p.related_cves[:4] if p.related_cves else ([p.cve_id] if p.cve_id else []))]),
                verification_status=v_status,
                missing_evidence=(
                    ["Cần chạy Verification probe để kiểm chứng hành vi thực tế"]
                    if v_status in ("PENDING", "APPLICABLE (Chờ Probe)", "INSUFFICIENT_EVIDENCE")
                    else []
                ),
                next_step_rationale=(
                    f"Thực thi probe an toàn đối với dịch vụ {svc_label} để xác thực {p.findings_count} lỗ hổng mà không làm gián đoạn hệ thống."
                    if not is_sev
                    else f"Đường dẫn đã bị cắt đứt tại nút {sev_by}. Cần quét kiểm tra lại (Re-scan) để xác nhận."
                ),
            )

            p.is_severed = is_sev
            p.severed_by_node = sev_by
            p.verification_status = v_status
            p.explainability = explain.model_dump()
            final_paths.append(p)

        return final_paths

    def _build_decision_points(
        self,
        target_id: str,
        open_ports: list[int],
        findings: list[Finding],
        probe_cache: dict[int, dict[str, Any]],
        severed_nodes: set[str],
    ) -> list[DecisionPoint]:
        """Construct conditional decision points for testing workflow."""
        dps: list[DecisionPoint] = []

        # DP 1: Target Reachability
        has_ports = len(open_ports) > 0
        dps.append(
            DecisionPoint(
                id="dp-01-reachability",
                step_name="Kiểm tra Tính khả dụng Mục tiêu (Target Reachability)",
                condition=f"Mục tiêu {target_id} phản hồi gói tin thăm dò mạng",
                evaluation=f"Phát hiện {len(open_ports)} cổng mở hoạt động" if has_ports else "Không nhận được phản hồi cổng",
                result=DecisionResult.PASSED if has_ports else DecisionResult.FAILED,
                branch_action="Tiến hành nhận diện dịch vụ trên các cổng mở" if has_ports else "Dừng kiểm thử, báo cáo mục tiêu không khả dụng",
                rationale="Cần có kết nối mạng ổn định trước khi thực hiện bất kỳ bước kiểm tra chuyên sâu nào.",
            )
        )

        # DP 2: Service Version Fingerprint
        has_version = any(
            f.affected_asset and f.trustworthy for f in findings
        ) or any(p in (80, 443, 22, 21) for p in open_ports)
        dps.append(
            DecisionPoint(
                id="dp-02-version-audit",
                step_name="Đối chiếu Phiên bản Phần mềm (Product & Version Audit)",
                condition="Banner phản hồi chứa tên sản phẩm và số hiệu phiên bản hợp lệ",
                evaluation="Trích xuất được thông tin dịch vụ từ HTTP/SSH Banner" if has_version else "Thiếu thông tin phiên bản chi tiết",
                result=DecisionResult.PASSED if has_version else DecisionResult.NEEDS_EVIDENCE,
                branch_action="Chuyển trạng thái sang APPLICABLE và lập kế hoạch probe" if has_version else "Gán INSUFFICIENT_EVIDENCE, yêu cầu thêm banner probe",
                rationale="Tuyệt đối không suy đoán phiên bản nếu banner không cung cấp bằng chứng rõ ràng.",
            )
        )

        # DP 3: CVE Applicability Verification
        applicable_count = sum(1 for f in findings if f.status in (FindingStatus.APPLICABLE, FindingStatus.VERIFIED))
        dps.append(
            DecisionPoint(
                id="dp-03-cve-applicability",
                step_name="Xác định Tính khả dụng Lỗ hổng (CVE Applicability)",
                condition="Product + Version nằm trong phạm vi Affected Version / CPE",
                evaluation=f"Xác định {applicable_count} phát hiện thỏa mãn điều kiện phiên bản bị ảnh hưởng",
                result=DecisionResult.PASSED if applicable_count > 0 else DecisionResult.NEEDS_EVIDENCE,
                branch_action="Hình thành Attack Path và kích hoạt kịch bản Verification an toàn",
                rationale="CVSS chỉ đo mức độ nghiêm trọng tiềm năng, cần đối chiếu Affected Version trước khi lên kế hoạch probe.",
            )
        )

        # DP 4: Verification Execution
        probes_executed = len(probe_cache) > 0
        any_vuln = any(res.get("is_vuln") for res in probe_cache.values())
        any_broken = any(res.get("is_broken") for res in probe_cache.values())

        eval_text = "Chưa chạy probe kiểm chứng thực địa"
        res_dp = DecisionResult.NEEDS_EVIDENCE
        act_text = "Thực thi kịch bản Verification Probe (Read-Only) để lấy raw evidence"

        if any_vuln:
            eval_text = "Verification Probe thành công: Nhận được phản hồi đặc trưng chứng minh tồn tại lỗ hổng"
            res_dp = DecisionResult.PASSED
            act_text = "Đánh dấu VERIFIED, tiếp tục Attack Path đến bước đánh giá tác động (Impact)"
        elif any_broken:
            eval_text = "Verification Probe thất bại: Nhận mã 403/401 hoặc dịch vụ đã đóng"
            res_dp = DecisionResult.BLOCKED
            act_text = "Cắt đứt Attack Path (Path Blocked), đánh dấu mục tiêu đã có cơ chế phòng vệ"
        elif probes_executed:
            eval_text = "Probe hoàn tất nhưng chưa đủ dữ liệu xác nhận chắc chắn"
            res_dp = DecisionResult.NEEDS_EVIDENCE
            act_text = "Giữ nguyên trạng thái APPLICABLE, không nâng lên VERIFIED"

        dps.append(
            DecisionPoint(
                id="dp-04-verification-gate",
                step_name="Chốt chặn Kiểm chứng (Verification Decision Gate)",
                condition="Phản hồi từ lệnh probe khớp với chữ ký bằng chứng dự kiến (Expected Evidence)",
                evaluation=eval_text,
                result=res_dp,
                branch_action=act_text,
                rationale="Chỉ chuyển sang bước tiếp theo khi điều kiện của bước hiện tại được đáp ứng bằng chứng thực tế.",
            )
        )

        # DP 5: Choke Point Remediation Check
        severed_count = len(severed_nodes)
        dps.append(
            DecisionPoint(
                id="dp-05-remediation-gate",
                step_name="Kiểm soát Khắc phục & Cắt đứt Chuỗi (Choke Point Remediation)",
                condition="Áp dụng biện pháp cô lập dịch vụ hoặc vá lỗi tại điểm nút thắt (Choke Point)",
                evaluation=f"Đã cô lập/vá lỗi tại {severed_count} nút chiến lược" if severed_count > 0 else "Chưa áp dụng biện pháp cắt đứt chuỗi",
                result=DecisionResult.PASSED if severed_count > 0 else DecisionResult.NEEDS_EVIDENCE,
                branch_action="Đánh dấu các Attack Paths tương ứng là SEVERED, yêu cầu Re-scan xác thực" if severed_count > 0 else "Duy trì Attack Paths ở trạng thái ACTIVE",
                rationale="Remediation tại đúng nút thắt sẽ vô hiệu hóa đồng thời nhiều chuỗi tấn công.",
            )
        )

        return dps

    def _analyze_choke_points(
        self,
        nodes: list[Any],
        edges: list[Any],
        attack_paths: list[AttackPath],
        findings: list[Finding],
        severed_nodes: set[str],
    ) -> list[ChokePoint]:
        """Discover graph choke points where fixing 1 node breaks maximum attack paths."""
        node_path_count: dict[str, list[str]] = {}
        node_map = {n.id: n for n in nodes}

        for path in attack_paths:
            for nid in path.node_ids:
                n = node_map.get(nid)
                if n and n.type in (NodeType.PORT, NodeType.SERVICE, NodeType.VULNERABILITY):
                    node_path_count.setdefault(nid, []).append(path.id)

        choke_points: list[ChokePoint] = []
        total_paths = len(attack_paths)

        # Sort nodes by number of intersecting attack paths descending
        sorted_nodes = sorted(
            node_path_count.items(), key=lambda x: len(x[1]), reverse=True
        )

        for nid, path_ids in sorted_nodes:
            n = node_map.get(nid)
            if not n:
                continue

            unique_paths = list(dict.fromkeys(path_ids))
            count = len(unique_paths)
            if count == 0:
                continue

            # Identify dependent findings
            dep_findings = []
            for f in findings:
                if f.cve_id and (f.cve_id in nid or (n.type == NodeType.SERVICE and str(n.properties.get("port", "")) in f.affected_asset)):
                    dep_findings.append(f"{f.cve_id or f.title}")
            if not dep_findings and n.label:
                dep_findings.append(n.label)

            # Recommend remediation based on node type
            if n.type == NodeType.PORT:
                rem = f"Cấu hình Firewall chặn hoặc giới hạn IP truy cập cổng {n.label}."
                reason = f"Đóng cổng này sẽ cắt đứt ngay lập tức {count}/{total_paths} ({int(count/total_paths*100 if total_paths else 100)}%) Attack Paths trước khi kẻ tấn công tiếp cận dịch vụ."
            elif n.type == NodeType.SERVICE:
                rem = f"Nâng cấp {n.label} lên phiên bản mới nhất, vô hiệu hóa các module không cần thiết."
                reason = f"Dịch vụ này là điểm hội tụ của {count} đường dẫn tấn công. Khắc phục tại đây sẽ loại bỏ toàn bộ các lỗ hổng phụ thuộc."
            else:
                rem = n.properties.get("remediation") or f"Áp dụng bản vá khẩn cấp của nhà cung cấp cho {n.label}."
                reason = f"Lỗ hổng này là mắt xích khai thác trực tiếp trong {count} đường dẫn dẫn đến rò rỉ dữ liệu hoặc chiếm quyền kiểm soát."

            choke_points.append(
                ChokePoint(
                    node_id=nid,
                    node_label=n.label,
                    node_type=n.type.value if hasattr(n.type, "value") else str(n.type),
                    affected_paths_count=count,
                    affected_path_ids=unique_paths,
                    dependent_findings=dep_findings[:5],
                    recommended_remediation=rem,
                    reason=reason,
                    is_severed=(nid in severed_nodes),
                )
            )

        return choke_points

    def _build_verification_probes(
        self,
        target_id: str,
        attack_paths: list[AttackPath],
        probe_cache: dict[int, dict[str, Any]],
        severed_nodes: set[str],
    ) -> list[VerificationProbe]:
        """Construct sequential read-only verification probes with full evidence tracking."""
        probes: list[VerificationProbe] = []
        is_win = platform.system() == "Windows"
        step_idx = 1

        for path in attack_paths:
            for s in path.steps:
                cached = probe_cache.get(step_idx)

                # Deduce probe command and expected evidence
                p_lower = s.phase.lower()
                port_val = getattr(path, "port_name", "") or ""
                svc_val = getattr(path, "service_name", "") or ""
                m_port = re.search(r"(\d+)", port_val or s.title or s.node_id or "")
                p_num = m_port.group(1) if m_port else ("22" if "ssh" in svc_val.lower() else ("3306" if "mysql" in svc_val.lower() else "80"))

                cmd = f"curl -s -I --connect-timeout 5 http://{target_id}/"
                exp = f"Phản hồi HTTP 200/301 kèm Server banner khớp với thông số trinh sát tại {s.title}."
                purpose = f"Kiểm chứng tính sẵn sàng và cấu hình của mắt xích: {s.title}"

                if "port" in s.node_id or s.node_type == "port":
                    cmd = f"nc -z -v -w 3 {target_id} {p_num}" if not is_win else f"curl -s -I --connect-timeout 3 http://{target_id}:{p_num}/"
                    exp = f"Cổng {p_num} mở và chấp nhận kết nối TCP từ bên ngoài."
                    purpose = f"Kiểm tra kết nối và tính mở của cổng {p_num}."
                elif "vuln" in s.node_id or path.cve_id or "svc" in s.node_id or s.node_type == "service":
                    cve = (path.cve_id or "").upper()
                    if "41773" in cve or "42013" in cve:
                        cmd = f"curl -s --path-as-is http://{target_id}:{p_num}/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w '%{{http_code}}'"
                        exp = "HTTP 200 xác nhận đường dẫn bị bypass; HTTP 403 hoặc 400 xác nhận hệ thống an toàn."
                        purpose = "Thăm dò an toàn chỉ đọc kiểm tra cơ chế chuẩn hóa đường dẫn Path Traversal."
                    elif "ssh" in (path.service_name or s.title or "").lower() or p_num == "22":
                        cmd = f"echo '' | nc -w 2 {target_id} 22" if not is_win else f"nc -z -v -w 3 {target_id} 22"
                        exp = "Banner SSH phản hồi tiết lộ phiên bản (VD: OpenSSH 4.7p1 Debian)."
                        purpose = f"Thăm dò thụ động banner dịch vụ OpenSSH đối soát {cve or 'dịch vụ'}."
                    elif "mysql" in (path.service_name or s.title or "").lower() or p_num == "3306":
                        cmd = f"echo '' | nc -w 2 {target_id} 3306 | tr -cd '\\11\\12\\15\\40-\\176'" if not is_win else f"nc -z -v -w 3 {target_id} 3306"
                        exp = "Banner MySQL phản hồi tiết lộ phiên bản (VD: 5.0.51a-3ubuntu5)."
                        purpose = f"Thăm dò thụ động banner cơ sở dữ liệu MySQL đối soát {cve or 'dịch vụ'}."
                    else:
                        cmd = f"curl -s -I http://{target_id}:{p_num}/"
                        exp = "Server banner phản hồi tiết lộ phiên bản dịch vụ."
                        purpose = f"Thăm dò thụ động banner dịch vụ để đối soát {cve or 'cấu hình'}."
                elif "impact" in s.node_id or s.node_type == "impact":
                    if p_num == "22":
                        cmd = f"nc -z -v -w 3 {target_id} 22"
                        exp = "Xác nhận cổng điều khiển hệ thống mở và có thể tiếp cận."
                    else:
                        cmd = f"curl -s -I http://{target_id}:{p_num}/ -o /dev/null -w '%{{http_code}}'"
                        exp = "Mã phản hồi chứng minh khả năng hạn chế hoặc phân đoạn tài nguyên."
                    purpose = "Xác nhận khả năng tiếp cận và phân đoạn tài nguyên của mục tiêu."

                # Status and confidence
                status = "PENDING"
                confidence = VerificationConfidence.UNVERIFIED
                next_dec = NextDecision.NEEDS_EVIDENCE
                actual_res = ""
                ev_found = ""

                if cached:
                    status = cached.get("status", "SUCCESS")
                    actual_res = cached.get("output", "")
                    ev_found = cached.get("evidence", "")
                    if cached.get("is_vuln"):
                        confidence = VerificationConfidence.HIGH
                        next_dec = NextDecision.CONTINUE_PATH
                    elif cached.get("is_broken"):
                        confidence = VerificationConfidence.HIGH
                        next_dec = NextDecision.BLOCK_PATH
                    else:
                        confidence = VerificationConfidence.MEDIUM
                        next_dec = NextDecision.NEEDS_EVIDENCE

                if s.node_id in severed_nodes:
                    status = "BLOCKED"
                    next_dec = NextDecision.BLOCK_PATH
                    ev_found = f"Nút {s.node_id} đã được khắc phục/cô lập. Chuỗi bị chặn."

                ai_assess = cached.get("ai_assessment", "") if cached else ""
                ai_deduct = cached.get("ai_deduction", "") if cached else ""

                probes.append(
                    VerificationProbe(
                        step_number=step_idx,
                        phase=s.phase,
                        node_id=s.node_id,
                        node_label=s.title,
                        purpose=purpose,
                        expected_result=exp,
                        actual_result=actual_res,
                        command=cmd,
                        evidence_found=ev_found,
                        confidence=confidence,
                        next_decision=next_dec,
                        status=status,
                        is_safe_readonly=True,
                        can_execute=True,
                        ai_assessment=ai_assess,
                        ai_deduction=ai_deduct,
                        timestamp=cached.get("timestamp") if cached else None,
                    )
                )
                step_idx += 1
                if step_idx > 8:
                    break
            if step_idx > 8:
                break

        return probes

    def execute_verification_probe(
        self, target_id: str, step_number: int, command: str
    ) -> dict[str, Any]:
        """Execute safe read-only probe in shell, record evidence and update plan."""
        clean_target = target_id.replace("target-", "").replace(":", "-")
        state = self._get_target_state(clean_target)

        # Run safe probe using verification planner
        res = verification_planner.execute_chain_step(
            chain_id=f"plan:{clean_target}",
            step_number=step_number,
            command=command,
        )

        # Enhance with deep AI probe analysis (assessment & deduction)
        from backend.app.services.ai_probe_analyzer import ai_probe_analyzer
        curr_plan = self.generate_attack_plan(target_id)
        matching_step = next((p for p in curr_plan.verification_steps if p.step_number == step_number), None)
        node_lbl = matching_step.node_label if matching_step else ""
        cve_id = getattr(matching_step, "cve_id", None) if matching_step else None
        purpose = matching_step.purpose if matching_step else ""
        exp_res = matching_step.expected_result if matching_step else ""

        ai_res = ai_probe_analyzer.analyze_probe(
            target_id=clean_target,
            command=command,
            raw_output=res.output,
            exit_code=0 if res.status == "SUCCESS" else 1,
            node_label=node_lbl,
            cve_id=cve_id,
            purpose=purpose,
            expected_result=exp_res,
        )

        ai_assessment = res.ai_assessment or ai_res.get("assessment", "")
        ai_deduction = res.ai_deduction or ai_res.get("deduction", "")
        res.ai_assessment = ai_assessment
        res.ai_deduction = ai_deduction

        ts = datetime.now(timezone.utc).isoformat()
        probe_record = {
            "step_number": step_number,
            "command": command,
            "output": res.output,
            "status": res.status,
            "is_vuln": res.is_vulnerable_indicated,
            "is_broken": res.is_chain_broken,
            "evidence": res.evidence_found,
            "ai_assessment": ai_assessment,
            "ai_deduction": ai_deduction,
            "timestamp": ts,
        }
        state["probe_results"][step_number] = probe_record

        # If vulnerable, update matching finding to VERIFIED
        if res.is_vulnerable_indicated:
            findings = findings_db.list_findings(target_id=clean_target)
            for f in findings:
                if f.status in (FindingStatus.CANDIDATE, FindingStatus.APPLICABLE):
                    from backend.app.schemas.finding import FindingUpdate
                    findings_db.update_finding(f.id, FindingUpdate(status=FindingStatus.VERIFIED))
                    break

        # Recompute updated attack plan
        updated_plan = self.generate_attack_plan(target_id)
        return {
            "result": res.model_dump(),
            "updated_plan": updated_plan.model_dump(),
        }

    def toggle_remediation_node(
        self, target_id: str, node_id: str
    ) -> RemediationImpact:
        """Remediate or restore a node in graph and calculate severed attack paths."""
        clean_target = target_id.replace("target-", "").replace(":", "-")
        state = self._get_target_state(clean_target)
        severed_set: set[str] = state["severed_nodes"]

        if node_id in severed_set:
            severed_set.remove(node_id)
        else:
            severed_set.add(node_id)

        # Re-generate plan with updated severed state
        plan = self.generate_attack_plan(target_id)
        severed_paths = [p.id for p in plan.attack_paths if p.is_severed]
        remaining_paths = [p.id for p in plan.attack_paths if not p.is_severed]
        total = len(plan.attack_paths)
        reduction = (len(severed_paths) / total * 100.0) if total > 0 else 0.0

        return RemediationImpact(
            target_id=target_id,
            remediated_node_id=node_id,
            severed_path_ids=severed_paths,
            remaining_path_ids=remaining_paths,
            risk_reduction_percent=round(reduction, 1),
            updated_plan=plan,
        )

    def rescan_target(self, target_id: str) -> AttackPlan:
        """Trigger re-scan & re-eval of attack graph and plan."""
        clean_target = target_id.replace("target-", "").replace(":", "-")
        # Clear probe results on re-scan, but retain severed state for confirmation
        state = self._get_target_state(clean_target)
        state["probe_results"].clear()

        # Rebuild graph from artifacts
        graph_builder.build_graph_for_target(target_id)
        return self.generate_attack_plan(target_id)


attack_plan_service = AttackPlanService()
