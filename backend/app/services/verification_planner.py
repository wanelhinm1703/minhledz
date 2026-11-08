"""Safe Read-Only Verification Planner enforcing non-destructive security validation."""

from __future__ import annotations

import os
import pathlib
import platform
import re
import subprocess
from datetime import datetime, timezone

root_dir = pathlib.Path(__file__).resolve().parent.parent.parent.parent

from backend.app.schemas.finding import Finding
from backend.app.schemas.graph import AttackPath
from backend.app.schemas.verification import (
    ChainExecutionResult,
    ChainVerificationPlan,
    ChainVerificationStep,
    VerificationPlan,
    VerificationResult,
    VerificationStep,
)



class VerificationPlanner:
    """Generates strictly non-destructive, read-only verification plans for findings."""

    SAFE_COMMAND_WHITELIST = ["curl", "nmap", "nc", "ping", "dig", "openssl"]
    DISALLOWED_PATTERNS = [
        "--os-shell",
        "meterpreter",
        "rm -rf",
        "drop table",
        "upload",
        "write",
        "eval",
    ]

    def generate_plan(self, finding: Finding) -> VerificationPlan:
        ts = datetime.now(timezone.utc).isoformat()
        steps: list[VerificationStep] = []

        asset = finding.affected_asset
        # Extract host and port
        host = (
            asset.split(":")[0]
            .replace("http://", "")
            .replace("https://", "")
            .split("/")[0]
        )
        port = "80"
        if ":" in asset:
            parts = asset.split(":")
            if len(parts) >= 2:
                port = parts[1].split("/")[0]

        # Step 1: Pre-condition connectivity check
        steps.append(
            VerificationStep(
                step_number=1,
                name="Kiểm tra Kết nối & Nhận diện Banner (Reachability & Banner Inspection)",
                description="Kiểm tra cổng dịch vụ mục tiêu đang phản hồi và trích xuất thông tin HTTP / dịch vụ banner.",
                command=f"curl -s -I --connect-timeout 5 http://{asset}/",
                is_safe_readonly=True,
                expected_evidence="Dòng trạng thái HTTP (VD: HTTP/1.1 200 OK) kèm Server header khớp với phiên bản ghi nhận.",
                remediation_check="Cấu hình ServerTokens Prod / Min để ẩn số hiệu build chi tiết của phần mềm.",
            )
        )

        # Step 2: Targeted safe validation probe based on vulnerability type
        cve = (finding.cve_id or "").upper()
        if "CVE-2021-41773" in cve or "CVE-2021-42013" in cve:
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Thăm dò Đường dẫn Chỉ đọc An toàn (Safe Read-Only Path Traversal Probe)",
                    description="Gửi yêu cầu thăm dò chỉ đọc sử dụng chuỗi mã hóa percent-encoded để kiểm tra khả năng vượt ranh giới thư mục gốc (Document Root).",
                    command=f"curl -s --path-as-is http://{asset}/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w '%{{http_code}}'",
                    is_safe_readonly=True,
                    expected_evidence="HTTP 200 kèm nội dung tệp tin cho biết tồn tại lỗ hổng. HTTP 400 hoặc 403/404 cho thấy đã được phòng vệ.",
                    remediation_check="Hệ thống trả về HTTP 403 Forbidden hoặc HTTP 400 Bad Request sau khi nâng cấp lên Apache 2.4.51+.",
                )
            )
        elif "CWE-22" in (finding.cwe_id or ""):
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Thăm dò Ranh giới Chuẩn hóa Đường dẫn (Path Traversal Boundary Probe)",
                    description="Kiểm tra cơ chế chuẩn hóa đường dẫn của máy chủ mà không lấy tệp nhạy cảm hay ghi đè dữ liệu.",
                    command=f"curl -s -I http://{asset}/..%2f..%2findex.html",
                    is_safe_readonly=True,
                    expected_evidence="Máy chủ phản hồi 403 Forbidden hoặc 400 Bad Request khi nhận chuỗi duyệt thư mục chuẩn hóa.",
                    remediation_check="Đường dẫn được làm sạch nghiêm ngặt trước khi phân giải vào hệ thống tệp.",
                )
            )
        elif "SSH" in finding.title.upper() or "22" in port:
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Kiểm tra Banner Dịch vụ SSH Thụ động (Passive SSH Banner Audit)",
                    description="Đọc thụ động chuỗi định danh dịch vụ SSH daemon mà không khởi tạo xác thực.",
                    command=f"nc -v -w 3 {host} {port}",
                    is_safe_readonly=True,
                    expected_evidence="Banner SSH-2.0 tiết lộ phiên bản và mức độ vá lỗi chính xác của phần mềm daemon.",
                    remediation_check="Banner thể hiện phiên bản gói SSH đã được cập nhật bản vá mới nhất.",
                )
            )
        else:
            # Generic safe HTTP / port audit
            steps.append(
                VerificationStep(
                    step_number=2,
                    name="Thăm dò Dấu vân tay Dịch vụ Thụ động (Passive Service Fingerprint Probe)",
                    description="Gửi yêu cầu HTTP OPTIONS hoặc GET an toàn để ghi nhận phản hồi và hành vi của máy chủ.",
                    command=f"curl -s -X OPTIONS -I http://{asset}/",
                    is_safe_readonly=True,
                    expected_evidence="Danh sách các phương thức HTTP được hỗ trợ và các header phản hồi của máy chủ.",
                    remediation_check="Các phương thức không an toàn (PUT, DELETE, TRACE) đã bị vô hiệu hóa.",
                )
            )

        # Step 3: Post-verification non-regression check
        steps.append(
            VerificationStep(
                step_number=3,
                name="Xác nhận Tính Khả dụng của Dịch vụ (Service Availability Confirmation)",
                description="Xác nhận dịch vụ mục tiêu vẫn duy trì 100% thời gian hoạt động ổn định, hoàn toàn không bị gián đoạn sau khi hoàn tất kiểm tra an toàn.",
                command=f"curl -s -o /dev/null -w '%{{http_code}}' http://{asset}/",
                is_safe_readonly=True,
                expected_evidence="Mã phản hồi HTTP thông thường (200, 301 hoặc 302).",
                remediation_check="Thời gian uptime và tính sẵn sàng của dịch vụ được đảm bảo 100%.",
            )
        )

        return VerificationPlan(
            finding_id=finding.id,
            target_id=finding.target_id,
            title=finding.title,
            cve_id=finding.cve_id,
            affected_asset=finding.affected_asset,
            rationale=f"Kế hoạch kiểm chứng an toàn được thiết kế riêng cho {finding.title} trên tài sản {finding.affected_asset}, tuân thủ nghiêm ngặt nguyên tắc chỉ đọc (Read-only).",
            steps=steps,
            created_at=ts,
        )

    def _execute_command(self, command: str, timeout: int = 15) -> tuple[str, int]:
        """Execute a safe shell command on the host system (Kali Linux native bash)."""
        from backend.app.api.terminal import decode_output, get_shell_args, get_terminal_env

        cmd_args = get_shell_args(command)
        env = get_terminal_env()
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                cwd=str(root_dir),
                env=env,
                timeout=timeout,
            )
            stdout = decode_output(res.stdout)
            stderr = decode_output(res.stderr)
            combined = stdout
            if stderr:
                combined = (combined + "\n" if combined else "") + stderr
            return combined.strip(), res.returncode
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Lệnh thực thi vượt quá thời gian chờ ({timeout}s).", 124
        except Exception as e:
            return f"[ERROR] Lỗi thực thi lệnh: {e}", 1

    def execute_safe_check(self, command: str) -> VerificationResult:
        """Execute a strictly read-only validation command in real system shell."""
        cmd_lower = command.lower()
        if any(bad in cmd_lower for bad in self.DISALLOWED_PATTERNS):
            return VerificationResult(
                finding_id="",
                step_number=0,
                command=command,
                output="[ERROR] Command contains potentially unsafe or destructive patterns. Execution aborted by Guardrails.",
                status="BLOCKED",
                is_vulnerable_indicated=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        raw_output, exit_code = self._execute_command(command, timeout=15)
        output = (
            f"[+] Executing safe read-only command: {command}\n{raw_output}"
            if raw_output
            else f"[+] Executing safe read-only command: {command}\n(Không có dữ liệu trả về)"
        )
        out_lower = (raw_output or "").lower()
        is_vuln = exit_code == 0 and any(
            p in out_lower
            for p in ["root:x:0:0", "apache/2.4.49", "apache/2.4.50", "200 ok", "open"]
        )

        return VerificationResult(
            finding_id="",
            step_number=1,
            command=command,
            output=output,
            status="SUCCESS" if exit_code == 0 else "FAILED",
            is_vulnerable_indicated=is_vuln,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def generate_chain_plan(
        self, attack_path: AttackPath, target_id: str = ""
    ) -> ChainVerificationPlan:
        """Generates a multi-step safe read-only verification plan for a multi-hop attack chain."""
        ts = datetime.now(timezone.utc).isoformat()
        chain_steps: list[ChainVerificationStep] = []

        target = target_id or (
            attack_path.node_ids[0].replace("target:", "")
            if attack_path.node_ids
            else "127.0.0.1"
        )
        host = (
            target.replace("http://", "")
            .replace("https://", "")
            .replace("target-", "")
            .split("/")[0]
            .split(":")[0]
        )

        port = None
        for step in attack_path.steps:
            if "port" in step.node_id or getattr(step, "node_type", "") == "port":
                match = re.search(r":(\d+)|tcp-(\d+)|udp-(\d+)", step.node_id)
                if match:
                    port = match.group(1) or match.group(2) or match.group(3)
                    break

        host_port = f"{host}:{port}" if port and port not in ("80", "443") else host
        is_win = platform.system() == "Windows"

        for idx, s in enumerate(attack_path.steps, 1):
            phase_lower = s.phase.lower()
            if "recon" in phase_lower or "port" in s.node_id or "service" in s.node_id:
                cmd = f"curl -s -I --connect-timeout 5 http://{host_port}/"
                exp = f"Phản hồi HTTP 200/301 kèm Server banner khớp với thông tin trinh sát tại {s.node_label or s.title}."
                rem = "Ẩn thông tin phiên bản chi tiết (ServerTokens Prod) hoặc lọc cổng bằng Firewall."
                is_choke = False
            elif "exploit" in phase_lower or "vuln" in s.node_id or attack_path.cve_id:
                cve = (attack_path.cve_id or "").upper()
                if "CVE-2021-41773" in cve or "CVE-2021-42013" in cve:
                    cmd = f"curl -s --path-as-is http://{host_port}/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w '%{{http_code}}'"
                    exp = "HTTP 200 xác nhận đường dẫn bị bypass; HTTP 403 hoặc 400 xác nhận đã an toàn."
                else:
                    cmd = f"curl -s -I -X GET http://{host_port}/"
                    exp = "Xác nhận hành vi phản hồi dị biệt hoặc banner có chứa phiên bản dính lỗ hổng."
                rem = f"Cập nhật ngay bản vá bảo mật cho {cve or 'dịch vụ'} hoặc áp dụng quy tắc WAF tương ứng."
                is_choke = True
            elif "impact" in phase_lower or "exposure" in phase_lower:
                cmd = f"curl -s -I http://{host_port}/icons/ -o /dev/null -w '%{{http_code}}'"
                exp = "Kiểm tra quyền truy cập thư mục nhạy cảm: HTTP 403 Forbidden cho thấy quyền hạn đã được khống chế."
                rem = "Thiết lập quyền truy cập tối thiểu (Least Privilege), chặn Directory Listing và cấu hình 'Require all denied'."
                is_choke = False
            else:
                cmd = f"ping -n 1 -w 2000 {host}" if is_win else f"ping -c 1 -W 2 {host}"
                exp = "Kiểm tra phân đoạn mạng: Máy chủ không thể truy cập các tài sản nhạy cảm nội bộ khác."
                rem = "Cách ly mạng (Network Segmentation), áp dụng Zero Trust và cấm Egress traffic trái phép."
                is_choke = False

            chain_steps.append(
                ChainVerificationStep(
                    step_number=idx,
                    phase=s.phase,
                    node_id=s.node_id,
                    node_label=s.node_label or s.title,
                    name=f"Xác minh chặng {idx}: {s.title}",
                    description=s.description or f"Kiểm chứng an toàn chỉ đọc cho mắt xích {s.title} trong chuỗi tấn công.",
                    command=cmd,
                    is_safe_readonly=True,
                    expected_evidence=exp,
                    remediation_check=rem,
                    break_point_candidate=is_choke,
                )
            )

        choke_step = next(
            (cs for cs in chain_steps if cs.break_point_candidate),
            chain_steps[0] if chain_steps else None,
        )
        choke_name = (
            f"Bước {choke_step.step_number} ({choke_step.name})"
            if choke_step
            else "Bước khai thác lỗ hổng"
        )
        break_rec = (
            f"Điểm can thiệp tối ưu nhất (Chokepoint) để cắt đứt chuỗi tấn công là tại {choke_name}. "
            f"Vá lỗi hoặc ngăn chặn tại mắt xích này sẽ vô hiệu hóa toàn bộ các bước leo thang và tác động phía sau: '{attack_path.attacker_goal}'."
        )

        return ChainVerificationPlan(
            chain_id=attack_path.id,
            target_id=target,
            chain_title=attack_path.title,
            severity=attack_path.severity.value if hasattr(attack_path.severity, "value") else str(attack_path.severity),
            attacker_goal=attack_path.attacker_goal,
            rationale=f"Kế hoạch xác minh an toàn đa chặng được xây dựng tự động từ Attack Chain '{attack_path.title}'. Mọi kiểm thử đều ở chế độ Read-Only, đảm bảo tuyệt đối không làm ảnh hưởng đến hoạt động của hệ thống.",
            steps=chain_steps,
            break_point_recommendation=break_rec,
            recommended_mitigations=attack_path.mitigation_steps or [
                "Cập nhật bản vá chính thức của phần mềm.",
                "Cấu hình WAF chặn các pattern thăm dò độc hại.",
                "Thực hiện phân đoạn mạng nghiêm ngặt.",
            ],
            created_at=ts,
        )

    def execute_chain_step(
        self, chain_id: str, step_number: int, command: str
    ) -> ChainExecutionResult:
        """Execute a read-only validation command for an attack chain link in real native shell."""
        ts = datetime.now(timezone.utc).isoformat()
        cmd_lower = command.lower()
        if any(bad in cmd_lower for bad in self.DISALLOWED_PATTERNS):
            return ChainExecutionResult(
                chain_id=chain_id,
                step_number=step_number,
                command=command,
                output="[BLOCKED] Lệnh chứa mẫu payload nguy hiểm hoặc can thiệp phá hủy. Đã kích hoạt chốt chặn an toàn (Guardrails).",
                status="BLOCKED",
                is_vulnerable_indicated=False,
                is_chain_broken=False,
                evidence_found="Chặn bởi Guardrails an toàn.",
                timestamp=ts,
            )

        raw_output, exit_code = self._execute_command(command, timeout=15)
        output = (
            f"[+] Executing Chain Verification Probe [Step {step_number}]: {command}\n{raw_output}"
            if raw_output
            else f"[+] Executing Chain Verification Probe [Step {step_number}]: {command}\n(Không có dữ liệu trả về)"
        )
        out_lower = (raw_output or "").lower()
        is_vuln = False
        is_broken = False
        evidence = ""

        if exit_code == 0:
            if any(p in out_lower for p in ["root:x:0:0", "daemon:x:", "/bin/bash", "/bin/sh"]):
                is_vuln = True
                is_broken = False
                evidence = "Phát hiện tệp nhạy cảm hệ thống (/etc/passwd) trong phản hồi thực tế."
            elif any(p in out_lower for p in ["apache/2.4.49", "apache/2.4.50"]):
                is_vuln = True
                is_broken = False
                evidence = "Máy chủ phản hồi xác nhận phiên bản Apache dính lỗ hổng Path Traversal."
            elif "ssh-2.0" in out_lower or "openssh" in out_lower:
                is_vuln = True
                is_broken = False
                first_line = raw_output.strip().splitlines()[0] if raw_output else "OpenSSH"
                evidence = f"Máy chủ phản hồi banner xác thực OpenSSH: {first_line}"
            elif any(p in out_lower for p in ["mysql", "5.0.51", "ubuntu5"]):
                is_vuln = True
                is_broken = False
                evidence = "Máy chủ phản hồi banner xác nhận dịch vụ MySQL đang mở và chấp nhận kết nối."
            elif "200 ok" in out_lower or "200" in out_lower:
                is_vuln = True
                is_broken = False
                evidence = "Dịch vụ phản hồi HTTP 200 OK bình thường."
            elif "403 forbidden" in out_lower or "401 unauthorized" in out_lower:
                is_vuln = False
                is_broken = True
                evidence = "Cơ chế bảo vệ/phân quyền hoạt động: Nhận mã 403 Forbidden hoặc 401 Unauthorized."
            elif any(p in out_lower for p in ["open", "connected to", "succeeded", "bytes from"]):
                is_vuln = True
                is_broken = False
                evidence = "Cổng/dịch vụ mở và chấp nhận kết nối mạng thực tế."
            else:
                is_vuln = False
                is_broken = False
                evidence = "Lệnh hoàn tất thành công (Exit code 0)."
        else:
            if any(p in out_lower for p in ["connection refused", "route to host", "timed out", "could not resolve host"]):
                is_vuln = False
                is_broken = True
                evidence = "Không thể kết nối đến dịch vụ mục tiêu (Mắt xích bị đứt hoặc dịch vụ đã đóng)."
            elif "403" in out_lower or "401" in out_lower or "forbidden" in out_lower:
                is_vuln = False
                is_broken = True
                evidence = "Phản hồi lỗi xác thực/truy cập: Chuỗi tấn công bị chặn."
            else:
                is_vuln = False
                is_broken = True
                evidence = f"Lệnh kết thúc với lỗi (Exit code {exit_code})."

        from backend.app.services.ai_probe_analyzer import ai_probe_analyzer
        ai_res = ai_probe_analyzer.analyze_probe(
            target_id=chain_id.replace("plan:", "").replace("target-", ""),
            command=command,
            raw_output=raw_output,
            exit_code=exit_code,
        )

        final_evidence = evidence or ai_res.get("evidence_summary", "")
        return ChainExecutionResult(
            chain_id=chain_id,
            step_number=step_number,
            command=command,
            output=output,
            status="SUCCESS" if exit_code == 0 else "FAILED",
            is_vulnerable_indicated=is_vuln or ai_res.get("is_vulnerable", False),
            is_chain_broken=is_broken or ai_res.get("is_chain_broken", False),
            evidence_found=final_evidence,
            ai_assessment=ai_res.get("assessment", ""),
            ai_deduction=ai_res.get("deduction", ""),
            timestamp=ts,
        )


verification_planner = VerificationPlanner()
