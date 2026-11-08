import pytest
from backend.app.services.ai_probe_analyzer import ai_probe_analyzer


def test_probe_analyzer_apache_path_traversal():
    raw_output = "HTTP/1.1 200 OK\nServer: Apache/2.4.49\nroot:x:0:0:root:/root:/bin/bash"
    res = ai_probe_analyzer.analyze_probe(
        target_id="192.168.242.129",
        command="curl -s --path-as-is http://192.168.242.129/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        raw_output=raw_output,
        exit_code=0,
        node_label="Apache 2.4.49 (CVE-2021-41773)",
        cve_id="CVE-2021-41773",
        purpose="Kiểm tra Path Traversal trên Apache 2.4.49",
        expected_result="Trả về nội dung /etc/passwd hoặc mã 200 OK",
    )

    assert "assessment" in res
    assert "deduction" in res
    assert len(res["assessment"]) > 20
    assert len(res["deduction"]) > 20
    assert "Apache 2.4.49" in res["assessment"] or "passwd" in res["assessment"] or "200 OK" in res["assessment"]
    assert "choke point" in res["deduction"].lower() or "tiếp theo" in res["deduction"].lower() or "tấn công" in res["deduction"].lower()


def test_probe_analyzer_connection_refused():
    raw_output = "curl: (7) Failed to connect to 192.168.242.129 port 80: Connection refused"
    res = ai_probe_analyzer.analyze_probe(
        target_id="192.168.242.129",
        command="curl -s http://192.168.242.129",
        raw_output=raw_output,
        exit_code=7,
        node_label="Port 80/tcp",
        purpose="Xác thực mở cổng 80",
        expected_result="Kết nối thành công",
    )

    assert "assessment" in res
    assert "deduction" in res
    assert "chặn" in res["assessment"].lower() or "refused" in res["assessment"].lower() or "đóng" in res["assessment"].lower()
    assert "bẻ gãy" in res["deduction"].lower() or "chain broken" in res["deduction"].lower() or "choke point" in res["deduction"].lower()


def test_probe_analyzer_openssh_banner():
    raw_output = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    res = ai_probe_analyzer.analyze_probe(
        target_id="192.168.242.129",
        command="nc -zv 192.168.242.129 22",
        raw_output=raw_output,
        exit_code=0,
        node_label="OpenSSH 8.9p1",
        cve_id="CVE-2024-6387",
        purpose="Xác thực phiên bản OpenSSH",
        expected_result="Nhận banner SSH-2.0-OpenSSH",
    )

    assert "assessment" in res
    assert "deduction" in res
    assert "openssh" in res["assessment"].lower()
    assert len(res["deduction"]) > 15
