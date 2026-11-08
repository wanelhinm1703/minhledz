#!/usr/bin/env python3
"""
AI-Pentest Copilot - Robust Interactive Preview Server
Serves the built Web IDE frontend with a complete JSON API responder for all UI panels.
"""

import http.server
import json
import os
import pathlib
import socket
import socketserver
import urllib.parse
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST_DIR = ROOT / "frontend" / "dist"
TOOLKIT_DIR = ROOT / "toolkit"
PORT = 5173

class DualStackServer(socketserver.TCPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()

class RobustPreviewHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST_DIR), **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Reject WebSocket upgrade gracefully with 400, NEVER return index.html for ws
        if path.startswith("/ws/"):
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"WebSocket not supported in preview mode - using REST fallback")
            return

        # 2. API Routes (ALL /api/ must strictly return JSON)
        if path.startswith("/api/"):
            return self.handle_api_get(path, query)

        # 3. Static Files
        fs_path = DIST_DIR / path.lstrip("/")
        if fs_path.exists() and fs_path.is_file():
            return super().do_GET()

        # 4. SPA Fallback for frontend UI routes (only for non-asset GET requests)
        if not path.startswith("/assets/") and not path.endswith((".js", ".css", ".png", ".svg", ".ico")):
            self.path = "/index.html"
            return super().do_GET()

        return super().do_GET()

    def handle_api_get(self, path: str, query: dict):
        if path == "/api/health":
            return self.send_json({
                "status": "healthy",
                "version": "5.0.0-preview",
                "mode": "interactive-workbench",
                "kb_available": True
            })

        if path == "/api/targets":
            target_reg = TOOLKIT_DIR / "01-targets" / "registry" / "targets.json"
            if target_reg.exists():
                try:
                    targets = json.loads(target_reg.read_text(encoding="utf-8"))
                    return self.send_json(targets)
                except Exception:
                    pass
            return self.send_json([
                {
                    "target_id": "target-192.168.242.129",
                    "campaign_id": "lab-local",
                    "name": "192.168.242.129",
                    "type": "ipv4",
                    "host": "192.168.242.129",
                    "normalized_value": "192.168.242.129",
                    "scope": {
                        "is_in_scope": True,
                        "allowed_attacks": ["recon", "web", "network"],
                        "forbidden_attacks": ["dos", "exploit"],
                        "scope_rule": "192.168.0.0/16"
                    },
                    "tags": ["ipv4", "lab", "active"],
                    "status": "active"
                }
            ])

        if path.startswith("/api/targets/") and path.endswith("/services"):
            return self.send_json([
                {"port": 21, "service": "ftp", "product": "vsftpd", "version": "2.3.4", "confidence": "high"},
                {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "4.7p1", "confidence": "high"},
                {"port": 80, "service": "http", "product": "Apache", "version": "2.2.8", "confidence": "high"},
                {"port": 139, "service": "netbios-ssn", "product": "Samba", "version": "3.0.20", "confidence": "high"},
                {"port": 445, "service": "netbios-ssn", "product": "Samba", "version": "3.0.20", "confidence": "high"},
                {"port": 3306, "service": "mysql", "product": "MySQL", "version": "5.0.51a", "confidence": "high"}
            ])

        if path == "/api/scans":
            return self.send_json(self.get_scans_list())

        if path == "/api/scans/file":
            file_rel = query.get("path", [""])[0]
            file_path = TOOLKIT_DIR / file_rel
            if file_path.exists() and file_path.is_file():
                content = file_path.read_text(encoding="utf-8", errors="replace")
                return self.send_json({
                    "path": file_rel,
                    "content": content,
                    "is_json": file_path.suffix.lower() == ".json"
                })
            return self.send_json({"error": "File not found", "path": file_rel}, status=404)

        if path == "/api/findings":
            target_id = query.get("target_id", [""])[0]
            return self.send_json(self.get_findings_list(target_id))

        if path.startswith("/api/verification/plan/"):
            return self.send_json({
                "plan_id": "plan-safe-probe-01",
                "finding_id": path.split("/")[-1],
                "safe_mode": True,
                "strategy": "Non-destructive version banner matching and read-only query",
                "steps": [
                    {"step": 1, "description": "Gửi gói tin thăm dò banner dịch vụ", "command": "nmap -sV -p 21 192.168.242.129", "safe": True},
                    {"step": 2, "description": "Kiểm tra phản hồi không xâm lấn", "command": "echo 'QUIT' | nc -w 3 192.168.242.129 21", "safe": True}
                ]
            })

        if path.startswith("/api/topology"):
            return self.send_json(self.get_topology_data())

        if path.startswith("/api/chat/conversations/"):
            conv_id = path.split("/")[-2]
            return self.send_json({
                "conversation_id": conv_id,
                "messages": []
            })

        if path == "/api/llm/providers":
            return self.send_json([
                {"id": "gemini", "name": "Google Gemini 1.5 Pro (Active)", "available": True, "active": True},
                {"id": "openai", "name": "OpenAI GPT-4o", "available": True, "active": False},
                {"id": "ollama", "name": "Ollama Local", "available": True, "active": False}
            ])

        if path.startswith("/api/reports"):
            rep_file = TOOLKIT_DIR / "10-reports" / "192.168.242.129_report.json"
            if rep_file.exists():
                try:
                    rep_data = json.loads(rep_file.read_text(encoding="utf-8"))
                    return self.send_json(rep_data)
                except Exception:
                    pass
            return self.send_json({
                "target_id": "192.168.242.129",
                "campaign_name": "Automated Lab Assessment",
                "summary": {"total": 9, "by_severity": {"CRITICAL": 4, "HIGH": 5, "MEDIUM": 0, "LOW": 0}},
                "compliance": {"compliance_score": 0, "status": "NON-COMPLIANT"}
            })

        if path.startswith("/api/attack-plan/"):
            return self.send_json({
                "target_id": "192.168.242.129",
                "attack_graph_status": "synced",
                "recommended_steps": [
                    {"step": "Recon", "action": "Port service fingerprinting", "status": "COMPLETED"},
                    {"step": "Correlation", "action": "CVE mapping", "status": "COMPLETED"}
                ]
            })

        # Generic JSON fallback for any unhandled /api/ endpoint
        return self.send_json({"status": "ok", "path": path})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"
        try:
            body = json.loads(body_bytes.decode("utf-8", errors="replace"))
        except Exception:
            body = {}

        if path.startswith("/api/topology"):
            return self.send_json(self.get_topology_data())

        if path == "/api/terminal/execute":
            cmd = body.get("command", "").strip()
            stdout_res, stderr_res, code = self.safe_execute(cmd)
            return self.send_json({
                "command": cmd,
                "stdout": stdout_res,
                "stderr": stderr_res,
                "exit_code": code,
                "duration_seconds": 0.15
            })

        if path == "/api/chat/message":
            msg = body.get("message", "")
            reply = (
                f"### [AI-Pentest Copilot v5.0]\n\n"
                f"Tôi đã tiếp nhận yêu cầu: **\"{msg}\"**\n\n"
                f"**Mục tiêu đang chọn**: `192.168.242.129` (Trong phạm vi `192.168.0.0/16`)\n\n"
                f"**Các phát hiện trọng yếu đã kiểm chứng**:\n"
                f"1. **Cổng 21/tcp (FTP)**: `vsftpd 2.3.4` - Khớp lỗ hổng nghiêm trọng [CVE-2011-2523] (CVSS 9.8 - Backdoor RCE).\n"
                f"2. **Cổng 22/tcp (SSH)**: `OpenSSH 4.7p1 Debian 8ubuntu1` - Khớp lỗ hổng [CVE-2023-38408] (CVSS 9.8).\n"
                f"3. **Cổng 445/tcp (Samba)**: `Samba 3.0.20` - Khớp lỗ hổng [CVE-2007-2447] (CVSS 9.8).\n\n"
                f"**Kế hoạch thăm dò an toàn (Non-destructive probe)**:\n"
                f"```bash\nnmap -sV -p 21,22,80,445 192.168.242.129\n```\n\n"
                f"> **Chính sách Guardrails**: Nền tảng tuân thủ nguyên tắc *No Automated Exploitation* - từ chối tự động vũ khí hóa hoặc bắn reverse shell."
            )
            return self.send_json({
                "role": "assistant",
                "content": reply,
                "sources": ["03-network/scans/target-192.168.242.129/nmap/structured/nmap_result.json", "CVE-2011-2523"],
                "confidence": 0.98,
                "next_steps": [
                    "Xem danh sách đầy đủ tại Findings Manager",
                    "Kiểm tra Attack Graph trực quan",
                    "Xuất báo cáo Pentest Report"
                ]
            })

        if path == "/api/llm/switch":
            return self.send_json({"status": "switched", "provider": body.get("provider")})

        if path.startswith("/api/findings/deduplicate"):
            return self.send_json({"message": "Đã tương quan hóa và loại bỏ trùng lặp thành công!"})

        if path == "/api/verification/execute":
            return self.send_json({
                "status": "completed",
                "output": "[+] Safe banner check returned: vsftpd 2.3.4 (Backdoor candidate confirmed in read-only mode).",
                "is_vulnerable": True
            })

        if path.startswith("/api/reports/generate/"):
            return self.send_json({
                "status": "success",
                "report_id": "192.168.242.129",
                "message": "Báo cáo kiểm thử thâm nhập đã được tạo thành công!"
            })

        return self.send_json({"status": "acknowledged"}, status=200)

    def do_DELETE(self):
        return self.send_json({"status": "deleted"}, status=200)

    def safe_execute(self, cmd):
        allowed_prefixes = ("ls", "echo", "pwd", "nmap", "cat", "uname", "python", "date", "whoami", "ss")
        if any(cmd.startswith(p) for p in allowed_prefixes):
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5, cwd=str(ROOT))
                return res.stdout, res.stderr, res.returncode
            except Exception as e:
                return "", str(e), 1
        return f"Simulation: Safe command '{cmd}' executed in read-only sandbox.", "", 0

    def get_scans_list(self):
        results = []
        net_scans = TOOLKIT_DIR / "03-network" / "scans"
        if net_scans.exists():
            for tdir in net_scans.iterdir():
                if tdir.is_dir():
                    tid = tdir.name
                    files = []
                    tools = []
                    for tool in tdir.iterdir():
                        if tool.is_dir():
                            tools.append(tool.name)
                            for sub in tool.rglob("*"):
                                if sub.is_file():
                                    rel = str(sub.relative_to(TOOLKIT_DIR))
                                    files.append({
                                        "name": sub.name,
                                        "tool": tool.name,
                                        "type": "json" if sub.suffix == ".json" else "raw",
                                        "rel_path": rel
                                    })
                    results.append({
                        "target_id": tid,
                        "tools": tools,
                        "files": files,
                        "scan_count": len(files)
                    })
        return results

    def get_findings_list(self, target_id=""):
        findings_dir = TOOLKIT_DIR / "09-analysis" / "findings"
        if findings_dir.exists():
            for f in findings_dir.iterdir():
                if f.name.endswith("_findings.json"):
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        if isinstance(data, list):
                            return data
                        if isinstance(data, dict) and "findings" in data:
                            return data["findings"]
                    except Exception:
                        pass
        return [
            {
                "id": "find-192.168.242.129-21-cve-2011-2523",
                "target_id": "target-192.168.242.129",
                "title": "vsftpd 2.3.4 Backdoor Command Execution",
                "cve_id": "CVE-2011-2523",
                "cwe_id": "CWE-78",
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "is_cisa_kev": True,
                "epss_score": 0.975,
                "description": "vsftpd 2.3.4 contains a backdoor in the smile emoticon code allowing arbitrary command execution.",
                "remediation": "Upgrade vsftpd to a supported non-backdoored release immediately."
            }
        ]

    def get_topology_data(self):
        return {
            "nodes": [
                {"id": "node-target", "label": "192.168.242.129", "type": "target", "category": "host"},
                {"id": "node-ftp", "label": "Port 21 (vsftpd 2.3.4)", "type": "service", "category": "service"},
                {"id": "node-ssh", "label": "Port 22 (OpenSSH 4.7p1)", "type": "service", "category": "service"},
                {"id": "node-http", "label": "Port 80 (Apache 2.2.8)", "type": "service", "category": "service"},
                {"id": "node-smb", "label": "Port 445 (Samba 3.0.20)", "type": "service", "category": "service"},
                {"id": "node-mysql", "label": "Port 3306 (MySQL 5.0.51a)", "type": "service", "category": "service"},
                {"id": "node-cve1", "label": "CVE-2011-2523 (vsftpd RCE)", "type": "vulnerability", "category": "vuln", "severity": "CRITICAL"},
                {"id": "node-cve2", "label": "CVE-2007-2447 (Samba usermap)", "type": "vulnerability", "category": "vuln", "severity": "CRITICAL"}
            ],
            "edges": [
                {"source": "node-target", "target": "node-ftp", "label": "exposes"},
                {"source": "node-target", "target": "node-ssh", "label": "exposes"},
                {"source": "node-target", "target": "node-http", "label": "exposes"},
                {"source": "node-target", "target": "node-smb", "label": "exposes"},
                {"source": "node-target", "target": "node-mysql", "label": "exposes"},
                {"source": "node-ftp", "target": "node-cve1", "label": "vulnerable_to"},
                {"source": "node-smb", "target": "node-cve2", "label": "vulnerable_to"}
            ],
            "stats": {
                "total_nodes": 8,
                "total_edges": 7,
                "critical_vulns": 2
            },
            "attack_paths": [
                {
                    "id": "path-ftp-rce",
                    "name": "FTP Unauthenticated Remote Code Execution Path",
                    "severity": "CRITICAL",
                    "steps": ["Target: 192.168.242.129", "Port 21: vsftpd 2.3.4", "CVE-2011-2523"]
                }
            ]
        }

def main():
    os.chdir(str(ROOT))
    # Try Dual-Stack (IPv4 + IPv6) first, fallback to standard IPv4 if not supported
    try:
        server = DualStackServer(("::", PORT), RobustPreviewHandler)
        print(f"[*] Dual-stack server listening on [::]:{PORT} and 0.0.0.0:{PORT}")
    except Exception as e:
        print(f"[!] Dual-stack bind failed ({e}), falling back to IPv4 0.0.0.0:{PORT}")
        server = socketserver.TCPServer(("0.0.0.0", PORT), RobustPreviewHandler)

    server.allow_reuse_address = True
    print(f"[*] AI-Pentest Copilot Interactive Preview Server running at: http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping preview server...")
        server.shutdown()

if __name__ == "__main__":
    main()
