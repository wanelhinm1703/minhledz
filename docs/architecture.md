# AI-Pentest Copilot — Kiến Trúc Hệ Thống (Architecture Overview)

> **Tài liệu đặc tả kiến trúc tổng thể, luồng dữ liệu và phân tách trách nhiệm (v5.0)**  
> **Phiên bản:** 5.0 (Dynamic Target & Integrated Pentest Toolset)  
> **Ngôn ngữ:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Kỹ thuật Phần mềm)

---

## 1. Tổng Quan Kiến Trúc

**AI-Pentest Copilot** là nền tảng Security Workbench tích hợp AI Copilot hỗ trợ kiểm thử an ninh (Penetration Testing) định hướng phòng thủ. Hệ thống kết hợp khả năng tiếp nhận mục tiêu động, điều phối đa công cụ trinh sát tiêu chuẩn (Nmap, Masscan, RustScan, HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana, Nuclei, SearchSploit, enum4linux, smbclient, snmpwalk, ldapsearch, DB clients, Burp Suite, OWASP ZAP), cơ sở tri thức lỗ hổng ngoại tuyến có thẩm quyền (539 CVEs / 52 CWEs), hệ thống chốt chặn an toàn (Guardrails) nghiêm ngặt, Copilot Chat RAG theo thời gian thực và tự động tạo báo cáo tuân thủ.

```
+-----------------------------------------------------------------------------------------+
|                                  GIAO DIỆN WEB IDE (FRONTEND)                           |
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  |     Explorer Panel     |  |   Tabbed Editor / Findings    |  |  IDE Chat Copilot   | |
|  | - Target Registry      |  | - Trình đọc Raw XML/JSONL     |  | - WebSocket realtime| |
|  | - Evidence Manifests   |  | - Findings Manager            |  | - Trích dẫn nguồn KB| |
|  | - Cây công cụ & Scan   |  | - Topology & Báo cáo Pentest  |  | - Cảnh báo xung đột | |
|  +------------------------+  +-------------------------------+  +---------------------+ |
|  +------------------------------------------------------------------------------------+ |
|  |                      Interactive Terminal / Nhật Ký Thực Thi                       | |
|  +------------------------------------------------------------------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | WebSocket / REST (/api)
+--------------------------------------------v--------------------------------------------+
|                                NHÂN HỆ THỐNG FASTAPI (BACKEND)                          |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |   Quản Lý Mục Tiêu    |  |  Điều Phối Trinh Sát     |  |  Vulnerability KB & RAG   | |
|  | - TargetParser        |  | - Multi-tool Runner      |  | - SQLite KB (CVE/CWE)     | |
|  | - ScopeValidator      |  | - 22 Công cụ tích hợp    |  | - Semantic Version Tuple  | |
|  | - Dynamic Registry    |  | - Định tuyến theo dịch vụ|  | - Correlator Engine       | |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
|  |  Chốt Chặn An Toàn    |  |  Lỗ Hổng & Xung Đột      |  |  Xác Minh & Báo Cáo       | |
|  | - Anti-Exploitation   |  | - Tự động tổng hợp       |  | - Kế hoạch Safe Read-Only | |
|  | - Anti-Hallucination  |  | - Phát hiện xung đột tool|  | - Thăm dò không phá hoại  | |
|  | - Phân định Fact/Hypo |  | - Liên kết chuỗi bằng chứng- Báo cáo MD, HTML, SARIF| |
|  +-----------------------+  +--------------------------+  +---------------------------+ |
+--------------------------------------------+--------------------------------------------+
                                             | Đọc / Ghi bất biến
+--------------------------------------------v--------------------------------------------+
|                                KHO DỮ LIỆU BẰNG CHỨNG (TOOLKIT)                         |
|  - toolkit/01-targets/      -> Định nghĩa mục tiêu & registry động                       |
|  - toolkit/03-network/      -> Nmap, Masscan, RustScan, Naabu (raw + structured + audit) |
|  - toolkit/04-web/          -> HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana             |
|  - toolkit/05-vulnerability/-> Nuclei, SearchSploit, Nmap Safe NSE                       |
|  - toolkit/06-service-enum/ -> enum4linux, smbclient, snmpwalk, ldapsearch, DB clients   |
|  - toolkit/08-manual/       -> Cấu hình Scope Burp Suite & OWASP ZAP upstream            |
|  - toolkit/09-analysis/     -> Evidence manifests, correlated findings                   |
|  - toolkit/10-reports/      -> Báo cáo đánh giá bảo mật (.md, .html, .sarif)             |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Phân Tách 8 Phân Tầng Hệ Thống (Layer Separation)

Hệ thống được thiết kế theo nguyên lý phân tách trách nhiệm nghiêm ngặt (Separation of Concerns):

1. **`backend/` (Nhân API & Logic nghiệp vụ)**:
   Xây dựng trên nền tảng Python FastAPI, chịu trách nhiệm quản lý ngữ cảnh (Context Engine), dịch vụ kết nối LLM, nạp dữ liệu tri thức (Ingest), công cụ đối soát (Correlator), RAG, lập kế hoạch trinh sát (Recon Planner), danh mục công cụ (Tool Registry), bộ tổng hợp lỗ hổng (Findings Builder) và sinh báo cáo tuân thủ (Report Generator).
2. **`frontend/` (Giao diện Web IDE)**:
   Xây dựng bằng React 18, TypeScript, Tailwind CSS, Monaco Editor, terminal xterm.js, trợ lý IDE Chat Copilot, trình quản lý lỗ hổng Findings Manager, đồ thị Attack Topology và trình xem báo cáo đa định dạng.
3. **`security/` (Bộ quy chuẩn an toàn & Dữ liệu tham chiếu)**:
   Chứa toàn bộ JSON Schemas xác thực cấu trúc đầu ra của công cụ, bộ dữ liệu CVE/CWE, tiêu chí đánh giá benchmark và các kịch bản kiểm thử mẫu.
4. **`toolkit/` (Kho lưu trữ công cụ & Bằng chứng số)**:
   Nơi lưu trữ các script thực thi công cụ trinh sát, chứng cứ thô bất biến (raw outputs), dữ liệu JSON đã chuẩn hóa theo schema và nhật ký kiểm toán dòng lệnh (`commands.md`).
5. **`shared/` (Hợp đồng dữ liệu dùng chung)**:
   Đóng vai trò "Single Source of Truth" quy định schema JSON, kiểu dữ liệu mục tiêu (Target Types) và trạng thái công cụ trao đổi giữa Frontend và Backend.
6. **`docs/` (Tài liệu kỹ thuật hệ thống)**:
   Tập hợp đầy đủ tài liệu kiến trúc, mô hình an toàn, hệ thống target, cẩm nang toolkit, cơ sở tri thức lỗ hổng và kịch bản demo.
7. **`infra/` (Hạ tầng & Triển khai)**:
   Chứa Dockerfile, Docker Compose profiles (chạy dịch vụ mục tiêu mô phỏng vulnerable lab, backend, frontend) và script triển khai môi trường.
8. **`scripts/` (Kịch bản tự động hóa)**:
   Các script tiện ích khởi tạo môi trường, kiểm tra tính toàn vẹn và nạp dữ liệu tự động.

---

## 3. Các Dịch Vụ Cốt Lõi (Core Services)

### 3.1. Danh Mục & Kiểm Tra Khả Dụng Công Cụ (`backend/app/services/tool_registry.py`)
Định nghĩa siêu dữ liệu tập trung cho toàn bộ các công cụ hỗ trợ trên 5 danh mục nghiệp vụ:
- **Network Discovery**: Nmap (chính), Masscan (tốc độ cao), RustScan (hiện đại), Naabu (dự phòng).
- **Web Recon**: HTTPx (thăm dò), WhatWeb (nhận diện công nghệ), Nikto (quét máy chủ web), Gobuster (dò thư mục), FFUF (fuzzing web siêu tốc), Katana (spider/crawler).
- **Vulnerability**: Nuclei (quét template CVE), Nmap Safe NSE, SearchSploit (tra cứu mã khai thác Exploit-DB offline).
- **Service Enum**: enum4linux (thông tin SMB), smbclient (chia sẻ tệp), snmpwalk (giao thức SNMP), ldapsearch (dịch vụ thư mục LDAP), DB clients (MySQL, Postgres, Redis, MongoDB, MSSQL).
- **Manual / Proxy**: Tạo cấu hình phạm vi và định tuyến upstream cho Burp Suite và OWASP ZAP.

Cơ chế kiểm tra nhị phân thời gian thực (`shutil.which` kết hợp kiểm tra quyền thực thi) xác định tình trạng cài đặt trên OS host hoặc container. Nếu thiếu công cụ, hệ thống kích hoạt cơ chế **Graceful Degradation** (`installed: False`, exit code 127) mà không làm sập quy trình trinh sát.

### 3.2. Điều Phối Trinh Sát & Tiếp Nhận Target (`backend/app/services/recon_planner.py`)
- Tự động nhận diện năng lực mục tiêu (`IPV4`, `CIDR`, `URL`, `HOST_PORT`, `DOMAIN`) để chỉ định bộ công cụ phù hợp.
- **Định tuyến theo dịch vụ phát hiện (Service-Driven Routing)**: Khi phát hiện cổng mở tương ứng, hệ thống tự động lên lịch chạy các công cụ chuyên biệt:
  - Cổng 445 / 139 -> `enum4linux`, `smbclient`
  - Cổng 161 -> `snmpwalk`
  - Cổng 389 / 636 -> `ldapsearch`
  - Cổng 3306, 5432, 6379, 27017, 1433 -> Database clients (chế độ chỉ đọc)
  - Cổng dịch vụ web phát hiện phiên bản cụ thể -> `searchsploit`, `whatweb`, `nikto`
- Hỗ trợ chuyên gia tự chọn công cụ theo nhu cầu (`requested_tools`).

### 3.3. Quản Lý Ngữ Cảnh & Phát Hiện Xung Đột Đa Công Cụ (`backend/app/core/context.py`)
- Thu thập bằng chứng thô và dữ liệu có cấu trúc trên toàn bộ các phân mục lưu trữ (`03-network`, `04-web`, `05-vulnerability`, `06-service-enum`, `08-manual`).
- **Phát hiện xung đột (Conflict Detection)**: Tự động so sánh phiên bản và dịch vụ được ghi nhận giữa các công cụ khác nhau (Ví dụ: Nmap báo `Apache 2.4.49` nhưng WhatWeb báo `Apache 2.4.51`).
- Đưa ra cảnh báo ưu tiên cao kèm đề xuất lệnh kiểm chứng thực tế không phá hoại (Safe Verification Probe) cho chuyên gia vận hành.

### 3.4. Kiến Trúc Multi-Agent Chuyên Biệt (Specialist Agents Framework)
Hệ thống tích hợp mô hình phân vai Multi-Agent chuyên sâu tại `backend/app/agents/`:
- **ReconAnalyst**: Chuyên trách tổng hợp dữ liệu trinh sát đa nguồn, đối chiếu kết quả scan và phát hiện xung đột thông tin giữa các công cụ.
- **ThreatIntelAgent**: Tương quan phiên bản dịch vụ với cơ sở dữ liệu tri thức lỗ hổng offline (NVD, CWE, CISA KEV), đánh giá mức độ rủi ro (CVSS) và chiến thuật MITRE ATT&CK.
- **SafeVerificationPlannerAgent**: Xây dựng kịch bản kiểm chứng an toàn (chỉ đọc, không phá hoại, không weaponize) để xác minh độ tin cậy của lỗ hổng.
- **SpecialistAgentOrchestrator**: Điều phối tập trung, tổng hợp ý kiến của các agent chuyên biệt và trả về phản hồi mạch lạc cho người dùng trên giao diện IDE Chat.

---

## 4. Quy Tắc Ràng Buộc Phụ Thuộc (Dependency Rules)

Để đảm bảo tính độc lập và khả năng bảo trì lâu dài, kiến trúc tuân thủ nghiêm ngặt các quy tắc:
1. `toolkit/` **KHÔNG BAO GIỜ** import từ `backend/`.
2. `security/` **KHÔNG BAO GIỜ** import từ `backend/app`.
3. `backend/` đọc và nạp dữ liệu từ `toolkit/` và `security/`.
4. `frontend/` chỉ giao tiếp với Backend thông qua các chuẩn giao thức mở: REST API và WebSocket (`/ws`).
5. `shared/` là nguồn định nghĩa hợp đồng chung duy nhất, không phụ thuộc vào thư viện cụ thể của Backend hay Frontend.

---

## 5. Tài Liệu Liên Quan

- [Mô hình An toàn & Guardrails](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md)
- [Hệ thống Quản lý Target Động](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/target-system.md)
- [Cẩm nang Bộ Công cụ Pentest Toolkit](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md)
- [Cơ sở Tri thức Lỗ hổng & Correlator](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/knowledge-base.md)
- [Kịch bản Demo Chi Tiết](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md)
