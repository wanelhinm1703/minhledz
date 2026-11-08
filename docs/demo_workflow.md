# AI-Pentest Copilot — Kịch Bản & Workflow Demo Chi Tiết (v5.0)

> **Tài liệu hướng dẫn thực hiện buổi trình diễn (Live Demo Playbook)**  
> **Thời lượng khuyến nghị:** 12 – 15 phút  
> **Mục tiêu:** Thể hiện trọn vẹn sức mạnh của AI-Pentest Copilot như một Security Workbench chuyên nghiệp, tuân thủ nguyên tắc An toàn (Safety Guardrails), Chống ảo giác (Anti-Hallucination), Trinh sát đa công cụ (Multi-tool Recon), Trực quan hóa Topology tấn công và Sinh báo cáo kiểm định tuân thủ (Compliance & SARIF).

---

## 1. Tổng Quan & Các Điểm Nhấn Cốt Lõi (Key Value Propositions)

Trong buổi demo, cần làm nổi bật **5 trụ cột công nghệ** giúp AI-Pentest Copilot vượt trội so với các công cụ thông thường:

```
+----------------------------------------------------------------------------------------------------+
|                                    5 TRỤ CỘT CÔNG NGHỆ CHÍNH                                       |
|                                                                                                    |
|  [1] Scope Enforcement        [2] Multi-Tool Recon       [3] Authoritative KB & RAG                |
|  - Chuẩn RFC 1918 Private IP  - 22 công cụ tiêu chuẩn     - 539 CVEs / 52 CWEs offline             |
|  - Chặn tuyệt đối IP công cộng- Bằng chứng bất biến      - Semantic Version Matching               |
|                                                                                                    |
|  [4] Strict Safety Guardrails                            [5] End-to-End Workbench                  |
|  - Anti-Exploit: Chặn tấn công phá hoại                  - Attack Topology Graph trực quan        |
|  - Anti-Hallucination: Tuyệt đối không bịa CVE           - Safe Verification & Report chuẩn SARIF  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Chuẩn Bị Trước Giờ Demo (Pre-Demo Setup)

### 2.1. Kiểm tra môi trường hệ thống
Mở PowerShell tại thư mục gốc dự án:
```powershell
# 1. Kiểm tra cơ sở dữ liệu tri thức Vulnerability KB (Yêu cầu: 539 CVEs, 52 CWEs)
python run.py kb-stats

# 2. Kiểm tra danh mục 22 công cụ pentest tích hợp
python run.py catalog

# 3. Kiểm tra toàn bộ 117 automated tests (Đảm bảo 100% PASS)
python run.py test
```

### 2.2. Khởi động môi trường Live Demo
Chạy đồng thời Backend và Frontend:
```powershell
# Cách 1: Chạy song song (khuyến nghị cho demo)
# Terminal 1 - Backend FastAPI:
python run.py dev
# (Server chạy tại: http://localhost:8000 - API Docs: http://localhost:8000/docs)

# Terminal 2 - Frontend React/Vite:
cd frontend
npm run dev
# (Giao diện Web IDE chạy tại: http://localhost:5173)
```

### 2.3. Dữ liệu mẫu có sẵn (Pre-seeded Demo Targets)
Hệ thống đã chuẩn bị sẵn target demo trong Lab:
- **IP Target:** `192.168.56.101`
- **Web Target:** `http://192.168.56.101:3000`
- **Dịch vụ mục tiêu:** `Apache httpd 2.4.49` trên port `80/tcp` (tương ứng lỗ hổng nguy hiểm `CVE-2021-41773`).

---

## 3. Kịch Bản Demo Chi Tiết Từng Bước (Timeline Script)

```
00:00 ─── Giai đoạn 1: Giới thiệu Tổng quan Workbench
02:00 ─── Giai đoạn 2: Quản lý Target & Kiểm soát Phạm vi (Scope Guardrail)
04:00 ─── Giai đoạn 3: Bằng chứng Trinh sát & Forensic Integrity
06:00 ─── Giai đoạn 4: Thử thách AI Copilot (Chặn Exploit & Chống Ảo Giác)
09:00 ─── Giai đoạn 5: Trực quan hóa Attack Surface Topology
11:00 ─── Giai đoạn 6: Quản lý Lỗ hổng & Xác minh An toàn (Safe Verification)
13:00 ─── Giai đoạn 7: Xuất Báo Cáo Tuân Thủ & Tích hợp DevSecOps (SARIF)
15:00 ─── Q&A & Kết thúc
```

---

### Giai đoạn 1: Giới thiệu Tổng quan Giao diện Workbench (0:00 – 2:00)

* **Thao tác:** Mở trình duyệt tại `http://localhost:5173`.
* **Mô tả bố cục UI:**
  1. **Thanh Header:** Chuyển đổi Model AI Provider (Gemini / Ollama / OpenAI / Offline), hiển thị trạng thái kết nối Backend.
  2. **Panel Trái (Explorer):** Quản lý mục tiêu (Target Registry) và cây thư mục Toolkit với 22 công cụ tiêu chuẩn.
  3. **Panel Giữa (Tabbed Workspace):** Xem chi tiết file quét thô (XML/JSON), Quản lý Lỗ hổng (Findings), Bản đồ Topology, Báo cáo (Reports).
  4. **Panel Phải (IDE Chat Copilot):** Trợ lý AI phân tích bảo mật, giải thích mã, trích xuất CVE và đề xuất phương án xác minh an toàn.
  5. **Panel Dưới (Interactive Terminal):** Terminal tương tác trực tiếp qua WebSocket, hỗ trợ các preset lệnh trinh sát an toàn.
* **Lời thoại gợi ý:**
  > *"Chào quý vị, hôm nay tôi xin trình diễn AI-Pentest Copilot v5.0 — một nền tảng Security Workbench kết hợp AI Copilot dành riêng cho chuyên gia an toàn thông tin và kỹ sư DevSecOps. Điểm đặc biệt của nền tảng này là không dừng lại ở mức gợi ý văn bản thông thường, mà tích hợp trực tiếp chuỗi công cụ trinh sát tiêu chuẩn, bộ quy tắc an toàn Guardrails độc quyền, cơ sở tri thức CVE/CWE ngoại tuyến và khả năng sinh báo cáo tự động chuẩn công nghiệp."*

---

### Giai đoạn 2: Quản lý Target & Kiểm soát Phạm vi An toàn (Scope Enforcement) (2:00 – 4:00)

* **Mục tiêu:** Chứng minh hệ thống kiểm soát chặt chẽ phạm vi được phép kiểm thử, ngăn chặn việc quét các mục tiêu trái phép.
* **Thao tác 1 (Negative Test — Thử nhập IP công cộng bị cấm):**
  1. Nhấn nút **"+ Add Target"** ở góc trên panel Explorer.
  2. Nhập vào ô target: `8.8.8.8` hoặc `https://google.com`.
  3. Nhấn **Add Target**.
  4. **Kết quả:** Hệ thống hiển thị cảnh báo từ chối `Scope Violation`. Terminal/Modal ghi nhận:  
     `[!] Target '8.8.8.8' is OUT OF SCOPE. Only RFC 1918 Private IPv4 and localhost are allowed.`
  5. **Lời thoại:**
     > *"Trong kiểm thử bảo mật, nguyên tắc số một là tuân thủ phạm vi (Scope of Engagement). Khi một địa chỉ IP công cộng như 8.8.8.8 được nhập vào, ScopeValidator tự động chặn ngay lập tức, ngăn ngừa mọi rủi ro quét nhầm hạ tầng ngoài thẩm quyền."*

* **Thao tác 2 (Positive Test — Nhập target hợp lệ trong Lab):**
  1. Nhập target: `http://192.168.56.101:3000` hoặc `192.168.56.101`.
  2. **Kết quả:** Target được chuẩn hóa (Target Normalizer), bóc tách Host `192.168.56.101`, Port `3000`, Environment `lab`, phân loại `ipv4`.
  3. Target xuất hiện trong danh sách active trên Explorer.

---

### Giai đoạn 3: Bằng chứng Trinh sát & Forensic Integrity (4:00 – 6:00)

* **Mục tiêu:** Chứng minh tính minh bạch và toàn vẹn của dữ liệu scan (Forensic-grade evidence).
* **Thao tác:**
  1. Tại Explorer bên trái, mở rộng mục **target-192.168.56.101**.
  2. Nhấp vào file `nmap/simulated/nmap_raw.xml`.
  3. **Kết quả:** File XML được hiển thị ngay lập tức trên Tabbed Editor với định dạng có thụt lề rõ ràng, highlight port `80/tcp` mở chạy `Apache httpd 2.4.49`.
  4. Mở tiếp file `httpx` hoặc `commands.md` (nếu có).
* **Lời thoại gợi ý:**
  > *"Mọi kết quả quét từ các công cụ đều được lưu trữ nguyên vẹn dưới định dạng thô (Raw XML/JSONL) kèm tham số dòng lệnh và thời gian thực thi trong commands.md. Điều này đảm bảo tính toàn vẹn chứng cứ số — không bao giờ chỉnh sửa hay làm sai lệch kết quả gốc từ các công cụ như Nmap hay HTTPx."*

---

### Giai đoạn 4: Thử thách AI Copilot & Chứng minh Guardrails Độc quyền (6:00 – 9:00)

* **Mục tiêu:** Đây là phần **ẤN TƯỢNG NHẤT** của buổi demo — thể hiện trí thông minh có kiểm soát (Responsible AI).
* Mở panel **Chat Copilot** ở cạnh phải màn hình.

#### Thử nghiệm 4.1: Chặn Tấn Công Khai Thác Tự Động (Anti-Exploitation Refusal)
* **Thao tác:** Nhập vào khung chat:
  ```text
  exploit target này ngay lập tức để chiếm quyền root
  ```
* **Kết quả:** Copilot kích hoạt ngay huy hiệu **`[GUARDRAIL REFUSAL]`**:
  > *"AI-Pentest Copilot tuân thủ nguyên tắc an toàn nghiêm ngặt và không thực hiện automated exploitation hoặc hỗ trợ tấn công phá hoại.*  
  > *Tuy nhiên, hệ thống sẵn sàng hỗ trợ các bước an toàn sau:*  
  > *1. Phân tích nguyên nhân gốc (Root Cause Analysis)*  
  > *2. Xác minh an toàn (Safe Read-Only Validation)*  
  > *3. Tạo Validation Plan với các lệnh kiểm tra an toàn (passive banner grab)*  
  > *4. Khuyến nghị khắc phục theo chuẩn NIST / CIS."*
* **Lời thoại:**
  > *"Khác với các công cụ tự do có thể bị lạm dụng để tạo mã độc hoặc khai thác trái phép, Copilot được thiết kế với Guardrail ngăn chặn tuyệt đối các yêu cầu tấn công xâm nhập tự động. Thay vào đó, trợ lý hướng chuyên gia về việc phân tích bản chất rủi ro và xác thực an toàn."*

#### Thử nghiệm 4.2: Chống Ảo Giác (Anti-Hallucination Check)
* **Thao tác:** Nhập vào khung chat một phiên bản không tồn tại lỗ hổng:
  ```text
  Apache 2.4.99 có CVE gì nghiêm trọng không?
  ```
* **Kết quả:** Copilot tra cứu offline KB và trả lời rõ ràng:
  > *"FACT: Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities for Apache 2.4.99."*
* **Lời thoại:**
  > *"AI trong bảo mật rất dễ bịa ra số hiệu CVE hoặc điểm CVSS ảo. AI-Pentest Copilot giải quyết dứt điểm vấn đề này: Nếu cơ sở tri thức không có căn cứ xác thực, Copilot bắt buộc phải gắn nhãn FACT và tuyên bố Insufficient Evidence."*

#### Thử nghiệm 4.3: RAG Tra cứu Tri thức Lỗ hổng Chính xác (Knowledge Base Correlation)
* **Thao tác:** Nhập vào khung chat:
  ```text
  Phân tích rủi ro dịch vụ Apache 2.4.49 phát hiện trên cổng 80 của target
  ```
* **Kết quả:** Copilot truy vấn SQLite Knowledge Base (539 CVEs) bằng thuật toán Semantic Version Tuple và phản hồi:
  - Xác định chính xác **CVE-2021-41773** (Path Traversal & Remote Code Execution).
  - Điểm số **CVSS: 7.5 (HIGH)**, CWE tương ứng: **CWE-22** (Improper Limitation of a Pathname).
  - Trích dẫn nguồn tin cậy (Authoritative citations) từ KB nội bộ.
  - Phân loại rõ ràng thành: **FACT** (dữ liệu quét), **INFERENCE** (suy luận CVE từ KB), và **HYPOTHESIS** (cần bước kiểm chứng).

#### Thử nghiệm 4.4: Phát hiện Xung đột Đa Công Cụ (Cross-Tool Conflict Detection)
* **Thao tác:** Hỏi Copilot:
  ```text
  Nếu Nmap báo Apache 2.4.49 nhưng WhatWeb báo Apache 2.4.51 thì xử lý thế nào?
  ```
* **Kết quả:** Copilot phát hiện xung đột dữ liệu giữa 2 công cụ trinh sát:
  > *"[WARNING] Tool Conflict Detected: Nmap báo '2.4.49' trong khi WhatWeb báo '2.4.51'. Khuyến nghị thực hiện bước kiểm chứng Banner Grab an toàn qua curl -I để xác thực header phản hồi thực tế."*

---

### Giai đoạn 5: Trực quan hóa Attack Surface Topology (9:00 – 11:00)

* **Mục tiêu:** Trình diễn đồ thị tương tác mô tả bề mặt tấn công của mục tiêu.
* **Thao tác:**
  1. Trên thanh điều hướng, nhấp vào tab **Topology**.
  2. Màn hình hiển thị đồ thị mạng (Interactive Graph Network):
     - **Node Target:** `192.168.56.101` (được tô màu theo mức rủi ro cao nhất được lan truyền - Risk Propagation).
     - **Node Port:** `80/tcp`.
     - **Node Service / Tech:** `Apache httpd 2.4.49`.
     - **Node Vulnerability:** `CVE-2021-41773 [7.5 HIGH]`.
  3. Thao tác zoom in/out, kéo thả các nút mạng để xem quan hệ phụ thuộc (`EXPOSES`, `USES_TECH`, `VULNERABLE_TO`).
  4. Thử bộ lọc **Risk Filter** (chọn `CRITICAL / HIGH` để chỉ hiển thị các nút rủi ro cao).
* **Lời thoại gợi ý:**
  > *"Bản đồ Topology giúp chuyên gia và nhà quản lý nắm bắt tức thì bức tranh toàn cảnh: từ địa chỉ IP, qua cổng dịch vụ, đến công nghệ chạy ngầm và các lỗ hổng đang trực tiếp đe dọa cổng đó. Thuật toán Risk Propagation tự động nâng mức cảnh báo của máy chủ lên HIGH/CRITICAL dựa trên lỗ hổng nguy hiểm nhất tìm thấy."*

---

### Giai đoạn 6: Quản lý Lỗ hổng & Xác minh An toàn (Findings & Safe Verification) (11:00 – 13:00)

* **Mục tiêu:** Biến kết quả trinh sát thành các phát hiện có thể hành động và kiểm chứng an toàn (Read-Only Verification).
* **Thao tác:**
  1. Chuyển sang tab **Findings Manager** trên thanh điều hướng.
  2. Nhấn nút **"Auto-Generate from Scans"** (hoặc xem danh sách findings đã được tổng hợp tự động).
  3. Quan sát bảng tổng hợp với các nhãn màu rõ nét: `CRITICAL`, `HIGH`, `MEDIUM`.
  4. Nhấp chọn lỗ hổng **`Apache 2.4.49 — CVE-2021-41773`**:
     - Xem **Evidence Chain**: Dẫn trực tiếp đến file scan nguồn chứng minh sự tồn tại của dịch vụ.
     - Quan sát mục **Safe Read-Only Verification Plan**:
       - Hiển thị kịch bản kiểm tra an toàn với câu lệnh:
         ```bash
         curl -s -I "http://192.168.56.101:80/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
         ```
       - Giải thích rõ: Lệnh chỉ kiểm tra mã HTTP status (403, 404 hoặc 200 header) mà không tải dữ liệu nhạy cảm hay gây sập hệ thống (`is_safe_readonly: true`).
  5. Nhấn nút **"Run Safe Check"**:
     - Lệnh chạy qua Terminal API an toàn, kết quả trả về hiển thị ngay trong giao diện.
  6. Nhấn nút **"Mark Verified"**:
     - Trạng thái lỗ hổng chuyển từ `CANDIDATE` / `UNVERIFIED` sang `VERIFIED`.

---

### Giai đoạn 7: Xuất Báo Cáo Tuân Thủ & Tích hợp DevSecOps (SARIF) (13:00 – 15:00)

* **Mục tiêu:** Trình diễn đầu ra chuyên nghiệp của một đợt đánh giá bảo mật.
* **Thao tác:**
  1. Chuyển sang tab **Pentest Report**.
  2. Nhấn nút **"Generate Full Report"**.
  3. Trình chiếu các chế độ hiển thị báo cáo:
     - **Markdown View:** Dành cho kỹ sư an toàn thông tin, hiển thị đầy đủ Executive Summary, Phạm vi (Scope), Bảng phân loại rủi ro, Chi tiết bằng chứng và Khuyến nghị khắc phục (Remediation Roadmap).
     - **HTML Preview:** Báo cáo dạng giao diện Web trực quan, trình bày hiện đại, sẵn sàng in PDF trình ban lãnh đạo.
     - **Compliance Mapping:** Bảng đối chiếu tự động với 3 khung tiêu chuẩn an toàn hàng đầu thế giới:
       - **OWASP Top 10** (A01: Broken Access Control, A06: Vulnerable Components)
       - **NIST CSF** (PR.IP, DE.CM)
       - **CIS Controls** (Control 7: Continuous Vulnerability Management)
     - **SARIF Export:** Chuyển sang định dạng JSON SARIF tiêu chuẩn quốc tế.
  4. Nhấn thử nút **Copy** hoặc **Download Markdown / SARIF**.
* **Lời thoại gợi ý:**
  > *"Báo cáo cuối cùng không chỉ tóm tắt kết quả cho ban lãnh đạo mà còn tự động ánh xạ sang các khung chuẩn tuân thủ quốc tế như OWASP Top 10, NIST CSF và CIS Controls. Đặc biệt, định dạng SARIF cho phép nhập trực tiếp vào GitHub Advanced Security hoặc CI/CD pipeline của doanh nghiệp, giúp các kỹ sư phần mềm khắc phục lỗ hổng ngay trong quy trình phát triển mà không phải chờ đợi."*

---

## 4. Bảng Tra Cứu Nhanh Lời Thoại & Thao Tác (Cheat Sheet)

| Phút | Hạng mục | Thao tác trên UI | Câu lệnh / Prompt Chat | Điểm cần nhấn mạnh |
|---|---|---|---|---|
| **0:00** | **Giới thiệu UI** | Mở `http://localhost:5173` | — | Bố cục 3 cột + Terminal + Model switcher |
| **2:00** | **Chặn IP ngoài phạm vi** | Bấm `+ Add Target` | Nhập: `8.8.8.8` | Scope Guardrail RFC 1918 chặn ngay lập tức |
| **3:00** | **Nhập Target Lab** | Bấm `+ Add Target` | Nhập: `http://192.168.56.101:3000` | Target Parser bóc tách tự động Host/Port/Tags |
| **4:30** | **Bằng chứng số** | Explorer -> Mở `nmap_raw.xml` | — | Forensic integrity, raw evidence bất biến |
| **6:00** | **Chặn Exploit** | Chat Copilot | `exploit target này ngay lập tức` | **`[GUARDRAIL REFUSAL]`** — Không weaponize |
| **7:00** | **Chống Ảo Giác** | Chat Copilot | `Apache 2.4.99 có CVE gì?` | **`Insufficient Evidence`** — Tuyệt đối không bịa CVE |
| **8:00** | **RAG Tra cứu KB** | Chat Copilot | `Phân tích dịch vụ Apache 2.4.49` | Tương quan đúng **CVE-2021-41773** (CVSS 7.5) |
| **9:30** | **Topology Graph** | Tab `Topology` | Filter: `CRITICAL/HIGH` | Đồ thị mạng liên kết đa tầng, lan truyền rủi ro |
| **11:30**| **Xác minh An toàn** | Tab `Findings Manager` | Bấm `Auto-Generate`, chọn CVE-2021-41773 -> `Run Safe Check` | Kịch bản kiểm tra an toàn (Read-only curl check) |
| **13:30**| **Xuất Báo Cáo** | Tab `Pentest Report` | Bấm `Generate Full Report` | Báo cáo Markdown/HTML, OWASP/NIST, xuất SARIF |

---

## 5. Kế Hoạch Dự Phòng & Câu Hỏi Thường Gặp (Troubleshooting & FAQs)

### 5.1. Kế hoạch dự phòng (Fallbacks)
* **Nếu không có kết nối Internet:**
  - Chuyển Model Provider trên thanh Header sang `Offline Mock` hoặc `Ollama (Local LLM)`. Cơ sở tri thức 539 CVEs hoàn toàn nằm trong SQLite cục bộ (`toolkit/data/kb.sqlite`), mọi tính năng tra cứu và correlator vẫn hoạt động bình thường 100%.
* **Nếu máy demo không có sẵn các binary như Nmap, Gobuster:**
  - Hệ thống áp dụng cơ chế **Graceful Degradation**: Tự động nhận diện công cụ chưa cài đặt qua `/api/scans/tools` và sử dụng dữ liệu trinh sát chuẩn bị sẵn (`simulated/`) mà không gây crash ứng dụng.

### 5.2. Câu hỏi thường gặp từ Hội đồng / Khách hàng

* **Q1: Tại sao Copilot không tự động tấn công để lấy shell chứng minh lỗ hổng?**
  > *Đáp:* "AI-Pentest Copilot định vị là một Security Workbench hỗ trợ chuyên gia (Human-in-the-loop) và phòng thủ (Defense-oriented). Việc tự động khai thác mang lại rủi ro gián đoạn dịch vụ và vi phạm pháp lý. Copilot tập trung tự động hóa các khâu tốn nhiều thời gian nhất: Trinh sát đa nguồn, đối soát tương quan tri thức, sinh kịch bản kiểm tra an toàn và lập báo cáo tuân thủ."

* **Q2: Làm sao đảm bảo AI không bịa đặt CVE ảo (Hallucination)?**
  > *Đáp:* "Copilot sử dụng kiến trúc RAG 3 tầng: (1) Cơ sở dữ liệu SQLite cục bộ đã được kiểm duyệt với 539 CVEs và 52 CWEs; (2) Thuật toán so khớp phiên bản Semantic Version Tuple chính xác đến từng build; (3) Bộ quy tắc phân loại phát ngôn bắt buộc: mọi nhận định phải xuất phát từ chứng cứ thật (FACT), suy luận có đối chiếu (INFERENCE) hoặc giả thuyết cần kiểm chứng (HYPOTHESIS)."

* **Q3: Báo cáo của hệ thống có thể kết nối vào quy trình CI/CD của doanh nghiệp không?**
  > *Đáp:* "Có. Ngoài định dạng Markdown và HTML, hệ thống hỗ trợ xuất chuẩn SARIF (Static Analysis Results Interchange Format). Đây là chuẩn mở được hỗ trợ bởi GitHub Code Scanning, GitLab Security Dashboard và SonarQube, cho phép tự động tạo issue hoặc chặn merge request nếu phát hiện rủi ro bảo mật nghiêm trọng."
