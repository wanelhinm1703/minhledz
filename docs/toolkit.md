# AI-Pentest Copilot — Cẩm Nang Bộ Công Cụ Pentest Tích Hợp (Toolkit Documentation)

> **Tài liệu đặc tả danh mục công cụ, cấu hình tham số, cấu trúc bằng chứng và cơ chế giải quyết xung đột (v5.0)**  
> **Phiên bản:** 5.0  
> **Ngôn ngữ:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Vận hành Công cụ Pentest)

---

## 1. Tổng Quan Về Bộ Công Cụ

**AI-Pentest Copilot** tích hợp một chuỗi công cụ kiểm thử bảo mật toàn diện, đạt tiêu chuẩn công nghiệp (Production-grade), được tổ chức khoa học theo 5 nhóm nghiệp vụ trinh sát và đánh giá:

1. **Quét mạng & Phát hiện cổng (Network Discovery & Port Scanning)**
2. **Thăm dò web & Thu thập liên kết (Web Probing & Content Discovery)**
3. **Đánh giá lỗ hổng & Tham chiếu mã khai thác (Vulnerability Assessment & Exploit Reference)**
4. **Rà soát thông tin dịch vụ (Service Enumeration & Target Fingerprinting)**
5. **Cấu hình Proxy & Kiểm thử bán tự động (Proxy Configuration & Manual Testing Workflow)**

Toàn bộ các công cụ vận hành tuân thủ nghiêm ngặt các nguyên lý kỹ thuật:
- **Không giả lập bừa bãi (Zero Simulation in Production)**: Nếu file nhị phân (binary) chưa được cài đặt trên hệ thống, tiến trình kết thúc an toàn với mã lỗi 127 (`ToolNotInstalled`), ghi lại thông báo chẩn đoán rõ ràng mà không làm gián đoạn toàn bộ pipeline.
- **Bằng chứng số thô bất biến (Immutable Raw Evidence)**: Kết quả đầu ra từ CLI (`.xml`, `.jsonl`, `.txt`) được lưu trữ tại các phân mục chuyên biệt trong `toolkit/` và tuyệt đối không bị ghi đè hay sửa đổi.
- **Chuẩn hóa JSON theo Schema chặt chẽ**: Mỗi công cụ đều có parser chuyển đổi đầu ra thô thành dữ liệu JSON được thẩm định theo JSON Schema tại `security/schemas/`.
- **Nhật ký kiểm toán dòng lệnh đầy đủ**: 100% câu lệnh thực thi được lưu lại vào `toolkit/<category>/commands.md`.
- **Chốt chặn an toàn chỉ đọc (Non-Destructive Guardrails)**: Tuyệt đối ngăn chặn các hành vi tấn công phá hoại, brute-force mật khẩu ồ ạt hoặc kích hoạt các script xâm lấn nguy hiểm.

---

## 2. Ma Trận Công Cụ Được Tích Hợp (Supported Tools Matrix)

| Nhóm Nghiệp Vụ | Mã Định Danh | File Nhị Phân | Chức Năng Chính | Thư Mục Bằng Chứng | Schema Xác Thực |
|---|---|---|---|---|---|
| **Network** | `nmap` | `nmap` / `nmap.exe` | Quét cổng TCP/UDP, nhận diện hệ điều hành và phiên bản dịch vụ | `toolkit/03-network/nmap/` | `nmap_scan_result.schema.json` |
| **Network** | `masscan` | `masscan` | Quét cổng băng thông siêu tốc bằng kỹ thuật bất đồng bộ SYN | `toolkit/03-network/masscan/` | `masscan_result.schema.json` |
| **Network** | `rustscan` | `rustscan` | Quét cổng hiện đại viết bằng Rust, chuyển hướng cổng mở sang Nmap | `toolkit/03-network/rustscan/` | `rustscan_result.schema.json` |
| **Network** | `naabu` | `naabu` | Thăm dò cổng nhanh theo cơ chế SYN/Connect (dự phòng) | `toolkit/03-network/naabu/` | `naabu_scan_result.schema.json` |
| **Web** | `httpx` | `httpx` | Thăm dò dịch vụ HTTP/HTTPS đa luồng, kiểm tra mã trạng thái, tiêu đề phản hồi | `toolkit/04-web/httpx/` | `httpx_scan_result.schema.json` |
| **Web** | `whatweb` | `whatweb` | Nhận diện dấu vân tay công nghệ web (CMS, Server, Framework, Analytics) | `toolkit/04-web/whatweb/` | `whatweb_result.schema.json` |
| **Web** | `nikto` | `nikto` / `nikto.pl` | Quét cấu hình sai máy chủ web, phát hiện tệp tin và thư mục nguy hiểm | `toolkit/04-web/nikto/` | `nikto_result.schema.json` |
| **Web** | `gobuster` | `gobuster` | Dò quét thư mục ẩn, tệp tin và subdomain trên máy chủ web | `toolkit/04-web/gobuster/` | `gobuster_result.schema.json` |
| **Web** | `ffuf` | `ffuf` | Công cụ Fuzzing đường dẫn web và tham số HTTP tốc độ cao | `toolkit/04-web/ffuf/` | `ffuf_result.schema.json` |
| **Web** | `katana` | `katana` | Thu thập liên kết tự động (Web crawler/spider thế hệ mới) | `toolkit/04-web/katana/` | `katana_result.schema.json` |
| **Vulnerability** | `nuclei` | `nuclei` | Đánh giá lỗ hổng dựa trên hệ thống templates cộng đồng định dạng YAML | `toolkit/05-vulnerability/nuclei/` | `nuclei_scan_result.schema.json` |
| **Vulnerability** | `searchsploit` | `searchsploit` | Tra cứu ngoại tuyến các mã khai thác trên Exploit-DB và tham chiếu CVE | `toolkit/05-vulnerability/searchsploit/` | `searchsploit_result.schema.json` |
| **Service Enum** | `enum4linux` | `enum4linux` | Trích xuất thông tin hệ thống Windows/Samba (Workgroup, Users, Shares) | `toolkit/06-service-enum/enum4linux/` | `service_enum_result.schema.json` |
| **Service Enum** | `smbclient` | `smbclient` | Liệt kê các thư mục chia sẻ tệp SMB và kiểm tra phiên ẩn danh Null Session | `toolkit/06-service-enum/smbclient/` | `service_enum_result.schema.json` |
| **Service Enum** | `snmpwalk` | `snmpwalk` | Truy vấn cây dữ liệu MIB và OID qua giao thức quản trị mạng SNMP | `toolkit/06-service-enum/snmpwalk/` | `service_enum_result.schema.json` |
| **Service Enum** | `ldapsearch` | `ldapsearch` | Truy vấn dịch vụ danh bạ Active Directory / OpenLDAP (`namingContexts`) | `toolkit/06-service-enum/ldapsearch/` | `service_enum_result.schema.json` |
| **Service Enum** | `database` | `mysql`/`psql`/`redis-cli`/`mongosh`/`sqlcmd` | Thu thập banner và kiểm tra trạng thái chỉ đọc của các hệ quản trị CSDL | `toolkit/06-service-enum/database/` | `service_enum_result.schema.json` |
| **Manual/Proxy** | `burpsuite` | `burpsuite` | Tạo file cấu hình scope dự án và thiết lập proxy chuyển tiếp cho Burp Suite | `toolkit/08-manual/burpsuite/` | `proxy_manual.schema.json` |
| **Manual/Proxy** | `zap` | `zap.sh` / `zap.bat` | Tạo cấu hình Context và thiết lập proxy upstream cho OWASP ZAP | `toolkit/08-manual/zap/` | `proxy_manual.schema.json` |

---

## 3. Chi Tiết Từng Công Cụ & Cấu Hình Hồ Sơ Thực Thi

### 3.1. Nhóm Quét Mạng (Network Discovery)

#### Nmap (`run_nmap.py`, `parse_nmap.py`)
- **Các hồ sơ quét (Profiles)**:
  - `default`: `-sS -sV -T3 -F` (Quét SYN 100 cổng phổ biến, nhận diện dịch vụ chuẩn).
  - `stealth`: `-sS -sV -T2 --randomize-hosts` (Quét ẩn mình, giãn cách thời gian để tránh kích hoạt IDS/IPS).
  - `fast`: `-sS -sV -T4 -F` (Quét nhanh 100 cổng phổ biến).
  - `comprehensive`: `-sS -sV -O -p-` (Quét toàn diện 65.535 cổng và nhận diện OS).
  - `safe_nse`: `-sV --script="banner,default and safe"` (Quét dịch vụ kèm các script NSE an toàn, không phá hoại).
- **Đầu ra**:
  - Dữ liệu thô: `toolkit/03-network/nmap/raw/<target>_nmap.xml` và `.nmap`
  - Dữ liệu cấu trúc: `toolkit/03-network/nmap/structured/<target>_nmap.json`

#### Masscan (`run_masscan.py`, `parse_masscan.py`)
- **Các hồ sơ quét**:
  - `default`: `--rate=1000 -p1-1000`
  - `stealth`: `--rate=100 -p1-1000`
  - `fast`: `--rate=5000 -p1-10000`
  - `comprehensive`: `--rate=2000 -p1-65535`
- **Định dạng xuất**: `-oJ` (JSON chuẩn).
- **Rào chắn an toàn**: Do tốc độ gửi gói tin cực lớn có thể gây nghẽn đường truyền, Masscan bắt buộc có xác nhận người vận hành (`requires_user_confirmation: true`).

#### RustScan (`run_rustscan.py`, `parse_rustscan.py`)
- **Các hồ sơ quét**:
  - `default`: `-b 1000 -t 1500 -- -sV`
  - `stealth`: `-b 200 -t 3000 -- -sV`
  - `fast`: `-b 2500 -t 1000 -- -sV`
  - `comprehensive`: `-b 1500 -t 2000 -- -sV -sC -O`
- **Định dạng xuất**: Đầu ra dạng `--greppable` được bóc tách tự động thành danh sách cổng mở và nạp tiếp vào Nmap để kiểm tra phiên bản.

---

### 3.2. Nhóm Thăm Dò Web & Thu Thập Liên Kết (Web Recon & Crawling)

#### WhatWeb (`run_whatweb.py`, `parse_whatweb.py`)
- **Các hồ sơ quét**:
  - `stealth`: `-a 1` (Chỉ kiểm tra tiêu đề HTTP thụ động).
  - `default`: `-a 3` (Thăm dò tích cực tiêu chuẩn).
  - `comprehensive`: `-a 4` (Thăm dò sâu toàn diện).
- **Đầu ra**: Xuất file JSON (`--log-json`). Trích xuất chính xác tiêu đề máy chủ, framework backend (Laravel, Express, Django...), CMS (WordPress, Joomla...) và thư viện JavaScript.

#### Nikto (`run_nikto.py`, `parse_nikto.py`)
- **Các hồ sơ quét**:
  - `default`: `-Tuning 1234b`
  - `stealth`: `-Tuning 1 -evasion 1`
  - `comprehensive`: `-Tuning 1234567890abc`
- **Đầu ra**: Xuất file JSON (`-Format json -output <path>`). Phát hiện các tệp tin nguy hiểm (`.git`, backup, phpinfo), cấu hình tiêu đề thiếu sót và phiên bản máy chủ lỗi thời.

#### Gobuster (`run_gobuster.py`, `parse_gobuster.py`)
- **Các hồ sơ quét**:
  - `default`: `-t 10`
  - `stealth`: `-t 2 --delay 500ms`
  - `fast`: `-t 25`
- **Quản lý danh sách từ điển**: Tích hợp sẵn danh sách từ điển dự phòng (fallback wordlist) nếu môi trường chưa cài đặt các wordlist lớn như `dirb` hay `SecLists`.
- **Đầu ra**: Bóc tách mã trạng thái phản hồi HTTP, dung lượng byte và đường dẫn URL tìm thấy.

#### FFUF (`run_ffuf.py`, `parse_ffuf.py`)
- **Các hồ sơ quét**:
  - `default`: `-rate 50 -mc 200,204,301,302,307,401,403`
  - `stealth`: `-rate 10 -p 0.5`
  - `fast`: `-rate 150`
- **Đầu ra**: Tệp JSON cấu trúc (`-o <path> -of json`).

#### Katana (`run_katana.py`, `parse_katana.py`)
- **Các hồ sơ quét**:
  - `default`: `-depth 3 -concurrency 5`
  - `stealth`: `-depth 2 -concurrency 2 -delay 1`
  - `fast`: `-depth 3 -concurrency 15`
- **Đầu ra**: Dòng JSON (JSONL) chứa danh sách toàn bộ endpoint, phương thức HTTP (GET/POST) và tham số URL phát hiện được.

---

### 3.3. Nhóm Đánh Giá Lỗ Hổng & Rà Soát Dịch Vụ

#### SearchSploit (`run_searchsploit.py`, `parse_searchsploit.py`)
- **Phương thức vận hành**: Tra cứu chỉ đọc qua lệnh `searchsploit --json <tên_dịch_vụ_phiên_bản>`.
- **An toàn**: Hoàn toàn ngoại tuyến. Không tải về hay chạy file khai thác, chỉ thu thập mã định danh EDB-ID và liên kết CVE để đối chiếu vào Vulnerability KB.

#### Rà Soát Dịch Vụ Mạng (Service Enumeration)
- **SMB / Windows**:
  - `enum4linux -U -S <target>`: Thu thập người dùng và tài nguyên chia sẻ.
  - `smbclient -L //<target> -N`: Kiểm tra duyệt chia sẻ tệp không cần mật khẩu.
- **SNMP**:
  - `snmpwalk -v2c -c public <target> system`: Đọc an toàn thông tin hệ thống từ MIB-2.
- **LDAP**:
  - `ldapsearch -x -H ldap://<target> -b "" -s base namingContexts`: Trích xuất context phân cấp thư mục.
- **Dịch Vụ Cơ Sở Dữ Liệu**:
  - Gửi các lệnh truy vấn trạng thái chỉ đọc (ví dụ: `mysql -h <target> -e "STATUS;"` hoặc `redis-cli -h <target> INFO`).

---

### 3.4. Nhóm Proxy & Kiểm Thử Bán Tự Động

#### Burp Suite & OWASP ZAP (`run_proxy_manual.py`)
- **Chức năng**:
  - Tự động sinh tệp cấu hình dự án kèm danh sách URL được phép kiểm thử trong Scope (`burpsuite_project_config.json` hoặc `zap_context.xml`).
  - Thiết lập sẵn cấu hình proxy cục bộ (`127.0.0.1:8080`) để chuyên gia dễ dàng định tuyến trình duyệt vào công cụ phân tích thủ công.
- **An toàn**: Chỉ sinh cấu hình định tuyến, tuyệt đối không tự động chạy các plugin tấn công tích cực (Active Scanner).

---

## 4. Cơ Chế Kiểm Tra Tính Khả Dụng Của Công Cụ (Availability & Health Verification)

Hệ thống cung cấp cơ chế tự động phát hiện tình trạng cài đặt của công cụ qua API:
```http
GET /api/scans/tools
```
Hoặc trực tiếp qua Python:
```python
from backend.app.services.tool_registry import check_tool_availability

status = check_tool_availability("nmap")
# Kết quả: {"tool": "nmap", "installed": True, "path": "/usr/bin/nmap", "category": "network"}
```

Khi một file nhị phân chưa được cài đặt trên máy chủ:
- API phản hồi `installed: False`.
- Khi thực thi lệnh rà quét trong môi trường thực (`simulate=False`), tiến trình trả về mã thoát `127` với trạng thái `unavailable` và thông báo lỗi rõ ràng.
- Pipeline trinh sát sẽ bỏ qua công cụ bị thiếu một cách nhẹ nhàng (Graceful Degradation) và tiếp tục thực thi các công cụ khả dụng khác mà không gây gián đoạn hay crash hệ thống.

---

## 5. Cơ Chế Phát Hiện & Giải Quyết Xung Đột Đa Công Cụ (Conflict Resolution)

Khi các công cụ trinh sát đưa ra thông tin mâu thuẫn nhau về cùng một cổng hoặc dịch vụ (ví dụ: Nmap ghi nhận `Apache 2.4.49` trên cổng 80, nhưng WhatWeb lại ghi nhận `Apache 2.4.51`):

```
                      +-------------------+
                      |   Nmap Scanner    | -> Báo cáo: Apache 2.4.49
                      +---------+---------+
                                |
                                v
               +---------------------------------+
               |   Context Engine & Correlator   |
               |  (Hàm: detect_conflicts())     |
               +----------------+----------------+
                                ^
                                |
                      +---------+---------+
                      |  WhatWeb Scanner  | -> Báo cáo: Apache 2.4.51
                      +-------------------+
```

1. **Context Engine** thực thi hàm `detect_conflicts(evidence_dict)` để trích xuất các thuộc tính dị biệt.
2. Hệ thống phát hiện sự bất đồng về phiên bản và gửi cảnh báo ưu tiên cao tới Copilot Chat:
   > `[WARNING] Tool Conflict Detected: Nmap báo 'Apache 2.4.49' trong khi WhatWeb báo 'Apache 2.4.51'. Cần thực hiện bước kiểm chứng bổ sung.`
3. Copilot tự động đề xuất một kịch bản kiểm chứng an toàn (Safe Verification Probe) bằng lệnh:
   ```bash
   curl -s -I "http://<target>:80"
   ```
   nhằm trích xuất nguyên bản trường `Server:` trong HTTP Header để xác nhận phiên bản chuẩn xác nhất.

---

## 6. Hướng Dẫn Bổ Sung Công Cụ Mới Vào Toolkit

Để mở rộng thêm một công cụ pentest mới vào hệ thống, chỉ cần thực hiện 4 bước tiêu chuẩn:

1. **Khai báo cấu hình YAML**: Tạo tệp `backend/app/catalog/tools/<tool_name>.yaml` định nghĩa danh mục, tham số dòng lệnh và profile quét.
2. **Khai báo JSON Schema**: Tạo tệp `security/schemas/<tool_name>_result.schema.json` quy định cấu trúc dữ liệu JSON sau khi parse.
3. **Viết Runner & Parser**:
   - `toolkit/<category>/<tool_name>/run_<tool_name>.py`: Thực thi công cụ qua `subprocess` hoặc Docker.
   - `toolkit/<category>/<tool_name>/parse_<tool_name>.py`: Bóc tách log thô thành JSON chuẩn schema.
4. **Tạo cấu trúc thư mục lưu bằng chứng**:
   ```bash
   mkdir -p toolkit/<category>/<tool_name>/raw
   mkdir -p toolkit/<category>/<tool_name>/structured
   ```

---

## 7. Tài Liệu Liên Quan

- [Kiến Trúc Tổng Thể Hệ Thống](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md)
- [Mô Hình An Toàn & Guardrails](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md)
- [Hệ Thống Quản Lý Target Động](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/target-system.md)
- [Cơ Sở Tri Thức Lỗ Hổng](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/knowledge-base.md)
- [Kịch Bản Demo Chi Tiết](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md)
