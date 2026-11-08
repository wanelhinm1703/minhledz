# AI-Pentest Copilot — Hệ Thống Mục Tiêu Động & Mô Hình Lab Mở Rộng (Dynamic Target System & Extensible Lab Model)

> **Tài liệu đặc tả quy trình tiếp nhận mục tiêu, thẩm định phạm vi và định tuyến công cụ trinh sát (v5.0)**  
> **Phiên bản:** 5.0  
> **Ngôn ngữ:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Quản trị Hệ thống)

---

## 1. Tổng Quan

**AI-Pentest Copilot** cung cấp quy trình tiếp nhận mục tiêu động không độ trễ (Zero-friction Dynamic Target Ingestion Pipeline). Người vận hành không cần phải tự tay soạn thảo các tệp cấu hình YAML tĩnh phức tạp trước khi bắt đầu quét. 

Mọi mục tiêu được nhập vào hệ thống đều trải qua quy trình tự động: thẩm định cú pháp theo thời gian thực, đối soát chính sách phạm vi ủy quyền, chuẩn hóa dữ liệu và tự động sinh kế hoạch trinh sát đa công cụ tối ưu nhất dựa trên các cổng dịch vụ phát hiện được.

---

## 2. Quy Trình Xử Lý Mục Tiêu Tuần Hoàn (Pipeline Flow)

```text
Đầu vào Mục tiêu từ Người dùng (IP, CIDR, URL, Host:Port, Domain)
  ↓
[1] Target Parser (Nhận diện kiểu dữ liệu, bóc tách URI, protocol, host, port)
  ↓
[2] Target Normalizer (Đưa về dạng chuẩn Canonical, chữ thường, gán cổng mặc định)
  ↓
[3] Target Validator (Kiểm tra cú pháp RFC và giới hạn cổng hợp lệ [1-65535])
  ↓
[4] Scope Validator (Kiểm tra danh sách trắng phạm vi ủy quyền ALLOWED_SCOPES)
  ↓
[5] Target Registry (Lưu trữ đối tượng Target với ID duy nhất vào toolkit/01-targets/)
  ↓
[6] Recon Planner (Ánh xạ năng lực & lập lịch công cụ theo dịch vụ phát hiện)
  ↓
[7] Recon Runner (Thực thi đa công cụ song song/tuần tự, lưu raw evidence & commands.md)
  ↓
[8] JSON Parsers & Schema Validation (Chuẩn hóa đầu ra theo chuẩn security/schemas/)
  ↓
[9] Bằng chứng Số & Chỉ mục Manifest (Lưu trữ tại toolkit/09-analysis/manifests/)
  ↓
[10] Context Engine & Conflict Detection (Phát hiện sai lệch thông tin giữa các công cụ)
```

---

## 3. Các Định Dạng Mục Tiêu Được Hỗ Trợ (Supported Target Types)

Hệ thống hỗ trợ đầy đủ 6 định dạng mục tiêu mạng phổ biến:

| Kiểu Mục Tiêu | Cú Pháp Mẫu | Ví Dụ Điển Hình | Năng Lực Trinh Sát Tương Ứng |
|---|---|---|---|
| **IPv4** | Địa chỉ IPv4 chuẩn | `192.168.56.101` | Quét cổng TCP/UDP, nhận diện OS, dịch vụ mạng |
| **IPv6** | Địa chỉ IPv6 chuẩn | `::1`, `fe80::1` | Quét mạng thế hệ mới, kiểm tra dịch vụ cục bộ |
| **CIDR** | Dải mạng kèm subnet mask | `192.168.56.0/24` | Quét quét nhanh diện rộng (Masscan, Nmap Fast) |
| **URL** | Đường dẫn web đầy đủ | `http://192.168.56.101:3000`, `https://target.local/app` | Thăm dò HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana |
| **Host:Port** | Tên máy kèm cổng dịch vụ | `10.10.10.20:8080` | Thăm dò dịch vụ trực tiếp trên cổng đích |
| **Domain / Hostname** | Tên miền nội bộ hoặc FQDN | `juice-shop.local`, `target.corp` | Phân giải DNS, kiểm tra Web & dịch vụ Directory |

---

## 4. Cơ Chế Kiểm Soát Phạm Vi Ủy Quyền (Scope Enforcement)

Tuân thủ phạm vi kiểm thử (Scope of Engagement) là nguyên tắc an toàn số một của kiểm thử an ninh chuyên nghiệp.

- Hệ thống cấu hình chính sách phạm vi thông qua biến môi trường `ALLOWED_SCOPES`.
- **Phạm vi cho phép mặc định**: Bao gồm toàn bộ các dải địa chỉ mạng riêng tư theo chuẩn **RFC 1918**, máy chủ cục bộ và tên miền nội bộ:
  ```text
  10.0.0.0/8
  172.16.0.0/12
  192.168.0.0/16
  127.0.0.1
  localhost
  *.local
  ```
- **Chặn tuyệt đối mục tiêu công cộng**: Bất kỳ mục tiêu nào nằm ngoài phạm vi cho phép (ví dụ: `8.8.8.8` hoặc `https://google.com`) sẽ bị `ScopeValidator` ngăn chặn ngay lập tức với thông báo lỗi rõ ràng:
  ```text
  [!] Scope Violation: Target '8.8.8.8' is OUT OF SCOPE. 
      Only RFC 1918 Private IPv4 and authorized subnets are allowed.
  ```
  Quá trình kết thúc với mã lỗi `2` mà không phát bất kỳ gói tin nào ra mạng ngoài.

---

## 5. Định Tuyến Công Cụ Theo Dịch Vụ Phát Hiện (Service-Driven Tool Routing)

Sau khi giai đoạn quét cổng ban đầu (Nmap/Masscan/RustScan) hoàn tất, phân hệ `ReconPlanner` tự động phân tích các cổng mở và chỉ định tiếp các công cụ kiểm tra dịch vụ chuyên sâu:

```
                      [Các Cổng Mở Được Phát Hiện]
                                   |
         +-------------------------+-------------------------+
         |                         |                         |
         v                         v                         v
     Port 445/139               Port 161               Port 389/636
       (SMB)                     (SNMP)                   (LDAP)
         |                         |                         |
         v                         v                         v
    enum4linux                  snmpwalk                 ldapsearch
    smbclient
         |                         |                         |
         +-------------------------+-------------------------+
                                   |
         +-------------------------+-------------------------+
         |                                                   |
         v                                                   v
   Ports 3306, 5432, 6379, 27017, 1433                  Ports 80, 443, 8080, 3000...
         (Database Services)                                 (Web Services)
                 |                                                   |
                 v                                                   v
   Database Clients (MySQL, Postgres, Redis...)           HTTPx, WhatWeb, Nikto,
   (Chỉ đọc trạng thái và banner an toàn)                 Gobuster, FFUF, Katana
                                                                     |
                                                                     v
                                                          [Phiên Bản Phần Mềm Cụ Thể]
                                                                     |
                                                                     v
                                                                SearchSploit
                                                       (Tra cứu offline CVE & Exploit-DB)
```

### Chi tiết các kịch bản định tuyến tự động:
1. **Cổng 445 / 139 (SMB / Samba)**:
   - Tự động kích hoạt `enum4linux` (thu thập thông tin Domain, Workgroup, danh sách người dùng và tên chia sẻ mạng).
   - Tự động kích hoạt `smbclient` kiểm tra quyền truy cập phiên ẩn danh (Null Session / Anonymous Login).
2. **Cổng 161 (SNMP)**:
   - Tự động chạy `snmpwalk` với community string mặc định (`public`) để đọc cây thông tin hệ thống (System MIB tree).
3. **Cổng 389 / 636 (LDAP / Active Directory)**:
   - Tự động kích hoạt `ldapsearch` truy vấn cấu trúc ngữ cảnh danh mục (`namingContexts`).
4. **Cổng Cơ Sở Dữ Liệu (3306 - MySQL, 5432 - Postgres, 6379 - Redis, 27017 - MongoDB, 1433 - MSSQL)**:
   - Tự động kích hoạt client tương ứng ở chế độ kiểm tra banner và tình trạng sống chỉ đọc (Read-only status grab).
5. **Cổng Dịch Vụ Web (80, 443, 8080, 8443, 3000...)**:
   - Khởi chạy song song: `httpx` (thăm dò HTTP alive và status code), `whatweb` (nhận diện CMS và framework), `nikto` (rà soát cấu hình sai máy chủ web), `gobuster`/`ffuf` (dò quét thư mục nhạy cảm), `katana` (thu thập liên kết trang web).
6. **Nhận Diện Được Phiên Bản Phần Mềm Cụ Thể**:
   - Tự động gửi từ khóa phiên bản tới `searchsploit` để tra cứu ngoại tuyến các mã khai thác đã công bố trên Exploit-DB và đối soát với Vulnerability Knowledge Base.

---

## 6. Tài Liệu Liên Quan

- [Kiến Trúc Tổng Thể Hệ Thống](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md)
- [Mô Hình An Toàn & Guardrails](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md)
- [Cẩm Nang Bộ Công Cụ Pentest](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md)
- [Kịch Bản Demo Chi Tiết](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md)
