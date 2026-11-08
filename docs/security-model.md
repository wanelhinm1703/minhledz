# AI-Pentest Copilot — Mô Hình An Toàn & Chốt Chặn Bảo Vệ (Security Model & Guardrails)

> **Tài liệu đặc tả các nguyên tắc an toàn, kiểm soát phạm vi và cơ chế chống ảo giác (v5.0)**  
> **Phiên bản:** 5.0  
> **Ngôn ngữ:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Đạo đức AI)

---

## 1. Triết Lý Thiết Kế An Toàn (Safety-First Philosophy)

**AI-Pentest Copilot** được phát triển với sứ mệnh làm trợ lý an ninh chuyên nghiệp (Security Workbench) hỗ trợ các chuyên gia kiểm thử xâm nhập (Penetration Tester) và kỹ sư an ninh mạng (SecOps/DevSecOps) theo định hướng **phòng thủ và hỗ trợ con người (Human-in-the-loop, Defense-oriented)**. 

Hệ thống thiết lập một rào giậu bảo vệ nhiều lớp nhằm ngăn ngừa triệt để các rủi ro:
- Lạm dụng AI để thực hiện các cuộc tấn công phá hoại hoặc chiếm quyền điều khiển trái phép.
- Rà quét nhầm các hạ tầng mạng công cộng nằm ngoài phạm vi ủy quyền (Scope of Engagement).
- Phát sinh ảo giác (AI Hallucination) dẫn đến báo cáo sai lệch số hiệu CVE hoặc điểm CVSS ảo.
- Làm sai lệch hoặc mất dấu vết chứng cứ số trong quá trình điều tra pháp y (Digital Forensics).

---

## 2. 7 Quy Tắc Chốt Chặn An Toàn Cốt Lõi (Core Guardrail Rules)

```
+-----------------------------------------------------------------------------------------+
|                                7 CHỐT CHẶN AN TOÀN CỐT LÕI                              |
|                                                                                         |
|  [1] Chặn Tuyệt Đối Tấn Công Khai Thác (Strict NO Automated Exploitation)               |
|      -> Kích hoạt [GUARDRAIL REFUSAL], từ chối sinh vũ khí tấn công/reverse shell        |
|                                                                                         |
|  [2] Tính Toàn Vẹn Bằng Chứng Số Bất Biến (Immutable Raw Evidence)                     |
|      -> Kết quả scan thô (.xml, .jsonl) không bao giờ bị sửa đổi, ký băm SHA-256        |
|                                                                                         |
|  [3] Nhật Ký Kiểm Toán Dòng Lệnh Toàn Diện (Comprehensive Command Auditing)             |
|      -> Ghi vết 100% lệnh CLI, tham số, mã thoát vào commands.md                        |
|                                                                                         |
|  [4] Chống Ảo Giác & Phân Tách Dữ Liệu (Anti-Hallucination & FACT/INFERENCE)            |
|      -> Cấm bịa CVE/CWE; bắt buộc tuyên bố "Insufficient Evidence" khi thiếu chứng cứ   |
|                                                                                         |
|  [5] Kiểm Soát Phạm Vi Ủy Quyền Nghiêm Ngặt (Strict Scope Enforcement)                  |
|      -> Tuân thủ RFC 1918 Private IP; chặn tuyệt đối IP công cộng (8.8.8.8)             |
|                                                                                         |
|  [6] Hồ Sơ An Toàn & Quản Trị Rủi Ro Scan (Safety Profiles & Operator Confirmation)     |
|      -> Công cụ xung năng lượng cao (Masscan) bắt buộc có xác nhận người vận hành       |
|                                                                                         |
|  [7] Không Tạo Dữ Liệu Giả Trong Môi Trường Thật (Zero Simulation in Production)        |
|      -> Thiếu binary trả mã lỗi 127 chuẩn xác, không tạo open port giả lập              |
+-----------------------------------------------------------------------------------------+
```

---

### Quy Tắc 1: Tuyệt Đối KHÔNG Tấn Công Khai Thác Tự Động (Strict NO Automated Exploitation)
- Nền tảng **tuyệt đối không bao giờ** tự động hóa việc vũ khí hóa (weaponization) hoặc khai thác lỗ hổng xâm nhập hệ thống.
- Bất kỳ yêu cầu nào từ người dùng có xu hướng tấn công xâm nhập (ví dụ: `exploit target`, `reverse shell`, `sqlmap --os-shell`, `chiếm quyền root`) ngay lập tức kích hoạt cơ chế **`[GUARDRAIL REFUSAL]`**.
- Khi kích hoạt từ chối, Copilot tự động hướng dẫn chuyên gia theo quy trình kiểm thử có trách nhiệm:
  1. Phân tích nguyên nhân gốc của điểm yếu (Root Cause Analysis).
  2. Lập kế hoạch xác minh chỉ đọc, không phá hoại (Safe Read-Only Validation).
  3. Cung cấp câu lệnh thăm dò passive banner grab an toàn.
  4. Đề xuất phương án vá lỗi và phòng thủ theo tiêu chuẩn NIST / CIS.
- **Giới hạn công cụ Exploit (SearchSploit)**: Chỉ được phép hoạt động ở chế độ tra cứu thông tin tham chiếu ngoại tuyến (`searchsploit --json <query>`). Hệ thống cấm hoàn toàn việc tự động tải, biên dịch hoặc chạy mã khai thác (`.c`, `.py`).

### Quy Tắc 2: Tính Toàn Vẹn Bằng Chứng Số Bất Biến (Immutable Raw Evidence)
- Mọi đầu ra thô từ các công cụ dòng lệnh (`.xml`, `.nmap`, `.jsonl`, `.txt`) được lưu trữ tại các thư mục chuyên biệt trong `toolkit/`. Một khi đã ghi xuống đĩa, các tệp này mang tính chất bất biến (forensic records) và không bao giờ bị ghi đè hay chỉnh sửa thủ công.
- Tệp mục lục bằng chứng tại `toolkit/09-analysis/manifests/` lưu trữ chỉ số băm mật mã học (SHA-256) của từng tệp chứng cứ, đảm bảo tính pháp lý và khả năng phục dựng nguyên trạng chuỗi bằng chứng.

### Quy Tắc 3: Nhật Ký Kiểm Toán Dòng Lệnh Toàn Diện (Command Auditing)
- Mọi câu lệnh trinh sát do các Runner thực thi đều được ghi lại tức thì vào tệp nhật ký `toolkit/<category>/commands.md`.
- Các trường thông tin kiểm toán bắt buộc:
  - Thời điểm thực thi (Timestamp ISO 8601).
  - Tên công cụ và mã định danh.
  - Toàn bộ chuỗi đối số dòng lệnh chính xác.
  - Thời lượng thực thi (Duration).
  - Mã trạng thái kết thúc (Exit Code) và thông báo lỗi (nếu có).

### Quy Tắc 4: Chống Ảo Giác & Phân Tách Bằng Chứng / Giả Thuyết (Anti-Hallucination)
- Trợ lý AI Copilot bị ràng buộc chặt chẽ bởi System Prompt: **CẤM TUYỆT ĐỐI** việc tự sáng tác số hiệu CVE, mã CWE, phiên bản phần mềm, điểm số CVSS hoặc đường dẫn URL nguồn.
- Mọi thông điệp phân tích phải tuân thủ cấu trúc phân tầng nhận thức:
  - **`FACT`**: Các dữ kiện được chứng minh trực tiếp từ kết quả quét (ví dụ: `Cổng 80 mở, banner ghi nhận Apache 2.4.49`).
  - **`INFERENCE`**: Kết luận suy luận từ cơ sở tri thức đã kiểm duyệt (ví dụ: `Apache 2.4.49 khớp với CVE-2021-41773 trong KB`).
  - **`HYPOTHESIS`**: Các giả định chưa được chứng minh đầy đủ, cần thực hiện thêm bước xác minh an toàn.
- Nếu không tìm thấy bằng chứng trong kết quả quét hoặc cơ sở tri thức, Copilot bắt buộc phải đưa ra tuyên bố chuẩn:
  > *"FACT: Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities."*

### Quy Tắc 5: Kiểm Soát Phạm Vi Ủy Quyền Nghiêm Ngặt (Strict Scope Enforcement)
- Trước khi thực thi bất kỳ công cụ nào, mục tiêu được chuyển qua bộ thẩm định `ScopeValidator`.
- Mục tiêu hợp lệ bắt buộc phải thuộc danh sách phạm vi cho phép (`ALLOWED_SCOPES`), mặc định bao gồm các dải mạng riêng tư theo chuẩn **RFC 1918**:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.1` / `localhost`
  - Tên miền cục bộ: `*.local`
- Mọi địa chỉ IP công cộng (ví dụ: `8.8.8.8`) hoặc domain công cộng ngoài danh sách ủy quyền đều bị hệ thống từ chối lập tức với mã lỗi `ScopeViolationError` (Exit code 2).

### Quy Tắc 6: Hồ Sơ An Toàn & Quản Trị Rủi Ro Scan (Safety Profiles)
- Các công cụ có khả năng làm nghẽn băng thông mạng hoặc gửi lượng gói tin đột biến (như Masscan tốc độ cao) đều được gắn cờ ràng buộc `requires_user_confirmation: true`, bắt buộc người vận hành phải xác nhận trước khi phát gói tin.
- Các cấu hình quét mặc định (Default Profiles) luôn áp dụng cờ không phá hoại (Non-destructive flags), chẳng hạn Nmap Safe NSE:
  ```bash
  nmap -sV --script="banner,default and safe" <target>
  ```

### Quy Tắc 7: Không Tạo Dữ Liệu Giả Trong Môi Trường Thực (Zero Simulation in Production)
- Khi triển khai thực tế (`simulate=False`), nếu một binary công cụ chưa được cài đặt trên máy chủ, hệ thống trả về mã lỗi 127 kèm trạng thái chẩn đoán `ToolNotInstalled`.
- Hệ thống **tuyệt đối không bao giờ** sinh ra các cổng mở giả lập hoặc dịch vụ hư cấu trong chế độ vận hành chính thức, đảm bảo tính trung thực tuyệt đối của báo cáo an ninh.

---

## 3. Tài Liệu Liên Quan

- [Kiến Trúc Tổng Thể Hệ Thống](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md)
- [Cơ Sở Tri Thức Lỗ Hổng](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/knowledge-base.md)
- [Hệ Thống Quản Lý Target Động](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/target-system.md)
- [Cẩm Nang Bộ Công Cụ Pentest](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md)
