# AI-Pentest Copilot — Cơ Sở Tri Thức Lỗ Hổng & Công Cụ Tương Quan (Vulnerability Knowledge Base & Correlation Engine)

> **Tài liệu đặc tả kiến trúc lưu trữ, nguồn dữ liệu tri thức và thuật toán đối soát phiên bản (v5.0)**  
> **Phiên bản:** 5.0  
> **Ngôn ngữ:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Kỹ thuật Dữ liệu)

---

## 1. Tổng Quan & Kiến Trúc Lưu Trữ

**Vulnerability Knowledge Base (KB)** là phân hệ tri thức cốt lõi của AI-Pentest Copilot, cung cấp khả năng tra cứu, đối soát và làm giàu ngữ cảnh an ninh hoàn toàn **ngoại tuyến (Offline-first)** mà không phụ thuộc vào kết nối Internet khi tiến hành rà quét trong môi trường mạng cách ly (Air-gapped / Private Lab).

Hệ thống sử dụng mô hình lưu trữ lai tối ưu hóa cho hiệu năng:
- **Cơ sở dữ liệu SQLite (`toolkit/data/kb.sqlite`)**: Đảm bảo tốc độ truy vấn mili-giây, hỗ trợ tìm kiếm cấu trúc chính xác, đánh chỉ mục phiên bản và lưu trữ bản ghi có thẩm quyền.
  - Bảng dữ liệu chính: `cve`, `cve_affected`, `cwe`, `mitre_technique`, `cisa_kev`, `product_version_index`.
  - Quy mô dữ liệu chuẩn: **539 CVEs trọng yếu** và **52 danh mục CWE cốt lõi**.
- **Tính Minh Bạch Dữ Liệu (Data Provenance)**: Mỗi bản ghi trong hệ thống đều lưu trữ nguồn gốc xuất xứ chặt chẽ với các trường: `source_url`, `source_name`, `ingested_at`, và `last_modified`.

```
               +------------------------------------------+
               |       CÁC NGUỒN TRI THỨC CÓ THẨM QUYỀN   |
               |     (NVD CVE, MITRE CWE, CISA KEV...)    |
               +--------------------+---------------------+
                                    |
                                    v
                    +--------------------------------+
                    |    Scripts Nạp Dữ Liệu Ingest   |
                    |    (backend/app/ingest/)       |
                    +---------------+----------------+
                                    |
                                    v
       +------------------------------------------------------------+
       |             SQLite KNOWLEDGE BASE (kb.sqlite)              |
       |  - cve (ID, CVSS, Summary, Vector, CWE)                    |
       |  - cve_affected (Product, Version Min/Max, Vendor)         |
       |  - cwe (ID, Name, Description, Likelihood, Mitigation)     |
       |  - cisa_kev (CVE ID, Date Added, Due Date, Ransomware Flag)|
       |  - product_version_index (Chỉ mục tra cứu nhanh)           |
       +----------------------------+-------------------------------+
                                    |
                                    v
          +----------------------------------------------------+
          |       SEMANTIC VERSION CORRELATOR ENGINE           |
          |  - So khớp Version Tuple: (2, 4, 49) vs (2, 4, 9)  |
          |  - Đánh giá Confidence: Exact (0.95), Range (0.85) |
          +-------------------------+--------------------------+
                                    |
                                    v
       +----------------------------+-------------------------------+
       |             RAG CONTEXT CHO AI COPILOT CHAT                |
       |  - Phân định FACT / INFERENCE / HYPOTHESIS                 |
       |  - Chống ảo giác: Cấm bịa CVE / CVSS không có trong KB     |
       +------------------------------------------------------------+
```

---

## 2. Các Nguồn Dữ Liệu Có Thẩm Quyền (Authoritative Sources)

Hệ thống chỉ tích hợp dữ liệu từ các tổ chức an ninh tiêu chuẩn quốc tế:

1. **National Vulnerability Database (NVD)**:
   - Cung cấp mã định danh CVE, bản tóm tắt kỹ thuật, vector đánh giá mức độ nghiêm trọng CVSS v3.1 và CVSS v4.0.
   - Ánh xạ liên kết CWE, định danh CPE URI và dải phiên bản sản phẩm bị ảnh hưởng (`version_start_including`, `version_end_excluding`).
2. **MITRE CWE (Common Weakness Enumeration)**:
   - Từ điển phân loại điểm yếu phần mềm, mô tả bản chất kỹ thuật, khả năng bị khai thác (Likelihood of Exploit) và hướng dẫn khắc phục chi tiết (Mitigations).
   - Thiết lập cấu trúc phân cấp kế thừa điểm yếu (Pillar -> Class -> Base -> Variant).
3. **MITRE ATT&CK**:
   - Ánh xạ kỹ thuật và chiến thuật của kẻ tấn công tương ứng với từng dạng lỗ hổng, phục vụ việc mô hình hóa bề mặt tấn công.
4. **CISA KEV (Known Exploited Vulnerabilities)**:
   - Danh mục các lỗ hổng đã bị tin tặc khai thác trong các cuộc tấn công thực tế được Bộ An ninh Nội địa Hoa Kỳ (CISA) xác nhận.
   - Giúp hệ thống tự động nâng mức cảnh báo ưu tiên xử lý khẩn cấp (Action Urgency).

---

## 3. Thuật Toán Đối Soát Phiên Bản Ngữ Nghĩa (Semantic Version Correlator)

Khi trinh sát mục tiêu, các công cụ quét chỉ thu được chuỗi ký tự banner phiên bản (ví dụ: `Apache/2.4.49` hoặc `OpenSSH 8.2p1`). Việc so sánh chuỗi đơn thuần bằng toán tử chuỗi sẽ dẫn tới sai lệch logic nghiêm trọng (ví dụ: chuỗi `"2.4.9"` theo thứ tự chữ cái sẽ lớn hơn `"2.4.49"`).

Hệ thống áp dụng thuật toán phân tách **Numeric Tuple Comparison**:
```python
# Phiên bản "2.4.49" -> (2, 4, 49)
# Phiên bản "2.4.9"  -> (2, 4, 9)
# Kết quả so sánh toán học: (2, 4, 49) > (2, 4, 9) => Chính xác tuyệt đối
```

### Các Mức Độ Tin Cậy Tương Quan (Correlation Confidence Levels)

| Mức Độ | Trọng Số Tin Cậy | Điều Kiện Thỏa Mãn | Nhãn Gán Trong Copilot |
|---|---|---|---|
| **Exact Version Match** | `0.95` | Phiên bản phát hiện trùng khớp chính xác 100% với phiên bản lỗ hổng trong KB | `CONFIRMED / HIGH CONFIDENCE` |
| **Version Range Match** | `0.85` | Phiên bản phát hiện nằm trong dải `[version_start, version_end)` được công bố | `MATCHED IN RANGE` |
| **Product-Only Match** | `0.50` | Chỉ nhận diện được tên sản phẩm/dịch vụ, không trích xuất được phiên bản | `UNVERIFIED VERSION (Gắn cờ cảnh báo)` |

---

## 4. Tích Hợp RAG & Cơ Chế Chống Ảo Giác (Anti-Hallucination)

Trong quy trình phân tích của AI Copilot, phân hệ Correlator đóng vai trò là lớp bảo vệ thực tế (Grounding Layer):
- **Phân loại 3 mức phát ngôn bắt buộc**:
  - **FACT**: Dữ liệu có bằng chứng xác thực trực tiếp từ file quét thô (`raw evidence`).
  - **INFERENCE**: Kết luận suy luận dựa trên việc so khớp phiên bản thực tế với SQLite KB.
  - **HYPOTHESIS**: Các nhận định chưa đủ chứng cứ, bắt buộc phải có bước xác minh an toàn (Safe Verification Probe).
- **Quy tắc chặn ảo giác**: AI Copilot **tuyệt đối không bao giờ** tự sáng tác số hiệu CVE, điểm CVSS hoặc liên kết ngoài. Nếu cơ sở tri thức không có thông tin, hệ thống bắt buộc phản hồi:
  > *"FACT: Insufficient evidence in current scan results or knowledge base to confirm vulnerabilities."*

---

## 5. Danh Mục REST API Tra Cứu Tri Thức

Phân hệ cung cấp đầy đủ các API RESTful phục vụ cả giao diện Web IDE và tích hợp ngoài:

- `GET /api/vulnerabilities/cve/{cve_id}`:
  Trả về chi tiết bản ghi CVE, điểm CVSS, mã CWE, danh sách sản phẩm bị ảnh hưởng và liên kết tham chiếu.
- `GET /api/vulnerabilities/cwe/{cwe_id}`:
  Trả về chi tiết điểm yếu CWE, mức độ nghiêm trọng và phương án khắc phục phòng thủ.
- `GET /api/vulnerabilities/correlate?product={prod}&version={ver}`:
  Thực hiện đối soát tự động, trả về danh sách các CVE liên quan được sắp xếp theo mức độ tin cậy và điểm CVSS.
- `GET /api/vulnerabilities/stats`:
  Trả về số liệu thống kê tổng thể số lượng CVE, CWE, KEV và các bản ghi đã lập chỉ mục trong cơ sở dữ liệu.
- `GET /api/vulnerabilities/search?query={q}`:
  Tìm kiếm toàn văn (Full-text search) theo từ khóa trong phần tóm tắt và mô tả kỹ thuật của CVE.

---

## 6. Tài Liệu Liên Quan

- [Kiến Trúc Tổng Thể Hệ Thống](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md)
- [Mô Hình An Toàn & Guardrails](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md)
- [Cẩm Nang Bộ Công Cụ Pentest](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md)
- [Kịch Bản Demo Chi Tiết](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md)
