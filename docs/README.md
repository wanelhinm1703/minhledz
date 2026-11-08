# Thư Mục Tài Liệu Hệ Thống (Documentation Hub)

> **AI-Pentest Copilot — Trung Tâm Tài Liệu & Cẩm Nang Kỹ Thuật (v5.0)**  
> **Ngôn ngữ chính:** Tiếng Việt (Chuyên ngành An toàn Thông tin & Kỹ thuật Phần mềm)

---

## 1. Danh Mục Tài Liệu Kỹ Thuật (Table of Contents)

Thư mục `docs/` chứa toàn bộ tài liệu đặc tả kiến trúc, nguyên tắc an toàn, danh mục công cụ và kịch bản vận hành của dự án **AI-Pentest Copilot**:

| Tên Tài Liệu | Mô Tả Nội Dung | Đối Tượng Phù Hợp |
|---|---|---|
| [architecture.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md) | **Kiến trúc tổng thể hệ thống**: Phân tách 8 tầng (8 layers), luồng dữ liệu, các service lõi, quy tắc phụ thuộc và mô hình Multi-Agent. | Kiến trúc sư hệ thống, Backend/Frontend Developer |
| [security-model.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md) | **Mô hình an toàn & Guardrails**: 7 quy tắc an toàn cốt lõi, kiểm soát phạm vi ủy quyền (RFC 1918 Scope), tính bất biến của bằng chứng số và cơ chế chống ảo giác. | Chuyên gia An toàn thông tin, Compliance Auditor |
| [target-system.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/target-system.md) | **Hệ thống mục tiêu động & Lab**: Quy trình tiếp nhận mục tiêu động, thẩm định cú pháp, định tuyến công cụ trinh sát theo cổng dịch vụ (Service-driven Routing). | Pentester, Kỹ sư kiểm thử an ninh |
| [toolkit.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md) | **Cẩm nang bộ công cụ Pentest tích hợp**: Ma trận công cụ, các profile thực thi, thư mục lưu bằng chứng, JSON schemas, cơ chế phát hiện xung đột và hướng dẫn mở rộng tool mới. | Pentester, Tool Developer |
| [knowledge-base.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/knowledge-base.md) | **Cơ sở tri thức lỗ hổng & Correlator**: Cấu trúc CSDL SQLite offline (539 CVEs / 52 CWEs), thuật toán so khớp phiên bản ngữ nghĩa (Semantic Version Tuple) và hệ thống REST API tra cứu. | AI/Data Engineer, SecOps |
| [demo_workflow.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md) | **Kịch bản & Workflow Demo chi tiết**: Hướng dẫn từng bước kịch bản demo trực tiếp 15 phút (Live Demo Playbook), cheat sheet thao tác và bộ câu hỏi thường gặp Q&A. | Báo cáo viên, Diễn giả, Giảng viên |

---

## 2. Lộ Trình Đọc Tài Liệu Khuyến Nghị (Reading Pathways)

### 2.1. Dành cho Nhà Phát Triển Mới (New Developers / Contributors)
1. Bắt đầu với [architecture.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/architecture.md) để hiểu cách hệ thống phân chia 8 tầng và quy tắc phụ thuộc.
2. Đọc [target-system.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/target-system.md) để nắm rõ luồng dữ liệu từ lúc nhập IP đến khi lưu bằng chứng scan.
3. Đọc [toolkit.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md) để biết cách tích hợp công cụ pentest mới vào catalog YAML và JSON schema.

### 2.2. Dành cho Chuyên Gia An Toàn Thông Tin (Security Researchers & Pentesters)
1. Đọc kỹ [security-model.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/security-model.md) để hiểu về các giới hạn an toàn (Guardrails) và chính sách kiểm soát phạm vi rà quét.
2. Tham khảo [toolkit.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/toolkit.md) để xem danh sách tham số của các profile quét (`stealth`, `fast`, `comprehensive`, `safe_nse`).
3. Tham khảo [knowledge-base.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/knowledge-base.md) để khai thác các API tra cứu tri thức CVE/CWE ngoại tuyến.

### 2.3. Dành cho Buổi Thuyết Minh & Trình Diễn Sản Phẩm (Demo & Presentation)
1. Đọc và thực hành theo kịch bản chuẩn trong [demo_workflow.md](file:///run/media/ducthuan/54AC7DBAAC7D96E8/Shared/Projects/ai-pentest-copilot/docs/demo_workflow.md).
2. Chuẩn bị bảng tra cứu nhanh (Cheat Sheet) tại Mục 4 của `demo_workflow.md` để tự tin trả lời các câu hỏi từ hội đồng chuyên môn hoặc khách hàng.

---

## 3. Quy Ước & Tiêu Chuẩn Soạn Thảo Tài Liệu

- **Ngôn ngữ**: Sử dụng tiếng Việt rõ ràng, chuẩn văn phong kỹ thuật công nghệ thông tin và an toàn không gian mạng.
- **Thuật ngữ chuyên ngành**: Giữ nguyên các thuật ngữ quốc tế không thể dịch hoặc đã trở thành chuẩn công nghiệp (ví dụ: *Buffer Overflow, Reverse Shell, Null Session, SYN Scan, CVE, CWE, CVSS, RAG, Hash SHA-256*).
- **Liên kết**: Sử dụng đường dẫn tương đối hoặc Markdown link có cấu trúc rõ ràng để tiện truy cập chéo giữa các tài liệu.
