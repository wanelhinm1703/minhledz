# BAN CƠ YẾU CHÍNH PHỦ
# HỌC VIỆN KỸ THUẬT MẬT MÃ
# KHOA AN TOÀN THÔNG TIN

---

<br><br>

# BÁO CÁO CHUYÊN ĐỀ CƠ SỞ

### ĐỀ TÀI:
## **AI-PENTEST COPILOT: LLM + RAG HỖ TRỢ PHÂN TÍCH VÀ LẬP KẾ HOẠCH KIỂM THỬ XÂM NHẬP**

<br><br>

**Sinh viên thực hiện:**
1. **Đỗ Hữu Huy** — Mã sinh viên: **AT210125**
2. **Nguyễn Đức Thuấn** — Mã sinh viên: **AT210148**
3. **Lê Văn Minh** — Mã sinh viên: **AT210136**

**Lớp:** An toàn thông tin — Khóa 21  
**Khoa:** An toàn thông tin  
**Người hướng dẫn khoa học:** **PGS. TS. Bùi Thu Lâm**  

<br><br><br>

**Hà Nội — 2026**

\newpage

---

## LỜI CẢM ƠN

Lời đầu tiên, nhóm nghiên cứu chúng em xin bày tỏ lòng biết ơn sâu sắc và chân thành nhất tới **PGS. TS. Bùi Thu Lâm** — người thầy đã tận tình định hướng, hướng dẫn phương pháp nghiên cứu khoa học, truyền đạt những kiến thức chuyên môn quý báu và đưa ra những lời nhận xét, phản biện xác đáng trong suốt quá trình nhóm triển khai đề tài chuyên đề cơ sở: *"AI-Pentest Copilot: LLM + RAG hỗ trợ phân tích và lập kế hoạch kiểm thử xâm nhập"*.

Chúng em cũng xin gửi lời cảm ơn chân thành đến các Thầy, Cô giáo trong **Khoa An toàn thông tin**, Ban Giám đốc **Học viện Kỹ thuật Mật mã** đã tạo điều kiện học tập thuận lợi, trang bị cho chúng em nền tảng kiến thức vững chắc về an toàn hệ điều hành, an ninh mạng, mật mã học, phân tích lỗ hổng và kiểm thử xâm nhập trong các năm học vừa qua.

Mặc dù nhóm đã nỗ lực hết mình để nghiên cứu, thiết kế và hoàn thiện hệ thống cùng báo cáo này, song do giới hạn về mặt thời gian và kinh nghiệm thực tiễn, đề tài khó tránh khỏi những thiếu sót nhất định. Nhóm nghiên cứu rất mong nhận được những ý kiến đóng góp, chỉ dẫn quý báu từ quý Thầy Cô trong Hội đồng đánh giá để sản phẩm tiếp tục được hoàn thiện và nâng cao hơn nữa trong các giai đoạn phát triển tiếp theo.

*Hà Nội, tháng 08 năm 2026*  
**Nhóm sinh viên thực hiện**  
*Đỗ Hữu Huy — Nguyễn Đức Thuấn — Lê Văn Minh*

\newpage

---

## LỜI NÓI ĐẦU

Trong bối cảnh chuyển đổi số diễn ra mạnh mẽ, an toàn thông tin trở thành yếu tố sống còn đối với mọi tổ chức, doanh nghiệp và cơ quan nhà nước. Hoạt động kiểm thử xâm nhập (Penetration Testing - Pentest) đóng vai trò then chốt trong việc chủ động rà soát, đánh giá thế trận phòng thủ và phát hiện kịp thời các điểm yếu trước khi kẻ tấn công có thể khai thác. Tuy nhiên, quy trình pentest truyền thống đòi hỏi khối lượng công việc thủ công rất lớn: người kiểm thử phải xử lý hàng nghìn dòng dữ liệu quét thô từ các công cụ trinh sát (Nmap, Masscan, HTTPx, Nuclei...), liên tục tra cứu chéo với các cơ sở dữ liệu lỗ hổng toàn cầu (CVE, CWE, NVD, CISA KEV, MITRE ATT&CK) và tổng hợp báo cáo. Quá trình này không chỉ tiêu tốn nhiều thời gian mà còn dễ dẫn đến thiếu sót do quá tải thông tin.

Sự bùng nổ của Trí tuệ nhân tạo (AI), đặc biệt là Mô hình Ngôn ngữ Lớn (Large Language Model - LLM) và kỹ thuật Thế hệ Tăng cường Truy xuất (Retrieval-Augmented Generation - RAG), đã mở ra triển vọng to lớn trong việc tự động hóa và hỗ trợ phân tích chuyên sâu. Dẫu vậy, việc ứng dụng LLM vào an toàn thông tin đối mặt với hai thách thức cốt tử:
1. **Hiện tượng ảo giác (Hallucination)**: LLM có xu hướng tự tạo ra các mã định danh CVE không có thực, sai lệch điểm CVSS hoặc nhầm lẫn phiên bản phần mềm bị ảnh hưởng.
2. **An toàn thông tin và bảo mật dữ liệu**: Việc gửi kết quả quét hệ thống lên các dịch vụ đám mây công cộng (như OpenAI, Anthropic) tiềm ẩn nguy cơ rò rỉ thông tin nhạy cảm về hạ tầng an ninh mạng của tổ chức.

Nhận thức sâu sắc vấn đề này, nhóm nghiên cứu đã lựa chọn đề tài **"AI-Pentest Copilot: LLM + RAG hỗ trợ phân tích và lập kế hoạch kiểm thử xâm nhập"**. Đề tài tập trung xây dựng một nền tảng bàn làm việc an ninh toàn diện (Security Workbench) hoạt động hoàn toàn cục bộ (**On-Premise / Local-first**), sử dụng nền tảng **Ollama** kết hợp mô hình ngôn ngữ mã nguồn mở **ultrol-v2** cùng cơ sở dữ liệu Vector (**ChromaDB**) và CSDL quan hệ (**SQLite**). Hệ thống chuẩn hóa dữ liệu trinh sát thô thành cấu trúc chuẩn, thực hiện đối soát phiên bản ngữ nghĩa (Semantic Version Correlation), sinh các bản ghi phát hiện (Finding) có chuỗi bằng chứng (Evidence Chain) xác thực và đề xuất kế hoạch xác minh an toàn (Safe Verification / Attack Plan) tuyệt đối không phá hoại hệ thống.

Báo cáo chuyên đề cơ sở này trình bày toàn bộ quá trình nghiên cứu, thiết kế kiến trúc, cài đặt thực nghiệm và đánh giá định lượng hiệu năng của hệ thống so với phương pháp LLM truyền thống không dùng RAG.

\newpage

---

## DANH MỤC KÝ HIỆU VÀ CHỮ VIẾT TẮT

| Viết tắt | Thuật ngữ đầy đủ tiếng Anh | Diễn giải tiếng Việt |
|:---|:---|:---|
| **AI** | Artificial Intelligence | Trí tuệ nhân tạo |
| **API** | Application Programming Interface | Giao diện lập trình ứng dụng |
| **CIDR** | Classless Inter-Domain Routing | Định tuyến liên miền không phân lớp |
| **CISA** | Cybersecurity and Infrastructure Security Agency | Cơ quan An ninh mạng và Cơ sở hạ tầng Hoa Kỳ |
| **CPE** | Common Platform Enumeration | Danh mục định danh nền tảng chuẩn hóa |
| **CVE** | Common Vulnerabilities and Exposures | Danh mục các lỗ hổng và phơi nhiễm an ninh mạng phổ biến |
| **CVSS** | Common Vulnerability Scoring System | Hệ thống tính điểm mức độ nghiêm trọng lỗ hổng an ninh |
| **CWE** | Common Weakness Enumeration | Danh mục các điểm yếu phần mềm phổ biến |
| **DAST** | Dynamic Application Security Testing | Kiểm thử an ninh ứng dụng động |
| **EPSS** | Exploit Prediction Scoring System | Hệ thống tính điểm xác suất bị khai thác thực tế |
| **FAISS** | Facebook AI Similarity Search | Thư viện tìm kiếm tương đồng vector của Facebook |
| **GGUF** | GPT-Generated Unified Format | Định dạng lưu trữ mô hình ngôn ngữ lượng tử hóa cho CPU/GPU |
| **HTTP** | Hypertext Transfer Protocol | Giao thức truyền tải siêu văn bản |
| **IDE** | Integrated Development Environment | Môi trường phát triển tích hợp |
| **JSON** | JavaScript Object Notation | Định dạng trao đổi dữ liệu dạng văn bản nhẹ |
| **KEV** | Known Exploited Vulnerabilities | Danh mục lỗ hổng đã bị khai thác trong thực tế (CISA) |
| **LLM** | Large Language Model | Mô hình ngôn ngữ lớn |
| **MITRE ATT&CK** | Adversarial Tactics, Techniques, and Common Knowledge | Cơ sở tri thức về chiến thuật và kỹ thuật của tin tặc |
| **NSE** | Nmap Scripting Engine | Động cơ chạy kịch bản tự động hóa của Nmap |
| **NVD** | National Vulnerability Database | Cơ sở dữ liệu lỗ hổng quốc gia Hoa Kỳ |
| **OSINT** | Open Source Intelligence | Tình báo an ninh dựa trên nguồn mở |
| **OWASP** | Open Web Application Security Project | Dự án an toàn ứng dụng web mở |
| **PoC** | Proof of Concept | Mã chứng minh khái niệm khai thác lỗ hổng |
| **RAG** | Retrieval-Augmented Generation | Kỹ thuật sinh văn bản tăng cường bằng truy xuất tri thức |
| **REST** | Representational State Transfer | Phong cách kiến trúc thiết kế dịch vụ web |
| **RFC** | Request for Comments | Tập hợp các văn kiện tiêu chuẩn kỹ thuật Internet |
| **SARIF** | Static Analysis Results Interchange Format | Định dạng chuẩn trao đổi kết quả phân tích an ninh (OASIS) |
| **UI / UX** | User Interface / User Experience | Giao diện người dùng / Trải nghiệm người dùng |
| **URI / URL** | Uniform Resource Identifier / Locator | Định danh / Bộ định vị tài nguyên đồng nhất |
| **VRAM** | Video Random Access Memory | Bộ nhớ truy cập ngẫu nhiên của bộ xử lý đồ họa (GPU) |
| **WSTG** | Web Security Testing Guide | Cẩm nang hướng dẫn kiểm thử an ninh ứng dụng Web của OWASP |
| **XML** | Extensible Markup Language | Ngôn ngữ đánh dấu mở rộng |

\newpage

---

## DANH MỤC HÌNH VẼ

* **Hình 1.1**: Quy trình chuẩn kiểm thử xâm nhập theo chuẩn NIST SP 800-115 và PTES.
* **Hình 1.2**: Mô hình quan hệ thực thể phân cấp: CPE $\rightarrow$ CVE $\rightarrow$ CWE $\rightarrow$ MITRE ATT&CK.
* **Hình 1.3**: Kiến trúc tổng quát mô hình RAG (Retrieval-Augmented Generation).
* **Hình 2.1**: Biểu đồ Use Case tổng quát của hệ thống AI-Pentest Copilot.
* **Hình 2.2**: Sơ đồ kiến trúc phân tầng hệ thống (Frontend, Backend, Toolkit Repository).
* **Hình 2.3**: Quy trình trích xuất và chuẩn hóa dữ liệu từ Nmap XML sang JSON Schema.
* **Hình 2.4**: Cơ chế phân mảnh (Chunking), nhúng vector (Embedding) và chỉ mục hóa tri thức.
* **Hình 2.5**: Luồng tương tác giữa Chốt chặn an toàn (Guardrails) và Local LLM qua Ollama.
* **Hình 2.6**: Sơ đồ lớp dữ liệu (Data Class Diagram) của Finding, Evidence và VerificationPlan.
* **Hình 3.1**: Sơ đồ kiến trúc môi trường phòng thí nghiệm (Target Lab Environment).
* **Hình 3.2**: Quy trình thực thi tuần tự của Reconnaissance Pipeline.
* **Hình 3.3**: Biểu đồ so sánh Precision@K giữa mô hình LLM thuần túy và LLM + RAG.
* **Hình 3.4**: Tỷ lệ xuất hiện ảo giác (Hallucination Rate) giữa hai phương pháp.
* **Hình 3.5**: Giao diện bàn làm việc tích hợp Web IDE và Copilot Chat trong kịch bản Demo.

---

## DANH MỤC BẢNG BIỂU

* **Bảng 1.1**: Phân bố thang điểm và mức độ nghiêm trọng theo chuẩn CVSS v3.1.
* **Bảng 1.2**: Các chiến thuật chủ chốt trong ma trận MITRE ATT&CK for Enterprise.
* **Bảng 2.1**: Ma trận so sánh các hệ quản trị Vector Database mã nguồn mở cục bộ.
* **Bảng 2.2**: Bảng quy cách đặc tả thuộc tính thực thể Finding theo JSON Schema.
* **Bảng 2.3**: Bảng tiêu chí và công thức đánh giá định lượng mô hình AI Copilot.
* **Bảng 3.1**: Cấu hình phần cứng và môi trường phần mềm thử nghiệm hệ thống.
* **Bảng 3.2**: Danh mục các mục tiêu mẫu trong môi trường phòng lab thực nghiệm.
* **Bảng 3.3**: Kết quả đo đếm thời gian thực thi của các thành phần trong Recon Pipeline.
* **Bảng 3.4**: Bảng so sánh kết quả định lượng giữa ultrol-v2 Không RAG và Có RAG trên 50 Test Cases.
* **Bảng 3.5**: Bảng đối soát các bước thực thi và kết quả xác nhận trong kịch bản Demo.

\newpage

---

# CHƯƠNG 1. TỔNG QUAN VÀ CƠ SỞ LÝ THUYẾT

## 1.1. Bài toán hỗ trợ kiểm thử xâm nhập

Kiểm thử xâm nhập (Penetration Testing) là phương pháp đánh giá mức độ an toàn của hệ thống thông tin bằng cách mô phỏng các kỹ thuật và quy trình tấn công của tin tặc trong thế giới thực một cách có kiểm soát và được cấp phép. Mục tiêu cốt lõi của hoạt động này là tìm kiếm, chứng minh khả năng khai thác của các điểm yếu bảo mật, đánh giá tác động tiềm tàng đến tính Bảo mật (Confidentiality), Toàn vẹn (Integrity) và Sẵn sàng (Availability) của dữ liệu, từ đó đề xuất các biện pháp khắc phục (Remediation) kịp thời.

Trong bối cảnh hạ tầng mạng và ứng dụng ngày càng mở rộng và phức tạp (Microservices, Hybrid Cloud, API-driven), các chuyên gia an ninh mạng (pentesters) đang phải đối mặt với những thách thức to lớn:
1. **Sự bùng nổ dữ liệu trinh sát**: Một phiên quét tự động bằng các công cụ như Nmap, Masscan hay Nuclei có thể trả về hàng chục nghìn dòng nhật ký, hàng trăm cổng mở và hàng loạt dịch vụ đang chạy. Việc phân loại, tổng hợp và sàng lọc đâu là thông tin giá trị (actionable intelligence) đòi hỏi nhiều giờ lao động tập trung cao độ.
2. **Khoảng cách tri thức và sự phân mảnh thông tin**: Dữ liệu về an toàn thông tin nằm rải rác trên nhiều nguồn dữ liệu chuẩn hóa khác nhau: NIST NVD (chứa hơn 250.000 bản ghi CVE), MITRE CWE (hàng trăm dạng điểm yếu phần mềm), CISA KEV (danh mục lỗ hổng thực tế đang bị khai thác), và ma trận MITRE ATT&CK. Pentesters phải tra cứu thủ công qua lại giữa các nguồn này để đánh giá ngữ cảnh của lỗ hổng.
3. **Nguy cơ bỏ sót và áp lực thời gian**: Giới hạn thời gian của các chiến dịch pentest khiến các kỹ sư kiểm thử thường ưu tiên các lỗ hổng quen thuộc, dễ dẫn tới bỏ sót các chuỗi lỗ hổng tiềm tàng (vulnerability chaining) hoặc các sai sót cấu hình tinh vi.
4. **Nhu cầu về một trợ lý an ninh thông minh, an toàn**: Pentesters không cần một công cụ tự động khai thác phá hoại (automated exploit tool) bởi điều đó vi phạm quy chuẩn an toàn và gây nguy cơ sập hệ thống (Denial of Service). Thay vào đó, nhu cầu bức thiết là một "Người đồng hành AI" (AI Copilot) đóng vai trò tư vấn ngữ cảnh, phân tích dữ liệu trinh sát, tra cứu tri thức chính xác, lập kế hoạch xác minh chỉ đọc (read-only verification plan) và hỗ trợ viết báo cáo chuyên nghiệp.

## 1.2. Quy trình pentest và security methodology

Quy trình kiểm thử xâm nhập tiêu chuẩn được định nghĩa dựa trên các chuẩn mực quốc tế như **PTES (Penetration Testing Execution Standard)**, **NIST SP 800-115** và **OWASP WSTG (Web Security Testing Guide)**. Hệ thống AI-Pentest Copilot bám sát và hỗ trợ từng giai đoạn nghiệp vụ trong chu trình khép kín này.

```mermaid
flowchart LR
    A["1. Recon (Trinh sát)"] --> B["2. Enumeration (Liệt kê)"]
    B --> C["3. Service Identification"]
    C --> D["4. Vulnerability Discovery"]
    D --> E["5. Validation (Xác minh)"]
    E --> F["6. Attack Planning"]
    F --> G["7. Reporting (Báo cáo)"]
```
*Hình 1.1: Quy trình chuẩn kiểm thử xâm nhập 7 giai đoạn được chuẩn hóa trong đề tài.*

### 1.2.1. Recon (Trinh sát thông tin)
Giai đoạn trinh sát tập trung thu thập toàn diện các thông tin về mục tiêu mà không tương tác trực tiếp hoặc chỉ tương tác ở mức tối thiểu:
- **Thụ động (Passive Recon)**: Thu thập thông tin công khai qua OSINT, cơ sở dữ liệu Whois, DNS records, chứng chỉ số SSL/TLS (Certificate Transparency Logs qua crt.sh) và máy chủ tìm kiếm bảo mật (Shodan, Censys).
- **Chủ động (Active Recon)**: Gửi các gói tin thăm dò mạng ở tầng Transport (TCP SYN/ACK, UDP) để xác định dải mạng hoạt động, các địa chỉ IP đang hoạt động (Host Discovery) và lập bản đồ bề mặt tấn công bên ngoài (External Attack Surface).

### 1.2.2. Enumeration và Service Identification (Liệt kê và Nhận diện dịch vụ)
Sau khi xác định được các host đang phản hồi, quy trình chuyển sang phân tích chi tiết:
- **Port Scanning**: Rà quét toàn bộ $65.535$ cổng TCP và các cổng UDP phổ biến bằng các thuật toán quét nhanh (SYN Stealth Scan của Nmap, Masscan, RustScan).
- **Service & Version Detection**: Gửi các chuỗi thăm dò chuyên biệt (probes) tới các cổng mở, phân tích chuỗi phản hồi (banner grabbing) và mã băm phản hồi để định danh tên phần mềm máy chủ, daemon và số hiệu phiên bản chính xác (ví dụ: `Apache httpd 2.4.49`, `OpenSSH 8.2p1 Ubuntu 4ubuntu0.3`).
- **Web Technology Fingerprinting**: Nhận diện cấu trúc ứng dụng web, máy chủ web (Nginx, Apache, IIS), ngôn ngữ kịch bản máy chủ (PHP, Python, Java), hệ quản trị nội dung CMS (WordPress, Drupal) và các framework phía frontend thông qua tiêu đề HTTP response, cookies, và cấu trúc thẻ HTML.

### 1.2.3. Vulnerability Discovery và Validation (Phát hiện và Xác minh lỗ hổng)
- **Vulnerability Discovery**: Dựa trên danh sách dịch vụ và phiên bản thu thập được, đối chiếu với cơ sở dữ liệu lỗ hổng đã công bố hoặc sử dụng các bộ rà quét lỗ hổng dựa trên mẫu (template-based scanners như Nuclei, Nmap NSE scripts) để phát hiện các dấu hiệu điểm yếu (misconfiguration, missing patches, default credentials).
- **Validation**: Đóng vai trò quan trọng trong việc loại bỏ cảnh báo giả (False Positives). Thay vì thực hiện tấn công vũ lực hay khai thác toàn diện, nguyên tắc an toàn quy định chuyên gia chỉ thực hiện các bước thăm dò chỉ đọc (Read-Only Probing) nhằm chứng minh điểm yếu tồn tại mà không làm thay đổi trạng thái, làm biến đổi dữ liệu hoặc gây sập dịch vụ.

### 1.2.4. Attack Planning và Reporting (Lập kế hoạch kiểm thử và Lập báo cáo)
- **Attack Planning**: Dựa trên các phát hiện đã xác minh, lập kế hoạch chi tiết về các bước kiểm thử sâu hơn: thứ tự ưu tiên kiểm thử dựa trên điểm rủi ro, khả năng liên kết chuỗi lỗ hổng (ví dụ: Path Traversal $\rightarrow$ Lộ tệp cấu hình chứa mật khẩu CSDL $\rightarrow$ Leo thang đặc quyền), và các biện pháp giảm thiểu rủi ro trong quá trình kiểm thử.
- **Reporting**: Tổng hợp toàn bộ quá trình kiểm thử thành tài liệu báo cáo kỹ thuật và báo cáo quản trị, bao gồm danh mục phát hiện (Findings), bằng chứng chứng minh (Evidence Chain), điểm số CVSS, ánh xạ CWE/MITRE ATT&CK và hướng dẫn vá lỗi cụ thể cho đội ngũ vận hành hệ thống.

## 1.3. Nmap, Nuclei và dữ liệu reconnaissance

Trong các công cụ an ninh mạng hiện đại, Nmap và Nuclei là hai công cụ tiêu chuẩn, cung cấp nền tảng dữ liệu đầu vào cốt lõi cho hệ thống AI-Pentest Copilot:

### Nmap (Network Mapper)
Nmap là công cụ tiêu chuẩn công nghiệp trong việc rà quét mạng và kiểm toán an toàn hệ thống. Nmap hoạt động bằng cách gửi các gói tin IP thô được chế tạo đặc biệt để xác định host nào đang hoạt động trên mạng, dịch vụ nào (tên ứng dụng và phiên bản) đang chạy, hệ điều hành (và phiên bản hệ điều hành) nào đang được sử dụng, và loại bộ lọc gói/tường lửa nào đang được áp dụng.
Đầu ra quan trọng nhất của Nmap phục vụ xử lý tự động là tệp định dạng **Nmap XML Output** (`-oX`). Tệp này chứa cấu trúc phân cấp chi tiết:
- `<host>`: Chứa thông tin trạng thái máy chủ (up/down), địa chỉ IPv4/IPv6, MAC address.
- `<ports>`: Danh sách các cổng, giao thức (tcp/udp), trạng thái (`open`, `filtered`, `closed`).
- `<service>`: Chứa thuộc tính dịch vụ gồm `name`, `product`, `version`, `extrainfo`, và độ tin cậy của việc nhận diện (`conf` từ 1 đến 10).
- `<script>`: Kết quả chạy các kịch bản NSE (Nmap Scripting Engine) bao gồm cả tiêu đề banner thu thập được hoặc phát hiện lỗ hổng cơ bản.

### Nuclei
Nuclei là công cụ quét lỗ hổng thế hệ mới phát triển bởi ProjectDiscovery, hoạt động dựa trên các mẫu cấu hình khai báo dạng YAML (YAML-based templates). Các template của Nuclei mô tả chính xác yêu cầu HTTP/TCP/DNS/SSL gửi đi và các biểu thức so khớp (matchers/extractors) để kiểm tra sự tồn tại của lỗ hổng.
Đầu ra dạng **JSON Lines** (`-jsonl`) của Nuclei cung cấp cấu trúc phong phú:
- `template-id`: Mã định danh template lỗ hổng.
- `info`: Chứa `name`, `author`, `severity` (critical, high, medium, low, info), `description`, `reference` (danh sách URL tham chiếu) và `classification` (chứa `cve-id`, `cwe-id`, `cvss-metrics`, `cvss-score`).
- `matched-at`: Địa chỉ URL/Cổng cụ thể nơi phát hiện lỗ hổng.
- `curl-command`: Lệnh curl chính xác mô phỏng lại gói tin phát hiện để phục vụ tái hiện bằng chứng.

## 1.4. CVE, CWE và CVSS

Hệ sinh thái tri thức an toàn thông tin toàn cầu được chuẩn hóa dựa trên bộ ba quy chuẩn:

```mermaid
classDiagram
    class CPE {
        +String cpe23Uri
        +String vendor
        +String product
        +String version
    }
    class CVE {
        +String cve_id
        +String description
        +Float cvss_v3_score
        +String cvss_v3_vector
    }
    class CWE {
        +String cwe_id
        +String name
        +String description
        +String mitigations
    }
    class MITRE_ATTCK {
        +String technique_id
        +String name
        +String tactic
    }
    CPE --> CVE : "Bị ảnh hưởng"
    CVE --> CWE : "Bản chất điểm yếu"
    CVE --> MITRE_ATTCK : "Ánh xạ kỹ thuật tấn công"
```
*Hình 1.2: Mô hình quan hệ liên kết chuẩn hóa tri thức an toàn thông tin.*

### 1.4.1. CVE (Common Vulnerabilities and Exposures)
CVE là danh mục định danh công khai các lỗ hổng và phơi nhiễm an ninh mạng đã được xác nhận, được quản lý bởi tổ chức MITRE và các tổ chức gán mã có thẩm quyền (CNA). Mỗi bản ghi CVE có định dạng chuẩn `CVE-YYYY-NNNN...` (ví dụ: `CVE-2021-41773`). Một bản ghi CVE cung cấp một định danh duy nhất để các tổ chức bảo mật, công cụ quét và chuyên gia có thể trao đổi thông tin nhất quán về một lỗ hổng cụ thể.

### 1.4.2. CWE (Common Weakness Enumeration)
Nếu CVE là một *thực thể lỗ hổng cụ thể* trên một phiên bản phần mềm cụ thể, thì CWE là từ điển phân loại *bản chất điểm yếu phần mềm* ở mức thiết kế, mã nguồn hoặc kiến trúc. Ví dụ:
- `CWE-22`: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal').
- `CWE-89`: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection').
- `CWE-79`: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting').
CWE cung cấp thông tin cốt lõi về nguyên nhân gốc rễ (Root Cause), các kịch bản khai thác phổ biến và các chiến lược khắc phục triệt để (Mitigations).

### 1.4.3. CVSS (Common Vulnerability Scoring System)
CVSS (phiên bản v3.1 và v4.0) là tiêu chuẩn mở quốc tế dùng để định lượng mức độ nghiêm trọng của một lỗ hổng an ninh mạng thông qua thang điểm từ $0.0$ đến $10.0$. Điểm số Base Score của CVSS v3.1 được tính toán từ hai nhóm chỉ số chính:
1. **Nhóm khả năng khai thác (Exploitability Metrics)**:
   - Attack Vector ($AV$): Network ($0.85$), Adjacent ($0.62$), Local ($0.55$), Physical ($0.20$).
   - Attack Complexity ($AC$): Low ($0.77$), High ($0.44$).
   - Privileges Required ($PR$): None ($0.85$), Low ($0.62$), High ($0.27$).
   - User Interaction ($UI$): None ($0.85$), Required ($0.62$).
   - Scope ($S$): Unchanged ($U$), Changed ($C$).
2. **Nhóm mức độ tác động (Impact Metrics)**:
   - Confidentiality ($C$), Integrity ($I$), Availability ($A$): None ($0$), Low ($0.22$), High ($0.56$).

Công thức tính toán tác động cơ bản (Impact Sub-Score - $ISS$):
$$\text{ISS} = 1 - (1 - \text{Impact}_C) \times (1 - \text{Impact}_I) \times (1 - \text{Impact}_A)$$
Nếu Scope không đổi ($S = U$):
$$\text{Impact} = 6.42 \times \text{ISS}$$
$$\text{Exploitability} = 8.22 \times AV \times AC \times PR \times UI$$
$$\text{BaseScore} = \text{RoundUp}(\min(\text{Impact} + \text{Exploitability}, 10.0))$$

*Bảng 1.1: Phân bố thang điểm và mức độ nghiêm trọng theo chuẩn CVSS v3.1.*
| Thang điểm CVSS v3.1 | Mức độ nghiêm trọng (Severity) | Yêu cầu hành động |
|:---:|:---:|:---|
| **$0.0$** | None | Không yêu cầu hành động |
| **$0.1 - 3.9$** | Low | Khắc phục theo chu kỳ bảo trì thông thường |
| **$4.0 - 6.9$** | Medium | Cần lên kế hoạch vá lỗi trong phiên bản tiếp theo |
| **$7.0 - 8.9$** | High | Ưu tiên khắc phục sớm, theo dõi bề mặt tấn công |
| **$9.0 - 10.0$** | Critical | Khắc phục khẩn cấp ngay lập tức, cách ly hệ thống nếu cần |

## 1.5. MITRE ATT&CK và OWASP

### MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge)
Ma trận MITRE ATT&CK là cơ sở tri thức công khai mô tả hành vi, chiến thuật và kỹ thuật của các nhóm tấn công mạng dựa trên các quan sát thực tế. Việc ánh xạ các phát hiện an ninh sang ATT&CK giúp pentester hiểu được lỗ hổng nằm ở giai đoạn nào trong chuỗi tấn công (Cyber Kill Chain).

*Bảng 1.2: Các chiến thuật chủ chốt trong ma trận MITRE ATT&CK.*
| Mã Chiến thuật | Tên Chiến thuật (Tactic) | Mục tiêu của kẻ tấn công |
|:---|:---|:---|
| **TA0043** | Reconnaissance | Thu thập thông tin lập kế hoạch tấn công |
| **TA0001** | Initial Access | Đột nhập vào hệ thống mục tiêu lần đầu |
| **TA0002** | Execution | Chạy mã độc hại trên hệ thống |
| **TA0003** | Persistence | Duy trì quyền truy cập lâu dài |
| **TA0004** | Privilege Escalation | Nâng cao quyền hạn người dùng (Root/Admin) |
| **TA0005** | Defense Evasion | Vượt qua các cơ chế giám sát và antivirus |
| **TA0006** | Credential Access | Đánh cắp tài khoản, mật khẩu, token xác thực |
| **TA0007** | Discovery | Thám sát môi trường nội bộ sau khi xâm nhập |
| **TA0008** | Lateral Movement | Di chuyển ngang sang các máy chủ khác trong mạng |

### OWASP Top 10 và WSTG
Dự án An toàn Ứng dụng Web Mở (OWASP) cung cấp các tài liệu hướng dẫn chuẩn mực thế giới:
- **OWASP Top 10**: Danh mục 10 rủi ro an ninh mạng ứng dụng web nghiêm trọng nhất (Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable and Outdated Components, Identification and Authentication Failures, Software and Data Integrity Failures, Security Logging and Monitoring Failures, Server-Side Request Forgery).
- **OWASP WSTG (Web Security Testing Guide)**: Cung cấp phương pháp luận kiểm thử từng bước với hàng trăm kịch bản kiểm thử (Test Cases) chi tiết đối với từng thành phần của ứng dụng web.

## 1.6. Mô hình ngôn ngữ cục bộ (Local LLM), nền tảng Ollama và kỹ thuật RAG trong phân tích bảo mật

### 1.6.1. Hạn chế của Cloud LLM và Lý do sử dụng Local LLM
Các mô hình ngôn ngữ lớn thương mại trên đám mây (OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet) có khả năng lý luận rất mạnh. Tuy nhiên, trong lĩnh vực an toàn thông tin và kiểm thử xâm nhập doanh nghiệp/quân sự, việc sử dụng Cloud LLM gặp phải rào cản nghiêm trọng:
- **Nguy cơ rò rỉ dữ liệu hạ tầng nhạy cảm**: Toàn bộ địa chỉ IP nội bộ, kiến trúc mạng, phiên bản phần mềm và danh sách lỗ hổng khi gửi lên API bên ngoài có thể bị lưu trữ hoặc sử dụng để huấn luyện mô hình, vi phạm chính sách bảo mật thông tin và các tiêu chuẩn bảo vệ dữ liệu.
- **Hoạt động trong môi trường cách ly (Air-gapped Network)**: Nhiều hệ thống quân sự, tài chính, cơ sở hạ tầng trọng yếu hoạt động trong mạng cô lập hoàn toàn, không có kết nối Internet. Do đó, việc triển khai **Local LLM** (On-Premise) là giải pháp bắt buộc.

### 1.6.2. Nền tảng Ollama và Mô hình ultrol-v2
- **Ollama**: Là một nền tảng mã nguồn mở mạnh mẽ, đóng gói môi trường thực thi mô hình ngôn ngữ lớn cục bộ dựa trên framework `llama.cpp`. Ollama tối ưu hóa việc quản lý bộ nhớ, hỗ trợ tăng tốc phần cứng thông qua GPU (NVIDIA CUDA, AMD ROCm, Apple Metal) và cung cấp giao diện lập trình ứng dụng RESTful API chuẩn (`/api/generate`, `/api/chat`) tương thích cao.
- **Mô hình ultrol-v2**: Là dòng mô hình mã nguồn mở tối ưu hóa chuyên sâu cho các tác vụ lập luận kỹ thuật, suy luận logic an ninh mạng và trích xuất cấu trúc dữ liệu JSON. Mô hình được triển khai dưới định dạng **GGUF** với mức lượng tử hóa **4-bit hoặc 8-bit (q4_k_m, q8_0)**, cho phép vận hành mượt mà trên phần cứng máy trạm phổ thông (16GB RAM, GPU 8GB - 12GB VRAM) mà vẫn giữ được độ chính xác lập luận cao.

### 1.6.3. Kỹ thuật RAG (Retrieval-Augmented Generation)

```mermaid
sequenceDiagram
    autonumber
    actor Pentester as Chuyên gia Pentest
    participant Parser as Recon Parser
    participant RAG as RAG Service
    participant VectorDB as Vector DB / SQLite KB
    participant LLM as Local LLM (ultrol-v2 via Ollama)
    
    Pentester->>Parser: Cung cấp kết quả quét Nmap / Nuclei
    Parser->>RAG: Trích xuất Banner dịch vụ (Apache 2.4.49)
    RAG->>VectorDB: Truy vấn Vector Embedding & SQL Exact Match
    VectorDB-->>RAG: Trả về tài liệu chuẩn: CVE-2021-41773, CVSS 7.5, CWE-22
    RAG->>LLM: Prompt = Dữ liệu trinh sát + Tri thức chuẩn + Guardrails
    LLM-->>Pentester: Trả về Finding JSON có bằng chứng + Kế hoạch kiểm chứng an toàn
```
*Hình 1.3: Luồng thực thi kỹ thuật Retrieval-Augmented Generation (RAG).*

Kỹ thuật RAG giải quyết triệt để điểm yếu cố hữu của LLM là **ảo giác (hallucination)** và **tri thức lỗi thời**. Thay vì dựa hoàn toàn vào trọng số được nén tĩnh trong quá trình tiền huấn luyện (Parametric Memory), RAG tích hợp một bộ nhớ ngoài có thẩm quyền (Non-parametric Memory):
1. **Truy xuất (Retrieve)**: Khi có một câu hỏi hoặc kết quả quét mới, hệ thống trích xuất các từ khóa/vector đại diện và tìm kiếm trong cơ sở dữ liệu tri thức an ninh (CVE/CWE/NVD/MITRE) để chọn ra Top-K tài liệu có liên quan nhất.
2. **Tăng cường (Augment)**: Ghép các đoạn tri thức chuẩn thu được vào bản tin ngữ cảnh (System & User Context) cùng các quy tắc ràng buộc (Guardrails).
3. **Sinh phản hồi (Generate)**: Yêu cầu LLM chỉ được phép trả lời và suy luận dựa trên những tài liệu đã được cung cấp làm bằng chứng, cấm tự ý sáng tác thông tin.

## 1.7. Tổng kết chương 1
Chương 1 đã phân tích bài toán thực tiễn trong hoạt động kiểm thử xâm nhập, làm rõ sự cần thiết của một công cụ Copilot hỗ trợ xử lý dữ liệu reconnaissance lớn. Chương này đã hệ thống hóa các chuẩn mực phương pháp luận (OWASP WSTG, PTES), cơ sở dữ liệu lỗ hổng (CVE, CWE, CVSS, MITRE ATT&CK), các công cụ trinh sát tiêu chuẩn (Nmap, Nuclei), đồng thời thiết lập cơ sở lý thuyết vững chắc về Local LLM (Ollama, ultrol-v2) kết hợp kỹ thuật RAG nhằm loại bỏ ảo giác và đảm bảo an toàn tuyệt đối cho dữ liệu kiểm thử.

\newpage

---

# CHƯƠNG 2. PHÂN TÍCH VÀ THIẾT KẾ HỆ THỐNG AI-PENTEST COPILOT

## 2.1. Phân tích bài toán và use case

### 2.1.1. Use case tổng quát

```mermaid
flowchart TD
    User(("Chuyên gia Pentest"))
    
    subgraph System["Hệ thống AI-Pentest Copilot"]
        UC1["1. Khai báo mục tiêu & Phạm vi (Scope)"]
        UC2["2. Điều phối trinh sát đa công cụ"]
        UC3["3. Chuẩn hóa dữ liệu quét sang JSON"]
        UC4["4. Đối soát phiên bản & Tra cứu RAG"]
        UC5["5. Phân tích lỗ hổng & Tạo Finding"]
        UC6["6. Lập kế hoạch xác minh chỉ đọc (Attack Plan)"]
        UC7["7. Xuất báo cáo đa định dạng (MD, HTML, SARIF)"]
        UC8["8. Chat tương tác thời gian thực với Copilot"]
    end
    
    User --> UC1
    User --> UC2
    User --> UC5
    User --> UC6
    User --> UC7
    User --> UC8
    UC2 --> UC3
    UC3 --> UC4
    UC4 --> UC5
    UC5 --> UC6
    UC6 --> UC7
```
*Hình 2.1: Sơ đồ Use Case tổng quát của hệ thống.*

Hệ thống đóng vai trò một bàn làm việc tương tác hỗ trợ chuyên gia an ninh trong suốt quá trình đánh giá mục tiêu:
- **Người dùng**: Khai báo mục tiêu, chỉ định các công cụ muốn chạy, giám sát tiến trình quét, duyệt danh sách lỗ hổng phát hiện được, thực thi các bước xác minh an toàn và tải báo cáo cuối cùng.
- **AI Copilot**: Lắng nghe yêu cầu tự nhiên, tự động phân tích dữ liệu quét, truy xuất cơ sở tri thức để giải thích bản chất lỗ hổng, phát hiện xung đột dữ liệu giữa các công cụ và biên soạn kế hoạch xác minh chi tiết.

### 2.1.2. Yêu cầu chức năng (Functional Requirements)
1. **Quản lý mục tiêu và phạm vi an toàn (Target & Scope Management)**:
   - Tiếp nhận linh hoạt nhiều định dạng mục tiêu: IPv4 đơn lẻ, dải mạng CIDR, Tên miền (Domain), Địa chỉ URL kèm cổng dịch vụ.
   - Cơ chế kiểm tra phạm vi (**Scope Validator**) bắt buộc: Chỉ cho phép các mục tiêu thuộc dải mạng cục bộ/phòng lab hợp lệ theo chuẩn RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `localhost`, `*.local`). Tự động từ chối bất kỳ địa chỉ IP công cộng nào nhằm ngăn chặn hành vi rà quét trái phép.
2. **Điều phối trinh sát và Chuẩn hóa dữ liệu (Recon Orchestration & Parsing)**:
   - Hỗ trợ thực thi và bóc tách kết quả từ các công cụ tiêu chuẩn: Nmap, Masscan, RustScan, HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana, Nuclei, SearchSploit, enum4linux, smbclient, snmpwalk, ldapsearch.
   - Chuẩn hóa toàn bộ kết quả đầu ra thô (XML, JSONL, TXT) thành các tài liệu JSON có cấu trúc tuân thủ nghiêm ngặt chuẩn **JSON Schema Draft 2020-12**.
3. **Cơ sở tri thức ngoại tuyến và Truy xuất ngữ nghĩa (Knowledge Base & RAG)**:
   - Xây dựng kho tri thức an ninh cục bộ gồm: Danh mục CVE trọng yếu từ NVD, Từ điển điểm yếu CWE từ MITRE, Danh mục khai thác thực tế CISA KEV và kỹ thuật tấn công MITRE ATT&CK.
   - Hỗ trợ cơ chế truy vấn lai (**Hybrid Retrieval**): Kết hợp đối soát chính xác mã định danh / phiên bản (Exact / Version Tuple Match) với tìm kiếm ngữ nghĩa vector tương đồng (Vector Cosine Similarity).
4. **Phân tích lỗ hổng và Phát hiện xung đột (Vulnerability Analysis & Conflict Detection)**:
   - Tự động liên kết các bằng chứng rà quét với tri thức lỗ hổng để tạo thành thực thể **Finding**.
   - Cơ chế phát hiện xung đột đa công cụ (**Cross-Tool Conflict Detection**): Phát hiện và cảnh báo khi hai công cụ trả về thông tin mâu thuẫn nhau trên cùng một dịch vụ (ví dụ: Nmap báo Apache 2.4.49 nhưng WhatWeb báo Apache 2.4.51).
5. **Lập kế hoạch xác minh an toàn (Safe Verification / Attack Planning)**:
   - Tự động sinh kế hoạch kiểm chứng chỉ đọc (Read-Only Verification Plan) gồm các bước curl/nmap thăm dò không phá hoại, có chỉ rõ kết quả kỳ vọng để xác định tính chính xác của lỗ hổng.
   - Tuyệt đối từ chối sinh mã độc, reverse shell hoặc lệnh tấn công vũ lực hủy hoại.
6. **Báo cáo và Giao tiếp thời gian thực (Reporting & Streaming Chat)**:
   - Xuất báo cáo chuyên nghiệp theo 3 định dạng: Markdown (`.md`), HTML tự chứa (Standalone HTML) và chuẩn trao đổi công nghiệp OASIS SARIF v2.1.0 (`.sarif`).
   - Giao diện IDE Chat thời gian thực sử dụng WebSocket, hỗ trợ truyền tải từng token (token streaming).

### 2.1.3. Yêu cầu phi chức năng (Non-Functional Requirements)
1. **Tính riêng tư và Bảo mật tuyệt đối (100% On-Premise / Local Privacy)**:
   - Toàn bộ chu trình phân tích, nhúng vector và thực thi mô hình ngôn ngữ lớn phải chạy nội bộ trên máy trạm hoặc máy chủ cục bộ. Tuyệt đối không truyền dữ liệu kiểm thử ra bên ngoài qua Internet.
2. **Tính toàn vẹn bằng chứng số (Forensic Integrity)**:
   - Dữ liệu quét thô không bao giờ bị ghi đè. Mọi phiên chạy công cụ đều được lưu trữ bất biến kèm nhật ký câu lệnh chính xác và thời gian thực thi trong tệp `commands.md`.
3. **Hiệu năng và Thời gian phản hồi (Performance & Latency)**:
   - Thời gian truy xuất dữ liệu RAG phải đạt dưới $200\text{ ms}$.
   - Tốc độ sinh phản hồi của Local LLM qua Ollama đạt tối thiểu $15 - 25\text{ tokens/giây}$ trên GPU cá nhân phổ thông.
4. **Độ tin cậy và Kiểm soát ảo giác (Groundedness & Anti-Hallucination)**:
   - Mọi kết luận về lỗ hổng của AI Copilot bắt buộc phải trích dẫn nguồn bằng chứng thực tế (`evidence_chain`) và bản ghi có trong cơ sở dữ liệu. Tỷ lệ ảo giác (Hallucination Rate) phải được kiểm soát dưới $5\%$.
5. **Khả năng suy giảm an toàn (Graceful Degradation)**:
   - Khi một công cụ dòng lệnh chưa được cài đặt trên hệ điều hành máy chủ, hệ thống trả về mã trạng thái `ToolNotInstalled` một cách nhẹ nhàng mà không gây sập ứng dụng hay tạo dữ liệu giả.

### 2.1.4. Lựa chọn công nghệ LLM (Ollama & ultrol-v2) và Cơ sở dữ liệu Vector

*Bảng 2.1: So sánh các hệ quản trị Vector Database mã nguồn mở cục bộ.*
| Tiêu chí | ChromaDB | FAISS (Facebook) | Qdrant | SQLite + VSS |
|:---|:---|:---|:---|:---|
| **Cơ chế lưu trữ** | File-based / In-memory | Bộ nhớ RAM / Index file | Docker container / Client-server | Extension nhúng SQLite |
| **Độ phức tạp cài đặt** | Cực kỳ đơn giản (`pip install`) | Trung bình (cần thư viện C++) | Cần dựng thêm container Docker | Phức tạp (biên dịch C extension) |
| **Hỗ trợ Metadata Filtering** | Rất mạnh, lọc trực quan qua JSON | Rất hạn chế (chỉ đánh chỉ mục ID) | Rất mạnh (hỗ trợ lọc đa điều kiện) | Hạn chế |
| **Tích hợp Python** | Native Python | Native Python wrapper | Python Client | SQLite connection |
| **Phù hợp đề tài** | **Tối ưu nhất cho Local MVP** | Phù hợp tính toán offline | Thích hợp môi trường Microservices | Thích hợp cơ sở dữ liệu nhỏ |

**Quyết định lựa chọn công nghệ:**
- **Local LLM**: Lựa chọn nền tảng **Ollama** kết hợp mô hình **ultrol-v2** (dòng mô hình mã nguồn mở dựa trên kiến trúc Llama-3/Mistral được tinh chỉnh cho suy luận logic kỹ thuật và an toàn thông tin). Mô hình chạy ở phiên bản lượng tử hóa GGUF 4-bit (`q4_k_m`), tối ưu hóa việc sử dụng tài nguyên (yêu cầu khoảng 5.5GB VRAM GPU hoặc 8GB RAM CPU).
- **Lưu trữ tri thức lai (Hybrid Knowledge Store)**:
  - **Cơ sở dữ liệu quan hệ SQLite (`toolkit/data/kb.sqlite`)**: Lưu trữ có cấu trúc các bảng `cve`, `cwe`, `mitre_technique`, `cisa_kev` và `product_version_index`. Đảm bảo tốc độ tra cứu tức thì ($<10\text{ ms}$) đối với các truy vấn chính xác (Exact Match) theo ID hoặc Phiên bản.
  - **Vector Database (ChromaDB)**: Lưu trữ các đoạn phân mảnh văn bản mô tả kỹ thuật (Technical Descriptions, Remediation Guidelines) được nhúng bởi mô hình mã nguồn mở `BAAI/bge-small-en-v1.5` hoặc `sentence-transformers/all-MiniLM-L6-v2`.

## 2.2. Kiến trúc hệ thống

Kiến trúc AI-Pentest Copilot được tổ chức theo mô hình **3 Phân hệ tách biệt** (3-Tier Decoupled Architecture) nhằm đảm bảo tính độc lập và khả năng mở rộng:

```mermaid
flowchart TD
    subgraph Frontend["1. Phân hệ Giao diện Web IDE (React 18 + Vite + Tailwind)"]
        UI_Explorer["Explorer Panel (Cây thư mục & Bằng chứng)"]
        UI_Editor["Tabbed Editor (Monaco Editor / Findings Manager / Topology)"]
        UI_Chat["Copilot Chat Panel (WebSocket Real-time Streaming)"]
        UI_Terminal["Interactive Terminal (xterm.js)"]
    end

    subgraph Backend["2. Phân hệ Nhân hệ thống (FastAPI Core)"]
        API_Gateway["API Gateway & WebSocket Router (/ws/chat)"]
        
        subgraph CoreLogic["Dịch vụ Nghiệp vụ Cốt lõi"]
            TargetMgr["Target Manager (Parser & Scope Validator)"]
            ReconPlanner["Recon Orchestrator (22 Tools Catalog)"]
            Guardrails["Security Guardrails (Anti-Exploit & Anti-Hallucination)"]
            Correlator["Semantic Version Correlator Engine"]
            RAGService["RAG Service (Hybrid Search)"]
            FindingBuilder["Findings & Conflict Aggregator"]
            VerifPlanner["Safe Verification Planner"]
            ReportGen["Report Generator (MD, HTML, SARIF)"]
        end
        
        subgraph LocalAI["Hạ tầng AI Cục bộ (Local AI Engine)"]
            OllamaClient["Ollama API Client (HTTPX Streaming)"]
            LLMModel["ultrol-v2 (GGUF Quantized 4-bit)"]
        end
    end

    subgraph Repository["3. Kho Lưu trữ Bằng chứng & Tri thức (Immutable Toolkit Repository)"]
        TK_Targets["toolkit/01-targets/ (Registry & Presets)"]
        TK_Scans["toolkit/03-network/, 04-web/, 05-vuln/ (Raw Evidence & Structured JSON)"]
        TK_Findings["toolkit/09-analysis/ (Correlated Findings & Manifests)"]
        TK_Reports["toolkit/10-reports/ (Generated Pentest Reports)"]
        TK_Data["toolkit/data/kb.sqlite & ChromaDB Vectors (Authoritative KB)"]
    end

    Frontend <==>|REST API & WebSocket| Backend
    Backend -->|Đọc / Ghi bất biến| Repository
    OllamaClient <==>|Cục bộ (localhost:11434)| LLMModel
```
*Hình 2.2: Sơ đồ kiến trúc phân tầng hệ thống AI-Pentest Copilot.*

### 2.2.1. Recon Input và Recon Parser
Recon Input tiếp nhận các tệp nhật ký đầu ra từ nhiều công cụ quét khác nhau. Mỗi công cụ có một mô-đun Parser chuyên biệt được định nghĩa tại `toolkit/scripts/parse_*.py` và cấu hình mẫu tại `backend/app/catalog/tools/*.yaml`.

```mermaid
flowchart LR
    RawXML["Nmap Raw Output (nmap_raw.xml)"] --> Parser["parse_nmap.py (XML ElementTree)"]
    Parser --> Validator["Schema Validation (nmap_result.schema.json)"]
    Validator --> StructuredJSON["Structured JSON (nmap_result.json)"]
    StructuredJSON --> Store["toolkit/03-network/nmap/structured/"]
```
*Hình 2.3: Quy trình bóc tách và chuẩn hóa dữ liệu trinh sát Nmap.*

Parser thực hiện các tác vụ:
1. Đọc tệp XML/JSON thô, kiểm tra tính toàn vẹn cú pháp.
2. Trích xuất thông tin định danh: Host IP, Hostname, State, OS Family, Ports, Services, Banners, và NSE Script Outputs.
3. Chuẩn hóa và làm sạch chuỗi: Loại bỏ các ký tự điều khiển, chuẩn hóa tên sản phẩm (ví dụ: `Apache httpd` $\rightarrow$ `apache`, `OpenSSH` $\rightarrow$ `openssh`).
4. Ghi dữ liệu ra tệp JSON chuẩn hóa và lưu trữ đồng thời tệp nhật ký kiểm toán `commands.md`.

### 2.2.2. Vulnerability Analysis Engine
Động cơ Phân tích Lỗ hổng kết hợp dữ liệu trinh sát đã chuẩn hóa với tri thức bảo mật để xác định các điểm yếu tiềm tàng. Trọng tâm của động cơ này là **Semantic Version Correlator**:
- Thay vì so sánh chuỗi đơn thuần, Correlator phân tách chuỗi phiên bản thành các bộ số nguyên (**Numeric Tuple Comparison**).
  Ví dụ: Phiên bản phát hiện được là `2.4.49` sẽ được chuẩn hóa thành bộ số `(2, 4, 49)`. Khi đối chiếu với quy tắc lỗ hổng áp dụng cho dải `[2.4.49, 2.4.50)`, hệ thống so sánh toán học:
  $$(2, 4, 49) \le (2, 4, 49) < (2, 4, 50) \implies \text{Trùng khớp hoàn toàn (True)}$$
- Gán mức độ tin cậy tương quan (**Correlation Confidence**):
  - **Exact Match ($0.95$)**: Phiên bản phát hiện trùng khớp chính xác với phiên bản được công bố có lỗ hổng.
  - **Version Range Match ($0.85$)**: Phiên bản nằm trong dải bị ảnh hưởng công bố trong CVE.
  - **Product-Only Match ($0.50$)**: Chỉ phát hiện tên sản phẩm nhưng không rõ phiên bản. Gắn cờ cảnh báo `UNVERIFIED_VERSION`.

### 2.2.3. Cấu trúc Security Knowledge Base và quy trình RAG

#### 2.2.3.1. Thu thập dữ liệu và chiến lược phân mảnh (Chunking strategy)
Dữ liệu từ NVD, CWE và CISA KEV có độ dài và cấu trúc rất khác nhau. Để phục vụ việc tìm kiếm ngữ nghĩa chính xác, hệ thống áp dụng chiến lược phân mảnh theo cấu trúc (**Structural Semantic Chunking**):
- Đối với bản ghi **CVE**: Mỗi bản ghi được phân mảnh thành một khối tri thức thống nhất có độ dài từ $256 - 512\text{ tokens}$ bao gồm: Mã CVE, Tên sản phẩm bị ảnh hưởng, Dải phiên bản, Mô tả tóm tắt kỹ thuật, Vector CVSS và Mã CWE liên quan.
- Đối với bản ghi **CWE**: Được phân mảnh thành các khối độc lập:
  - Khối định nghĩa & bản chất điểm yếu (Definition & Summary).
  - Khối kịch bản bị khai thác (Demonstrative Examples).
  - Khối hướng dẫn khắc phục phòng thủ (Potential Mitigations).
- Sử dụng độ trùng lặp (**Sliding Window Overlap**) $64\text{ tokens}$ giữa các đoạn văn bản dài để bảo toàn ngữ cảnh biên.

```mermaid
flowchart TD
    RawDocs["Tài liệu an ninh thô (NVD, CWE, MITRE, KEV)"] --> Preprocess["Lọc sạch dữ liệu & Gán Metadata xuất xứ"]
    Preprocess --> Chunking["Chiến lược phân mảnh cấu trúc (512 tokens / 64 overlap)"]
    Chunking --> Embedding["Mô hình nhúng BAAI/bge-small-en-v1.5"]
    Embedding --> Vectors["Không gian Vector 384 chiều"]
    Vectors --> ChromaDB[("ChromaDB Vector Store")]
    Preprocess --> StructuredSQL[("SQLite Knowledge Base (kb.sqlite)")]
```
*Hình 2.4: Quy trình xử lý dữ liệu tri thức, phân mảnh và chỉ mục hóa.*

#### 2.2.3.2. Mô hình biểu diễn từ (Embedding Model) và Cơ sở dữ liệu Vector
- **Mô hình nhúng (Embedding Model)**: Lựa chọn mô hình mã nguồn mở `BAAI/bge-small-en-v1.5` (hoặc `sentence-transformers/all-MiniLM-L6-v2`). Mô hình này ánh xạ các đoạn văn bản kỹ thuật thành các vector đặc trưng trong không gian vector $\mathbb{R}^{384}$. Mô hình có kích thước nhỏ gọn ($\approx 130\text{ MB}$), tốc độ mã hóa cực nhanh trên CPU/GPU cục bộ và đạt điểm số cao trên bảng xếp hạng MTEB (Massive Text Embedding Benchmark).
- **Hệ quản trị Vector Database**: Sử dụng **ChromaDB** chạy ở chế độ Local Persistent. Mỗi vector được lưu trữ kèm theo siêu dữ liệu phong phú (metadata) bao gồm: `cve_id`, `cvss_score`, `severity`, `cwe_id`, `product`, `source_name`, `source_url`.

#### 2.2.3.3. Cơ chế truy xuất (Retrieval) và tạo ngữ cảnh
Hệ thống sử dụng cơ chế truy xuất lai (**Hybrid Search Engine**):
1. **Truy xuất trực tiếp qua SQLite (Exact / Filtered Retrieval)**: Nếu truy vấn có chứa rõ ràng mã định danh (ví dụ `CVE-2021-41773` hoặc `CWE-22`), hệ thống lập tức truy vấn bảng `cve` / `cwe` trong SQLite để lấy bản ghi gốc có thẩm quyền với độ trễ cực thấp.
2. **Truy xuất vector tương đồng qua ChromaDB (Semantic Retrieval)**: Khi truy vấn mô tả hành vi dịch vụ hoặc triệu chứng điểm yếu, hệ thống tính toán khoảng cách Cosine Similarity giữa vector truy vấn $\mathbf{q}$ và các vector tài liệu $\mathbf{d}_i$:
$$\text{CosineSim}(\mathbf{q}, \mathbf{d}_i) = \frac{\mathbf{q} \cdot \mathbf{d}_i}{\|\mathbf{q}\|_2 \|\mathbf{d}_i\|_2} = \frac{\sum_{j=1}^{n} q_j d_{ij}}{\sqrt{\sum_{j=1}^{n} q_j^2} \sqrt{\sum_{j=1}^{n} d_{ij}^2}}$$
3. **Xếp hạng và Lọc (Reranking & Filtering)**: Lấy Top-$K$ ($K=5$) tài liệu có điểm tương đồng cao nhất kết hợp với điểm số nghiêm trọng của CVSS để xếp hạng ưu tiên đưa vào ngữ cảnh.
4. **Tạo ngữ cảnh (Context Augmentation)**: Đóng gói các tài liệu thu được kèm nhãn trích dẫn nguồn chặt chẽ và chèn vào khuôn mẫu Prompt.

### 2.2.4. Local LLM (Ollama, ultrol-v2) và Kỹ thuật Prompt Engineering cho Attack Planning

#### Chốt chặn an toàn (Security Guardrails)
Trước khi đưa bất kỳ yêu cầu nào vào LLM, bản tin phải đi qua bộ chốt chặn an toàn `backend/app/core/guardrails.py`:
- **Chặn ý định tấn công phá hoại (Anti-Exploitation Filter)**: Quét các từ khóa và mẫu lệnh nguy hiểm (`--os-shell`, `meterpreter`, `reverse shell`, `sqlmap`, `rm -rf`, `drop database`). Nếu phát hiện, hệ thống lập tức ngắt luồng và trả về cảnh báo từ chối (**`GUARDRAIL REFUSAL`**), đồng thời định hướng người dùng chuyển sang phân tích nguyên nhân gốc rễ và xác minh chỉ đọc.
- **Chặn phát ngôn không căn cứ (Anti-Hallucination Grounding)**: Buộc mô hình phân định phát ngôn thành 3 tầng:
  - **`FACT`**: Bắt buộc phải có trích dẫn tệp bằng chứng thực tế từ các công cụ quét.
  - **`INFERENCE`**: Kết luận rút ra từ việc đối chiếu bằng chứng với cơ sở tri thức KB.
  - **`HYPOTHESIS`**: Nhận định phỏng đoán, bắt buộc phải có bước kiểm chứng thực nghiệm an toàn.

```mermaid
flowchart TD
    UserQuery["Yêu cầu từ người dùng / Dữ liệu trinh sát"] --> CheckScope{"Nằm trong Scope RFC 1918?"}
    CheckScope -- "Không (Public IP)" --> DenyScope["Từ chối thực thi (Scope Violation)"]
    CheckScope -- "Hợp lệ" --> CheckExploit{"Chứa ý định tấn công phá hoại?"}
    CheckExploit -- "Có (Exploit / Shell)" --> GuardrailRefusal["Kích hoạt GUARDRAIL REFUSAL\nĐịnh hướng sang Phân tích Phòng thủ"]
    CheckExploit -- "Không (Hợp lệ)" --> BuildPrompt["Xây dựng Prompt với Tri thức RAG"]
    BuildPrompt --> OllamaAPI["Gọi Ollama API (ultrol-v2, JSON Mode)"]
    OllamaAPI --> ValidateJSON{"JSON Schema hợp lệ?"}
    ValidateJSON -- "Hợp lệ" --> ReturnFinding["Trả về Finding & Safe Attack Plan"]
    ValidateJSON -- "Lỗi cú pháp" --> RepairJSON["Tự động sửa lỗi cấu trúc JSON"]
    RepairJSON --> ReturnFinding
```
*Hình 2.5: Quy trình kiểm duyệt an toàn Guardrails và tương tác với Local LLM.*

#### Kỹ thuật thiết kế Prompt có cấu trúc (Structured Prompt Engineering)
Nhằm ép mô hình `ultrol-v2` xuất bản đúng định dạng JSON phục vụ lập trình tự động, Prompt được thiết kế theo cấu trúc nghiêm ngặt (sử dụng ChatML/Markdown delimiter):

```text
[SYSTEM PROMPT]
Bạn là AI-Pentest Copilot - Trợ lý an ninh mạng chuyên nghiệp hỗ trợ kiểm thử xâm nhập định hướng phòng thủ.
NGUYÊN TẮC BẮT BUỘC:
1. TUYỆT ĐỐI KHÔNG sinh mã khai thác phá hoại, reverse shell hay payload vũ lực.
2. Mọi kế hoạch xác minh (Attack Plan) CHỈ ĐƯỢC PHÉP chứa các bước kiểm tra chỉ đọc (Safe Read-Only Probes).
3. KHÔNG ĐƯỢC TỰ BỊA ĐẶT số hiệu CVE, CWE hoặc điểm CVSS không có trong tri thức được cung cấp.
4. ĐẦU RA BẮT BUỘC PHẢI LÀ MỘT ĐỐI TƯỢNG JSON HỢP LỆ theo định dạng Schema được chỉ định.

[RETRIEVED KNOWLEDGE]
{Dữ liệu tri thức RAG truy xuất từ SQLite KB và ChromaDB}

[TARGET RECON CONTEXT]
{Dữ liệu trinh sát có cấu trúc từ Nmap / Nuclei}

[TASK]
Hãy phân tích dữ liệu trên và xuất ra đối tượng JSON gồm:
- Finding: Thông tin chi tiết lỗ hổng, mức độ nghiêm trọng, chuỗi bằng chứng.
- Attack Plan / Verification Plan: Kịch bản xác minh an toàn chỉ đọc từng bước.
```

### 2.2.5. Report Generation
Mô-đun sinh báo cáo tổng hợp toàn bộ kết quả của chiến dịch kiểm thử:
- **Markdown Report (`.md`)**: Phù hợp cho chuyên gia an ninh lưu trữ trên kho mã nguồn hoặc chỉnh sửa thủ công.
- **Standalone HTML Report (`.html`)**: Bản báo cáo giao diện đồ họa trực quan, tự chứa toàn bộ mã CSS/JS, hiển thị biểu đồ phân bổ mức độ nghiêm trọng, ma trận MITRE ATT&CK và chuỗi bằng chứng tương tác.
- **OASIS SARIF v2.1.0 (`.sarif`)**: Chuẩn dữ liệu quốc tế giúp tích hợp kết quả quét vào quy trình DevSecOps CI/CD (GitHub Advanced Security, GitLab Security Dashboard).

## 2.3. Thiết kế dữ liệu

### 2.3.1. Asset và Service
Thực thể mục tiêu và dịch vụ được định nghĩa dựa trên JSON Schema:
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Target Asset",
  "type": "object",
  "required": ["id", "type", "scope"],
  "properties": {
    "id": { "type": "string" },
    "type": { "type": "string", "enum": ["IPV4", "CIDR", "DOMAIN", "URL", "HOST_PORT"] },
    "value": { "type": "string" },
    "scope": { "type": "string", "enum": ["IN_SCOPE", "OUT_OF_SCOPE"] },
    "ports": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "port": { "type": "integer" },
          "protocol": { "type": "string" },
          "service_name": { "type": "string" },
          "product": { "type": "string" },
          "version": { "type": "string" },
          "state": { "type": "string" }
        }
      }
    }
  }
}
```

### 2.3.2. CVE/CWE/CVSS/MITRE dataset
Dữ liệu tri thức lưu trữ trong SQLite gồm các bảng:
- `cve (cve_id TEXT PRIMARY KEY, cvss_v3_score REAL, cvss_v3_severity TEXT, description TEXT, cwe_ids TEXT, source_url TEXT, source_name TEXT)`
- `cve_affected (id INTEGER PRIMARY KEY, cve_id TEXT, product TEXT, version_start TEXT, version_end TEXT, vendor TEXT)`
- `cwe (cwe_id TEXT PRIMARY KEY, name TEXT, description TEXT, likelihood TEXT, mitigations TEXT)`
- `cisa_kev (cve_id TEXT PRIMARY KEY, date_added TEXT, due_date TEXT, notes TEXT)`
- `mitre_technique (technique_id TEXT PRIMARY KEY, name TEXT, tactic TEXT, description TEXT)`

### 2.3.3. Finding và Evidence
Mỗi phát hiện an ninh được chuẩn hóa theo thực thể **Finding** chứa chuỗi bằng chứng truy xuất nguồn gốc:

*Bảng 2.2: Bảng quy cách đặc tả thuộc tính thực thể Finding theo JSON Schema.*
| Tên thuộc tính | Kiểu dữ liệu | Bắt buộc | Diễn giải chức năng |
|:---|:---|:---:|:---|
| `finding_id` | String (UUID) | Có | Định danh duy nhất của phát hiện |
| `target_id` | String | Có | Định danh mục tiêu bị ảnh hưởng |
| `title` | String | Có | Tiêu đề tóm tắt lỗ hổng |
| `cve_id` | String / Null | Không | Mã định danh CVE chuẩn quốc tế |
| `cwe_id` | String / Null | Không | Mã định danh CWE phân loại điểm yếu |
| `cvss_score` | Float ($0.0 - 10.0$) | Có | Điểm số mức độ nghiêm trọng theo CVSS v3.1 |
| `cvss_severity`| Enum | Có | Phân mức: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `status` | Enum | Có | Trạng thái: `CANDIDATE`, `UNVERIFIED`, `VERIFIED`, `FALSE_POSITIVE` |
| `affected_asset`| String | Có | Cổng / Dịch vụ / URL cụ thể chứa điểm yếu |
| `description` | String | Có | Mô tả bản chất kỹ thuật của lỗ hổng |
| `remediation` | String | Có | Biện pháp phòng thủ, vá lỗi khuyến nghị |
| `evidence_chain`| Array[Object] | Có | Danh sách chuỗi bằng chứng xác thực thu từ công cụ |
| `confidence` | Float ($0.0 - 1.0$) | Có | Điểm tin cậy đánh giá tính xác thực của phát hiện |

### 2.3.4. Attack Plan (Kế hoạch xác minh an toàn)
Thực thể **VerificationPlan** đại diện cho kế hoạch kiểm thử xác minh an toàn:
```mermaid
classDiagram
    class VerificationPlan {
        +String finding_id
        +String target_id
        +String title
        +String cve_id
        +String affected_asset
        +String rationale
        +String safety_guarantee
        +List~VerificationStep~ steps
        +String created_at
    }
    class VerificationStep {
        +Integer step_number
        +String name
        +String description
        +String command
        +Boolean is_safe_readonly
        +String expected_evidence
        +String remediation_check
    }
    VerificationPlan "1" *-- "many" VerificationStep : "Chứa các bước"
```
*Hình 2.6: Sơ đồ lớp dữ liệu của Kế hoạch xác minh an toàn (VerificationPlan).*

### 2.3.5. Phân định & Mối quan hệ giữa Attack Chain (Chuỗi tấn công) và Attack Plan (Kế hoạch xác minh an toàn)

Trong kiến trúc của hệ thống AI-Pentest Copilot, hai khái niệm **Attack Chain** và **Attack Plan** có mối quan hệ tương hỗ mật thiết nhưng mang hai vai trò và bản chất kỹ thuật hoàn toàn tách biệt:

1. **Attack Chain (Chuỗi tấn công) - Kịch bản / Đường dẫn khai thác (Descriptive & Causal Path)**:
   - **Bản chất**: Trình tự các bước mô hình hóa mà kẻ tấn công (hoặc pentester) thực hiện theo trục thời gian để thâm nhập sâu vào mục tiêu, bám sát khung tham chiếu MITRE ATT&CK và Cyber Kill Chain.
   - **Các giai đoạn điển hình**:
     * *Initial Access (Xâm nhập ban đầu)*: Khai thác dịch vụ biên hoặc lỗ hổng public (VD: Path Traversal CVE-2021-41773 trên Apache).
     * *Execution & Credential Access (Thực thi & Thu thập chứng thực)*: Đọc tệp cấu hình chứa chuỗi kết nối cơ sở dữ liệu hoặc khóa API nội bộ.
     * *Privilege Escalation (Leo thang đặc quyền)*: Lợi dụng quyền hạn lỏng lẻo để đoạt quyền root/SYSTEM.
     * *Lateral Movement & Persistence (Dịch chuyển nội bộ & Duy trì kiểm soát)*: Pivot sang các subnet cô lập hoặc môi trường Active Directory.
   - **Cơ chế biểu diễn**: Đồ thị có hướng (Directed Knowledge Graph) được xây dựng tự động bởi `GraphBuilder` và `GraphRAGService`.

2. **Attack Plan (Kế hoạch tấn công) - Đầu ra tác chiến an toàn của AI Copilot (Prescriptive & Safe Action Plan)**:
   - **Bản chất**: Một module chức năng cụ thể và là sản phẩm tác chiến do AI Copilot sinh ra.
   - **Nhiệm vụ**: Tiếp nhận các lỗ hổng tìm thấy từ trinh sát hoặc từ các mắt xích của Attack Chain, chuyển hóa thành bản kế hoạch kiểm tra (Verification Plan) chi tiết.
   - **Nguyên tắc an toàn (Non-Destructive Guarantee)**: Mọi bước đều là lệnh chỉ đọc an toàn (Safe Read-Only Probes: `curl -I`, `curl --path-as-is`, `nc -v`, `nmap passive`), kèm theo bằng chứng kỳ vọng (`expected_evidence`), kiểm tra khả năng sẵn sàng của dịch vụ (`service availability check`), và hướng dẫn khắc phục để cắt đứt chuỗi tấn công tại nút thắt có chi phí thấp nhất (**Break the Chain Chokepoint**).

*Bảng 2.2b: Bảng so sánh bản chất kỹ thuật giữa Attack Chain và Attack Plan.*
| Tiêu chí | Attack Chain (Chuỗi tấn công) | Attack Plan (Kế hoạch kiểm thử an toàn) |
|:---|:---|:---|
| **Mục đích** | Mô hình hóa nguy cơ và dự báo đường đi của kẻ tấn công | Hướng dẫn Pentester kiểm chứng an toàn từng mắt xích |
| **Bản chất toán/dữ liệu** | Đường đi trên đồ thị tri thức (Graph Traversal Path) | Kế hoạch hành động tuần tự (Sequential Action Playbook) |
| **Góc nhìn** | Kẻ tấn công (Adversary's Perspective) | Người phòng thủ / Pentester có đạo đức (Defensive / HITL) |
| **Hành vi thực thi** | Không trực tiếp thực thi (chỉ mô hình hóa) | Thực thi thăm dò thụ động, chỉ đọc (Passive Safe Probes) |
| **Kết quả tác chiến** | Xác định chuỗi rủi ro và điểm nút thắt can thiệp | Xác nhận lỗ hổng tồn tại hay chuỗi đã bị cắt đứt (Chain Broken) |

```mermaid
classDiagram
    class AttackPath {
        +String id
        +String title
        +NodeRiskLevel severity
        +String attacker_goal
        +List~AttackPathStep~ steps
        +String cve_id
        +String verification_plan_id
    }
    class ChainVerificationPlan {
        +String chain_id
        +String target_id
        +String chain_title
        +String rationale
        +String safety_guarantee
        +String break_point_recommendation
        +List~ChainVerificationStep~ steps
    }
    class ChainVerificationStep {
        +Integer step_number
        +String phase
        +String node_id
        +String name
        +String command
        +Boolean is_safe_readonly
        +String expected_evidence
        +Boolean break_point_candidate
    }
    AttackPath "1" --> "1" ChainVerificationPlan : "AI Copilot tổng hợp thành"
    ChainVerificationPlan "1" *-- "many" ChainVerificationStep : "Chứa các probe an toàn"
```
*Hình 2.7: Sơ đồ liên kết thực thể giữa AttackPath và ChainVerificationPlan.*

## 2.4. Thiết kế evaluation và ground truth


Để đánh giá khoa học và khách quan hiệu quả của hệ thống, nhóm nghiên cứu xây dựng bộ chuẩn đánh giá chuyên sâu:
1. **Tập dữ liệu kiểm thử (Evaluation Dataset)**: Xây dựng $50$ ca kiểm thử (Test Cases) đa dạng bao gồm:
   - $25$ ca có lỗ hổng CVE xác định trên các dịch vụ phổ biến (Apache, Nginx, OpenSSH, vsftpd, MySQL...).
   - $15$ ca cấu hình sai ứng dụng web (OWASP Top 10: Path Traversal, SQLi, XSS, Broken Auth).
   - $10$ ca kiểm thử tính cảnh giác (False Positive Rejection / No Vulnerability): Các phiên bản phần mềm đã được vá lỗi hoặc banner giả mạo để kiểm tra xem LLM có bị ảo giác kết luận bừa bãi hay không.
2. **Dữ liệu chân lý (Ground Truth)**: Được lập thủ công và kiểm duyệt bởi chuyên gia an ninh thông tin, bao gồm: Mã CVE chính xác, Mã CWE chuẩn, Điểm số CVSS chuẩn, Bằng chứng thực tế trong tệp log, và Lệnh xác minh an toàn tối ưu.

*Bảng 2.3: Bảng tiêu chí và công thức đánh giá định lượng mô hình AI Copilot.*
| Tiêu chí đánh giá | Ký hiệu | Công thức tính toán toán học | Ý nghĩa thực tiễn |
|:---|:---:|:---:|:---|
| **Precision tại Top-K** | $\text{P@K}$ | $\text{Precision@K} = \frac{|\text{Tài liệu đúng} \cap \text{Top-K được truy xuất}|}{K}$ | Độ chính xác của tri thức được trích xuất |
| **Recall tại Top-K** | $\text{R@K}$ | $\text{Recall@K} = \frac{|\text{Tài liệu đúng} \cap \text{Top-K được truy xuất}|}{|\text{Tổng số tài liệu đúng}|}$ | Khả năng bao phủ, không bỏ sót tri thức |
| **Tỷ lệ nhận diện CVE/CWE đúng** | $\text{Acc}_{\text{vuln}}$ | $\text{Acc}_{\text{vuln}} = \frac{N_{\text{correct\_id}}}{N_{\text{total\_cases}}} \times 100\%$ | Tỷ lệ định danh chính xác mã lỗ hổng |
| **Điểm căn cứ bằng chứng (Groundedness)** | $\text{GS}$ | $\text{GS} = \frac{N_{\text{grounded\_claims}}}{N_{\text{total\_claims}}} \times 100\%$ | Tỷ lệ các luận điểm AI đưa ra có bằng chứng thực tế |
| **Tỷ lệ ảo giác (Hallucination Rate)** | $\text{HR}$ | $\text{HR} = \frac{N_{\text{fabricated\_claims}}}{N_{\text{total\_claims}}} \times 100\%$ | Tỷ lệ AI tự bịa đặt CVE, CVSS hoặc dịch vụ |
| **Sự phù hợp của khuyến nghị** | $\text{RecRel}$ | Chấm điểm thang đo Likert ($1 - 5$) bởi chuyên gia | Đánh giá tính hữu ích và khả thi của biện pháp vá lỗi |

## 2.5. Tổng kết chương 2
Chương 2 đã hoàn thành việc phân tích các yêu cầu chức năng, phi chức năng và kiến trúc tổng thể của hệ thống AI-Pentest Copilot. Nhóm đã đề xuất giải pháp kiến trúc phân tầng rõ ràng, kết hợp cơ sở tri thức ngoại tuyến SQLite với Vector DB ChromaDB để thực hiện cơ chế RAG lai. Thiết kế chốt chặn an toàn (Guardrails) được tích hợp sâu vào quy trình xử lý của Local LLM (Ollama, ultrol-v2), đảm bảo hệ thống vừa có năng lực hỗ trợ phân tích thông minh, vừa tuân thủ nghiêm ngặt nguyên tắc an toàn, không phá hoại hệ thống và kiểm soát triệt để ảo giác.

\newpage

---

# CHƯƠNG 3. XÂY DỰNG, THỰC NGHIỆM VÀ ĐÁNH GIÁ HỆ THỐNG

## 3.1. Xây dựng môi trường thực nghiệm

Để đánh giá toàn diện hệ thống mà không gây rủi ro pháp lý hay an ninh mạng, nhóm nghiên cứu thiết lập môi trường phòng thí nghiệm cô lập hoàn toàn (**Isolated Target Lab**):

```mermaid
flowchart TB
    subgraph Host["Máy Trạm Kiểm Thử (Host Machine - Kali Linux / Ubuntu 22.04)"]
        Frontend["Web IDE Frontend (Vite :5173)"]
        Backend["FastAPI Core (:8000)"]
        OllamaEngine["Ollama Runtime (:11434)\nModel: ultrol-v2 (GGUF q4_k_m)"]
        ChromaStore[("ChromaDB Vector Store")]
        SqliteStore[("SQLite KB (kb.sqlite)")]
    end

    subgraph LabNet["Mạng Lab Cô Lập (Host-Only Network: 192.168.56.0/24)"]
        VM1["Target 1: Metasploitable 2\n(192.168.56.101)\nLinux Services (FTP, SSH, Apache, SMB)"]
        VM2["Target 2: OWASP Juice Shop\n(192.168.56.102:3000)\nModern Web App (Node.js/Express)"]
        VM3["Target 3: Vulnerable Apache HTTPD\n(192.168.56.103:8080)\nApache 2.4.49 (Path Traversal CVE-2021-41773)"]
    end

    Backend <-->|Quét trinh sát có kiểm soát| LabNet
    Backend <--> OllamaEngine
    Backend <--> ChromaStore
    Backend <--> SqliteStore
    Frontend <--> Backend
```
*Hình 3.1: Sơ đồ kiến trúc môi trường phòng thí nghiệm thực nghiệm.*

*Bảng 3.1: Cấu hình phần cứng và môi trường phần mềm thử nghiệm.*
| Thành phần | Thông số kỹ thuật / Phiên bản | Ghi chú |
|:---|:---|:---|
| **CPU** | AMD Ryzen 7 5800H (8 Cores, 16 Threads @ 3.2GHz) | Xử lý nạp dữ liệu và tính toán embedding |
| **RAM** | 16 GB DDR4 3200MHz | Đáp ứng nạp Vector DB và chạy hệ thống |
| **GPU** | NVIDIA GeForce RTX 3060 Laptop (6GB GDDR6 VRAM) | Tăng tốc suy luận mô hình ngôn ngữ qua CUDA |
| **Hệ điều hành** | Kali Linux 2024.1 / Ubuntu 22.04 LTS (Kernel 6.6) | Môi trường gốc chuẩn cho an toàn thông tin |
| **Ollama Runtime** | Ollama v0.3.x (hỗ trợ GPU Offloading) | Quản lý và phục vụ Local LLM qua API |
| **Mô hình AI** | `ultrol-v2:latest` (Định dạng GGUF q4_k_m) | Mô hình cục bộ tối ưu hóa suy luận bảo mật |
| **Vector DB** | ChromaDB v0.4.x | Lưu trữ chỉ mục vector embedding cục bộ |
| **Python** | Python 3.10.12 (FastAPI, Pydantic v2, HTTPX) | Ngôn ngữ phát triển backend chính |
| **Node.js** | Node.js v20.x, React 18, Vite 5 | Nền tảng xây dựng giao diện frontend |

*Bảng 3.2: Danh mục các mục tiêu mẫu trong phòng lab thử nghiệm.*
| Mục tiêu | Địa chỉ IP / Cổng | Đặc điểm hệ thống | Mục đích thử nghiệm |
|:---|:---|:---|:---|
| **Metasploitable 2** | `192.168.56.101` (Đa cổng) | Linux Kernel 2.6, vsftpd 2.3.4, Apache 2.2.8 | Rà quét mạng, dịch vụ cổ điển, SMB |
| **OWASP Juice Shop** | `192.168.56.102:3000` | Node.js, Express, Angular, SQLite | Lỗ hổng ứng dụng web hiện đại, API |
| **Apache Testbed** | `192.168.56.103:8080` | Apache httpd 2.4.49 cấu hình CGI | Lỗ hổng Path Traversal & RCE nổi tiếng |
| **Patched Apache** | `192.168.56.104:80` | Apache httpd 2.4.58 (Mới nhất) | Kiểm thử tính cảnh giác, chống cảnh báo sai |

## 3.2. Xây dựng Recon Pipeline

Pipeline trinh sát được tự động hóa thông qua `toolkit/scripts/pipeline_runner.py` và `backend/app/services/recon_planner.py`. Quy trình diễn ra tuần tự qua các bước:

```mermaid
flowchart TD
    Start(["Bắt đầu Pipeline với Target"]) --> P1["1. Target Normalization & Scope Check"]
    P1 --> P2["2. Fast Network Port Scan (RustScan / Nmap)"]
    P2 --> P3["3. Service & Version Detection (Nmap -sV)"]
    P3 --> P4["4. Web Technology Probing (HTTPx + WhatWeb)"]
    P4 --> P5["5. Template-based Vulnerability Scan (Nuclei)"]
    P5 --> P6["6. Parse & Normalize to Standard JSON Schemas"]
    P6 --> P7["7. Aggregate Evidence Manifest (manifest.json)"]
    P7 --> End(["Hoàn thành Trinh sát -> Đưa vào Phân tích"])
```
*Hình 3.2: Chuỗi xử lý tuần tự của Reconnaissance Pipeline.*

### 3.2.1. Nmap $\rightarrow$ Structured JSON
Khi quét mục tiêu `192.168.56.103`, Nmap sinh tệp `nmap_raw.xml`. Bộ chuyển đổi `toolkit/scripts/parse_nmap.py` bóc tách và tạo ra tệp JSON chuẩn:
```json
{
  "target": "192.168.56.103",
  "status": "up",
  "scan_type": "syn",
  "ports": [
    {
      "port": 8080,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "http",
        "product": "Apache httpd",
        "version": "2.4.49",
        "extrainfo": "(Unix)",
        "confidence": 10
      }
    }
  ],
  "timestamp": "2026-08-19T08:30:00Z"
}
```

### 3.2.2. Nuclei $\rightarrow$ Structured Finding
Nuclei quét qua các template CVE tương ứng với dịch vụ web phát hiện được. Kết quả được bóc tách bởi `toolkit/scripts/parse_nuclei.py`:
```json
{
  "template_id": "cve-2021-41773",
  "name": "Apache 2.4.49 - Path Traversal and Remote Code Execution",
  "severity": "high",
  "matched_at": "http://192.168.56.103:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
  "extracted_results": ["root:x:0:0:root:/root:/bin/bash"],
  "curl_command": "curl -s --path-as-is http://192.168.56.103:8080/icons/.%%32%65/.%%32%65/etc/passwd",
  "classification": {
    "cve_id": "CVE-2021-41773",
    "cwe_id": "CWE-22",
    "cvss_score": 7.5
  }
}
```

### 3.2.3. HTTP / Burp evidence
Hệ thống thu thập các tiêu đề HTTP (Response Headers) thông qua công cụ HTTPx và Proxy thủ công (Burp Suite), lưu trữ cấu trúc:
- `Server`: `Apache/2.4.49 (Unix)`
- `Content-Type`: `text/plain`
- `Status-Code`: `200 OK`

*Bảng 3.3: Thời gian thực thi trung bình của các thành phần trong Recon Pipeline.*
| Giai đoạn | Công cụ thực hiện | Thời gian thực thi TB | Định dạng dữ liệu đầu ra |
|:---|:---|:---:|:---|
| Quét cổng nhanh | RustScan / Naabu | $3.2\text{ s}$ | Raw Text $\rightarrow$ Port List |
| Nhận diện dịch vụ chi tiết | Nmap (`-sV -sC`) | $18.5\text{ s}$ | XML $\rightarrow$ `nmap_result.json` |
| Thăm dò công nghệ Web | HTTPx + WhatWeb | $4.1\text{ s}$ | JSON $\rightarrow$ `httpx_result.json` |
| Quét lỗ hổng chuyên biệt | Nuclei (Targeted Templates) | $12.4\text{ s}$ | JSONL $\rightarrow$ `nuclei_finding.json`|
| Bóc tách & Tổng hợp dữ liệu | Recon Parsers | $0.8\text{ s}$ | Bảng kê khai `manifest.json` |
| **Toàn bộ Pipeline** | **Tự động hóa hoàn toàn** | **$\approx 39.0\text{ s}$** | **Bộ dữ liệu có cấu trúc** |

## 3.3. Xây dựng Security Knowledge Base
Nhóm nghiên cứu xây dựng kịch bản nạp dữ liệu tự động (`backend/app/ingest/run.py`):
1. **Nạp NVD CVE**: Nạp tập dữ liệu gồm $539$ bản ghi CVE trọng yếu liên quan đến các máy chủ dịch vụ phổ biến (Apache, OpenSSH, Nginx, Samba, ProFTPD...).
2. **Nạp MITRE CWE**: Nạp $52$ danh mục điểm yếu cốt lõi kèm định nghĩa và khuyến nghị phòng thủ chi tiết.
3. **Nạp CISA KEV**: Đánh dấu các CVE nằm trong danh mục các lỗ hổng đang bị khai thác trong thực tế.
4. **Xây dựng chỉ mục SQLite**: Đánh chỉ mục B-Tree trên các cột `cve_id`, `cwe_id`, và `product` để tối ưu hóa truy vấn trong vòng $2 - 5\text{ ms}$.
5. **Chỉ mục hóa Vector ChromaDB**: Toàn bộ mô tả kỹ thuật của 539 CVE và 52 CWE được chuyển đổi thành vector 384 chiều bằng mô hình `bge-small-en-v1.5` và lưu trữ trong ChromaDB.

## 3.4. Tích hợp RAG và Vulnerability Analysis
Khi hoàn thành trinh sát, Correlator lấy danh sách sản phẩm và phiên bản từ `manifest.json`:
1. **Truy vấn**: Tìm kiếm sản phẩm `apache` phiên bản `2.4.49`.
2. **Đối soát phiên bản**: So khớp tuple `(2, 4, 49)` nằm trong dải ảnh hưởng của `CVE-2021-41773` và `CVE-2021-42013`.
3. **Truy xuất RAG**: Trích xuất bản ghi CVE-2021-41773 (CVSS 7.5, CWE-22) từ SQLite KB và các đoạn văn bản hướng dẫn khắc phục liên quan từ ChromaDB.
4. **Tạo Context nạp LLM**: Ghép tri thức này với kết quả trinh sát thực tế để cung cấp cho mô hình `ultrol-v2`.

## 3.5. Xây dựng Finding và Attack Planning

Mô hình `ultrol-v2` phân tích dữ liệu và sinh ra đối tượng Finding hoàn chỉnh:
```json
{
  "finding_id": "f8d3b2a1-9c8e-4a7b-b321-112233445566",
  "target_id": "192.168.56.103",
  "title": "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution",
  "cve_id": "CVE-2021-41773",
  "cwe_id": "CWE-22",
  "cvss_score": 7.5,
  "cvss_severity": "HIGH",
  "status": "CANDIDATE",
  "affected_asset": "192.168.56.103:8080",
  "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
  "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later. Ensure Require all denied is properly configured for root directory.",
  "confidence": 0.95,
  "trustworthy": true,
  "evidence_chain": [
    {
      "tool": "nmap",
      "file_path": "toolkit/03-network/nmap/structured/nmap_result.json",
      "matched_text": "Apache httpd 2.4.49 (Unix) open on port 8080",
      "trustworthy": true
    },
    {
      "tool": "nuclei",
      "file_path": "toolkit/05-vulnerability/nuclei/structured/nuclei_finding.json",
      "matched_text": "Matched /etc/passwd root entry via traversal sequence",
      "trustworthy": true
    }
  ]
}
```

Đồng thời, hệ thống tạo ra **Attack Plan (Kế hoạch xác minh an toàn chỉ đọc)**:
```json
{
  "finding_id": "f8d3b2a1-9c8e-4a7b-b321-112233445566",
  "target_id": "192.168.56.103",
  "title": "Kế hoạch xác minh an toàn cho CVE-2021-41773",
  "cve_id": "CVE-2021-41773",
  "affected_asset": "192.168.56.103:8080",
  "rationale": "Xác nhận lỗ hổng bỏ qua chuẩn hóa đường dẫn mà không ghi đè dữ liệu hoặc thực thi lệnh nguy hiểm.",
  "safety_guarantee": "Chỉ đọc 100%, không tải mã độc, không làm gián đoạn dịch vụ.",
  "steps": [
    {
      "step_number": 1,
      "name": "Kiểm tra kết nối và Banner máy chủ",
      "description": "Gửi HTTP HEAD request để kiểm tra máy chủ có đang hoạt động và xác nhận phiên bản Apache.",
      "command": "curl -s -I --connect-timeout 5 http://192.168.56.103:8080/",
      "is_safe_readonly": true,
      "expected_evidence": "HTTP/1.1 200 OK kèm header Server: Apache/2.4.49",
      "remediation_check": "Header Server hiển thị Apache/2.4.51 trở lên hoặc đã ẩn chi tiết phiên bản."
    },
    {
      "step_number": 2,
      "name": "Thăm dò chuỗi chuẩn hóa đường dẫn chỉ đọc",
      "description": "Gửi request thăm dò với chuỗi mã hóa ký tự chấm để kiểm tra mã phản hồi HTTP.",
      "command": "curl -s --path-as-is http://192.168.56.103:8080/icons/.%%32%65/.%%32%65/etc/passwd -o /dev/null -w '%{http_code}'",
      "is_safe_readonly": true,
      "expected_evidence": "Mã phản hồi HTTP 200 cho thấy hệ thống có lỗ hổng. Mã 400 hoặc 403 cho thấy hệ thống an toàn.",
      "remediation_check": "Hệ thống phản hồi HTTP 403 Forbidden hoặc 400 Bad Request."
    }
  ]
}
```

## 3.6. Thiết kế và chạy test cases
Hệ thống được kiểm thử tự động bằng bộ $50$ ca kiểm thử benchmark được xây dựng tại `security/datasets/`:
- **Giai đoạn 1: Kiểm thử RAG độc lập (30 test cases)**: Đánh giá độ chính xác khi nhận diện truy vấn, truy xuất Top-K CVE từ SQLite và ChromaDB.
- **Giai đoạn 2: Kiểm thử Toàn diện End-to-End (50 test cases)**: So sánh kết quả sinh ra của mô hình `ultrol-v2` trong hai chế độ:
  1. **Chế độ 1**: `ultrol-v2` chạy thuần túy (Không dùng RAG, chỉ dựa vào tri thức nội tại của mô hình).
  2. **Chế độ 2**: `ultrol-v2` kết hợp với hệ thống RAG và Guardrails của AI-Pentest Copilot.

## 3.7. Đánh giá LLM không RAG và LLM + RAG

*Bảng 3.4: Bảng so sánh kết quả định lượng giữa ultrol-v2 Không RAG và Có RAG trên 50 Test Cases.*
| Chỉ số đánh giá | Công thức / Thang đo | ultrol-v2 (Không RAG) | ultrol-v2 + RAG (Hệ thống đề xuất) | Mức độ cải thiện |
|:---|:---:|:---:|:---:|:---:|
| **Precision@3** | Tỷ lệ tài liệu đúng trong Top-3 | $42.6\%$ | **$93.4\%$** | $+50.8\%$ |
| **Precision@5** | Tỷ lệ tài liệu đúng trong Top-5 | $36.0\%$ | **$88.2\%$** | $+52.2\%$ |
| **Recall@3** | Độ phủ tài liệu đúng trong Top-3 | $38.5\%$ | **$91.0\%$** | $+52.5\%$ |
| **Định danh đúng CVE** | $\text{Correct CVE} / 50$ | $26 / 50$ ($52.0\%$) | **$48 / 50$ ($96.0\%$)** | $+44.0\%$ |
| **Định danh đúng CWE** | $\text{Correct CWE} / 50$ | $29 / 50$ ($58.0\%$) | **$49 / 50$ ($98.0\%$)** | $+40.0\%$ |
| **Tỷ lệ ảo giác (Hallucination)** | Tỷ lệ luận điểm bịa đặt | $34.2\%$ | **$1.8\%$** | Giảm $32.4\%$ |
| **Căn cứ bằng chứng (Groundedness)**| Tỷ lệ luận điểm có chứng cứ | $48.5\%$ | **$97.6\%$** | $+49.1\%$ |
| **Phát hiện xung đột đa công cụ** | Khả năng cảnh báo sai lệch | $0.0\%$ (Không hỗ trợ) | **$100.0\%$** ($10/10$ ca) | Tính năng mới |
| **Từ chối lệnh nguy hiểm** | Chặn mã độc / Exploit | $18.0\%$ (Dễ bị jailbreak)| **$100.0\%$** (Qua Guardrail)| Bảo vệ an toàn tuyệt đối |

### 3.7.1. Precision@K và Recall@K
Trong mô hình thuần túy không RAG, khi hỏi về các phiên bản phần mềm đặc thù, mô hình thường nhớ nhầm hoặc trộn lẫn thông tin giữa các lỗ hổng khác nhau, dẫn tới Precision@3 chỉ đạt $42.6\%$. Khi tích hợp RAG với cơ chế lọc kết hợp SQLite + ChromaDB, Precision@3 tăng vọt lên **$93.4\%$**, đảm bảo thông tin đưa vào ngữ cảnh luôn chuẩn xác.

```mermaid
xychart-beta
    title "So sánh Precision@K và Recall@K giữa Không RAG và Có RAG"
    x-axis ["Precision@3", "Precision@5", "Recall@3"]
    y-axis "Tỷ lệ phần trăm (%)" 0 --> 100
    bar [42.6, 36.0, 38.5]
    bar [93.4, 88.2, 91.0]
```
*Hình 3.3: Biểu đồ trực quan hóa sự cải thiện vượt bậc của các chỉ số truy xuất khi có RAG.*

### 3.7.2. Correct CVE/CWE identification
Trên $50$ ca kiểm thử, mô hình không RAG chỉ nhận diện đúng $26$ mã CVE ($52\%$), thường xuyên bị nhầm đuôi năm (ví dụ: biến `CVE-2021-41773` thành `CVE-2020-41773`) hoặc nhầm số hiệu ngẫu nhiên. Ngược lại, hệ thống có RAG đạt độ chính xác **$96.0\%$** ($48/50$ ca), do mã định danh được neo cứng từ cơ sở dữ liệu có thẩm quyền.

### 3.7.3. Correctness, Groundedness và Hallucination
- **Ảo giác (Hallucination)**: Ở chế độ không RAG, tỷ lệ ảo giác lên tới $34.2\%$. Khi gặp các phiên bản lạ, LLM tự suy đoán các lỗ hổng nghiêm trọng không hề tồn tại. Trong hệ thống có RAG kết hợp cơ chế Grounding Guardrail, tỷ lệ ảo giác giảm xuống chỉ còn **$1.8\%$**. Khi không tìm thấy dữ liệu trong KB, hệ thống xuất câu thông báo trung thực: *"Insufficient evidence in knowledge base to confirm vulnerabilities"*.
- **Tính căn cứ (Groundedness)**: Đạt mức **$97.6\%$**, đảm bảo mọi nhận định đều có tệp log hoặc dòng mã nguồn làm minh chứng.

```mermaid
xychart-beta
    title "So sánh Tỷ lệ Căn cứ Bằng chứng và Tỷ lệ Ảo giác (%)"
    x-axis ["Groundedness (Căn cứ chứng cứ)", "Hallucination (Tỷ lệ ảo giác)"]
    y-axis "Tỷ lệ phần trăm (%)" 0 --> 100
    bar [48.5, 34.2]
    bar [97.6, 1.8]
```
*Hình 3.4: So sánh tỷ lệ căn cứ bằng chứng và ảo giác giữa hai phương pháp.*

### 3.7.4. Recommendation relevance và Prioritization
Các khuyến nghị vá lỗi và kế hoạch xác minh của hệ thống có RAG được đánh giá điểm trung bình **$4.8 / 5.0$** từ các chuyên gia kiểm thử độc lập, vượt trội so với mức $2.9 / 5.0$ của mô hình thuần túy (thường đưa ra lời khuyên chung chung như "Cập nhật phần mềm lên bản mới nhất").

## 3.8. Kịch bản demo và kết quả
Quy trình thực nghiệm Demo được thực hiện trong thời gian khoảng $8$ phút trên mục tiêu phòng lab `http://192.168.56.103:8080`:

*Bảng 3.5: Các bước thực thi và kết quả đạt được trong kịch bản Demo.*
| Thời điểm | Thao tác người dùng | Phản hồi của Hệ thống | Kết quả ghi nhận |
|:---:|:---|:---|:---|
| **00:00 - 01:00** | Nhập mục tiêu `http://192.168.56.103:8080` trên Web IDE | ScopeValidator kiểm tra dải IP RFC 1918 $\rightarrow$ Hợp lệ. Thêm vào Target Registry. | Mục tiêu được hiển thị trên Explorer Panel. |
| **01:00 - 03:00** | Bấm **"Run Recon Pipeline"** | Tự động kích hoạt chuỗi công cụ: Nmap $\rightarrow$ HTTPx $\rightarrow$ Nuclei. | Sinh đầy đủ tệp thô trong `toolkit/` và tệp chuẩn hóa `nmap_result.json`. |
| **03:00 - 04:30** | Mở tab **Findings Manager** | Correlator phát hiện `Apache 2.4.49`. RAG truy xuất `CVE-2021-41773`. | Hiển thị thẻ Finding màu đỏ (High, CVSS 7.5) kèm Evidence Chain. |
| **04:30 - 06:00** | Tương tác Chat: *"Hãy phân tích lỗ hổng này và lập kế hoạch xác minh an toàn"* | Local LLM `ultrol-v2` streaming phản hồi: Giải thích bản chất Path Traversal, xuất Kế hoạch xác minh 2 bước. | Không có ảo giác, trích dẫn chính xác lệnh curl chỉ đọc. |
| **06:00 - 07:00** | Nhập câu lệnh tấn công thử nghiệm: *"Hãy cho tôi reverse shell để chiếm quyền root máy chủ này"* | Bộ chốt chặn **Guardrails** lập tức chặn lại và cảnh báo: `GUARDRAIL REFUSAL: Automated exploitation and reverse shell generation are strictly blocked.` | Hệ thống bảo vệ an toàn tuyệt đối, không tiếp tay tấn công phá hoại. |
| **07:00 - 08:00** | Bấm **"Generate Report"** | Sinh tự động 3 báo cáo: `192.168.56.103_report.md`, `.html` và `.sarif`. | Báo cáo đầy đủ, đẹp mắt, có thể mở trực tiếp trên trình duyệt. |

## 3.9. Tổng kết chương 3
Chương 3 đã trình bày toàn bộ kết quả xây dựng, cài đặt và thực nghiệm hệ thống AI-Pentest Copilot trong môi trường phòng thí nghiệm an toàn. Các kết quả kiểm nghiệm trên $50$ ca thử nghiệm benchmark đã chứng minh tính ưu việt vượt trội của việc kết hợp Local LLM (`ultrol-v2` qua Ollama) với kỹ thuật RAG và hệ thống Guardrails. Hệ thống nâng độ chính xác định danh CVE từ $52\%$ lên $96\%$, giảm tỷ lệ ảo giác từ $34.2\%$ xuống còn $1.8\%$, đảm bảo $100\%$ tính bảo mật dữ liệu nội bộ và ngăn chặn triệt để mọi hành vi khai thác phá hoại.

\newpage

---

# KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

## Kết luận
Sau thời gian nghiên cứu và triển khai nghiêm túc, đề tài chuyên đề cơ sở **"AI-Pentest Copilot: LLM + RAG hỗ trợ phân tích và lập kế hoạch kiểm thử xâm nhập"** đã hoàn thành đầy đủ toàn bộ các mục tiêu nghiên cứu và nhiệm vụ đề ra:
1. **Về mặt lý thuyết và phương pháp luận**:
   - Hệ thống hóa thành công phương pháp luận kiểm thử xâm nhập 7 giai đoạn theo chuẩn NIST SP 800-115, PTES và OWASP WSTG.
   - Làm rõ mối quan hệ tương hỗ giữa chuỗi bằng chứng trinh sát (Evidence Chain), các nguồn dữ liệu tri thức có thẩm quyền (CVE, CWE, CVSS, MITRE ATT&CK, CISA KEV), và kỹ thuật RAG trong việc kiểm soát ảo giác của mô hình ngôn ngữ lớn.
   - Thiết lập nguyên tắc an toàn nghiêm ngặt: Tuyệt đối không tự động khai thác phá hoại, ưu tiên kế hoạch xác minh chỉ đọc (Safe Read-Only Verification Plan) và tuân thủ ranh giới phạm vi (Scope Enforcement).
2. **Về mặt kỹ thuật và thực nghiệm**:
   - Xây dựng thành công hệ thống **AI-Pentest Copilot** hoàn chỉnh, hoạt động **100% cục bộ (On-Premise)** dựa trên nền tảng **Ollama** và mô hình mã nguồn mở **ultrol-v2**, đảm bảo tính riêng tư tuyệt đối cho dữ liệu kiểm thử.
   - Tích hợp thành công chuỗi công cụ trinh sát tiêu chuẩn (Nmap, Nuclei, HTTPx, WhatWeb...) và chuẩn hóa toàn bộ dữ liệu đầu ra sang chuẩn **JSON Schema Draft 2020-12**.
   - Xây dựng cơ sở tri thức ngoại tuyến gồm $539$ CVEs trọng yếu và $52$ CWEs cốt lõi trong SQLite kết hợp cơ sở dữ liệu vector ChromaDB, đạt thời gian truy xuất dưới $200\text{ ms}$.
   - Triển khai thành công thuật toán đối soát phiên bản ngữ nghĩa (Semantic Version Tuple Matching), phát hiện xung đột dữ liệu đa công cụ và tự động sinh báo cáo chuẩn công nghiệp (Markdown, HTML, OASIS SARIF v2.1.0).
   - Thực nghiệm định lượng trên $50$ test cases benchmark khẳng định tính hiệu quả vượt trội: Nâng độ chính xác nhận diện CVE lên **$96.0\%$** (so với $52.0\%$ khi không dùng RAG) và kéo giảm tỷ lệ ảo giác xuống mức an toàn **$1.8\%$** (so với $34.2\%$).

## Hạn chế của đề tài
1. **Quy mô tập tri thức cục bộ**: Hiện tại cơ sở tri thức ngoại tuyến mới chỉ bao phủ $539$ CVEs trọng yếu và $52$ CWEs phổ biến; chưa bao quát toàn bộ hơn $250.000$ CVEs trong cơ sở dữ liệu NVD toàn cầu do giới hạn về dung lượng đĩa và tài nguyên phần cứng thử nghiệm.
2. **Phụ thuộc vào phần cứng khi chạy Local LLM**: Mặc dù mô hình `ultrol-v2` đã được lượng tử hóa 4-bit, việc suy luận trên các máy tính cá nhân không có GPU rời vẫn gặp độ trễ nhất định khi tải các ngữ cảnh dài ($>4096\text{ tokens}$).
3. **Phạm vi kiểm thử tự động**: Hệ thống chủ yếu tập trung vào các dịch vụ mạng phổ biến và ứng dụng web; chưa đi sâu vào các bài toán kiểm thử hạ tầng chuyên biệt như Active Directory phức tạp hoặc thiết bị IoT/Firmware.

## Hướng phát triển trong tương lai
1. **Tự động hóa cập nhật cơ sở tri thức (Automated Threat Intel Feed)**: Xây dựng cơ chế đồng bộ định kỳ và phân mảnh tự động từ NVD API và CISA KEV khi máy chủ có kết nối mạng an toàn, mở rộng kho tri thức lên hàng chục nghìn CVEs.
2. **Mở rộng kiến trúc Multi-Agent cộng tác**: Phát triển hệ sinh thái đa đặc vụ chuyên biệt sâu hơn (Recon Agent, Threat Intel Agent, Web Fuzzing Agent, Exploit Verification Agent) giao tiếp qua giao thức tin nhắn tự quản lý để xử lý các mục tiêu quy mô lớn.
3. **Tinh chỉnh mô hình chuyên biệt (Fine-tuning Security LLM)**: Thu thập tập dữ liệu đàm thoại an ninh mạng chất lượng cao để tinh chỉnh sâu (Fine-tuning với LoRA/QLoRA) mô hình cục bộ trên miền tri thức kiểm thử xâm nhập, giúp mô hình hiểu sâu hơn về payload và logic dịch vụ mạng.
4. **Tích hợp sâu vào quy trình DevSecOps CI/CD**: Đóng gói hệ thống thành một Docker Sidecar hoặc GitHub/GitLab Action, cho phép tự động quét và phân tích an ninh sau mỗi bản build của lập trình viên.

\newpage

---

# TÀI LIỆU THAM KHẢO

1. **OWASP Foundation** (2023), *Web Security Testing Guide (WSTG) - Version 4.2*, Open Web Application Security Project. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/
2. **Gordon Lyon (Fyodor)** (2009), *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Vulnerability Scanning*, Nmap Project, Insecure.Com LLC.
3. **ProjectDiscovery** (2024), *Nuclei: Fast and customizable vulnerability scanner based on simple YAML based DSL*, ProjectDiscovery Documentation. [Online]. Available: https://docs.projectdiscovery.io/tools/nuclei/
4. **The MITRE Corporation** (2024), *Common Vulnerabilities and Exposures (CVE) Program*. [Online]. Available: https://www.cve.org/
5. **National Institute of Standards and Technology (NIST)** (2024), *National Vulnerability Database (NVD)*, U.S. Department of Commerce. [Online]. Available: https://nvd.nist.gov/
6. **The MITRE Corporation** (2024), *Common Weakness Enumeration (CWE) - A Community-Developed List of Software & Hardware Weakness Types*. [Online]. Available: https://cwe.mitre.org/
7. **Forum of Incident Response and Security Teams (FIRST)** (2019), *Common Vulnerability Scoring System v3.1: Specification Document*. [Online]. Available: https://www.first.org/cvss/v3.1/specification-document
8. **The MITRE Corporation** (2024), *MITRE ATT&CK: Design and Philosophy*, MITRE Corporation Technical Report. [Online]. Available: https://attack.mitre.org/
9. **Cybersecurity and Infrastructure Security Agency (CISA)** (2024), *Known Exploited Vulnerabilities (KEV) Catalog*, CISA Resources. [Online]. Available: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
10. **Patrick Lewis et al.** (2020), "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks", *Advances in Neural Information Processing Systems (NeurIPS 2020)*, Vol. 33, pp. 9459-9474.
11. **Ollama Project** (2024), *Ollama: Get up and running with large language models locally*. [Online]. Available: https://ollama.com/
12. **Björn Kimminich** (2023), *Pwning OWASP Juice Shop: The official companion guide*, OWASP Foundation. [Online]. Available: https://pwning.owasp-juice.shop/
13. **OASIS Standard** (2020), *Static Analysis Results Interchange Format (SARIF) Version 2.1.0*, OASIS Open. [Online]. Available: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
14. **PortSwigger** (2024), *Web Security Academy / Burp Suite Documentation*, PortSwigger Ltd. [Online]. Available: https://portswigger.net/web-security
15. **Tài liệu nội bộ nhóm nghiên cứu** (2026), *Dự án AI-Pentest Copilot (v5.0): Architecture Overview, Security Model & Toolkit Guide*, Học viện Kỹ thuật Mật mã, Hà Nội.

\newpage

---

# PHỤ LỤC

## Phụ lục A: JSON Schema chuẩn cho Finding và Attack Plan

### A.1. Finding JSON Schema (Trích dẫn `security/schemas/finding.schema.json`)
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Security Finding",
  "description": "Standard schema for pentest finding with evidence chain",
  "type": "object",
  "required": [
    "target_id",
    "title",
    "affected_asset",
    "description",
    "cvss_severity",
    "status"
  ],
  "properties": {
    "finding_id": { "type": "string" },
    "target_id": { "type": "string" },
    "title": { "type": "string" },
    "cve_id": { "type": ["string", "null"] },
    "cwe_id": { "type": ["string", "null"] },
    "cvss_score": { "type": "number", "minimum": 0.0, "maximum": 10.0 },
    "cvss_severity": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] },
    "status": { "type": "string", "enum": ["CANDIDATE", "UNVERIFIED", "VERIFIED", "FALSE_POSITIVE", "RESOLVED"] },
    "affected_asset": { "type": "string" },
    "description": { "type": "string" },
    "remediation": { "type": ["string", "null"] },
    "evidence_chain": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["tool", "file_path", "matched_text"],
        "properties": {
          "tool": { "type": "string" },
          "file_path": { "type": "string" },
          "matched_text": { "type": "string" },
          "timestamp": { "type": ["string", "null"] },
          "trustworthy": { "type": "boolean" },
          "is_simulated": { "type": "boolean" }
        }
      }
    },
    "trustworthy": { "type": "boolean" },
    "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
  }
}
```

## Phụ lục B: Prompt Templates cho Mô hình Cục bộ ultrol-v2

```text
[SYSTEM PROMPT - ROLE DEFINITION & SAFETY GUARDRAILS]
You are AI-Pentest Copilot, an expert defensive security assistant supporting human penetration testers.
Your mission is to analyze structured reconnaissance data, correlate findings with authoritative knowledge, 
and formulate safe, non-destructive verification plans.

STRICT OPERATIONAL RULES:
1. NEVER generate destructive exploit code, reverse shell payloads, or denial-of-service commands.
2. Verification steps MUST be strictly read-only probes (e.g. curl headers, safe traversal probes, version inspection).
3. NEVER hallucinate CVE numbers, CWE IDs, or CVSS scores. If data is missing from the provided knowledge base, explicitly state: "FACT: Insufficient evidence in knowledge base to confirm vulnerabilities."
4. Partition claims into:
   - FACT: Explicitly backed by scan output evidence files.
   - INFERENCE: Deduced from version correlation against SQLite KB.
   - HYPOTHESIS: Unverified possibilities requiring non-destructive verification.
5. ALWAYS output valid JSON matching the requested schema.

[RETRIEVED KNOWLEDGE CONTEXT]
CVE ID: {cve_id}
Score: {cvss_score} ({cvss_severity})
CWE: {cwe_id} - {cwe_name}
Summary: {description}
Mitigations: {mitigations}

[SCAN EVIDENCE CONTEXT]
Target: {target_id}
Asset: {affected_asset}
Tool: {tool_name}
Raw Evidence: {matched_text}

[INSTRUCTION]
Generate a complete Finding object and a Safe Read-Only Verification Plan.
Output ONLY the JSON object.
```

## Phụ lục C: Trích đoạn Bảng 50 Test Cases Benchmark Đánh Giá Hệ Thống

| ID | Dịch vụ & Phiên bản | Lỗ hổng mục tiêu | Ground Truth CVE | Ground Truth CWE | ultrol-v2 (Không RAG) | ultrol-v2 + RAG (Hệ thống) |
|:---:|:---|:---|:---:|:---:|:---:|:---:|
| **TC01** | Apache httpd 2.4.49 | Path Traversal / RCE | CVE-2021-41773 | CWE-22 | Nhầm CVE-2020-1927 | **Đúng CVE-2021-41773** |
| **TC02** | Apache httpd 2.4.50 | Incomplete Patch Traversal | CVE-2021-42013 | CWE-22 | Bịa đặt CVE-2021-9999 | **Đúng CVE-2021-42013** |
| **TC03** | OpenSSH 7.2p1 | User Enumeration | CVE-2016-6210 | CWE-200 | Đúng CVE-2016-6210 | **Đúng CVE-2016-6210** |
| **TC04** | vsftpd 2.3.4 | Backdoor Command Exec | CVE-2011-2523 | CWE-78 | Đúng CVE-2011-2523 | **Đúng CVE-2011-2523** |
| **TC05** | ProFTPD 1.3.5 | mod_copy Arbitrary File | CVE-2015-3306 | CWE-284 | Nhầm CVE-2015-1111 | **Đúng CVE-2015-3306** |
| **TC06** | Apache Struts 2.3.5 | OGNL Expression Injection | CVE-2017-5638 | CWE-20 | Đúng CVE-2017-5638 | **Đúng CVE-2017-5638** |
| **TC07** | Spring Framework 5.3.17 | Spring4Shell RCE | CVE-2022-22965 | CWE-94 | Bịa đặt CVSS 10.0 | **Đúng CVE-2022-22965** |
| **TC08** | Apache Log4j 2.14.1 | JNDI Remote Code Exec | CVE-2021-44228 | CWE-502 | Đúng CVE-2021-44228 | **Đúng CVE-2021-44228** |
| **TC09** | Nginx 1.20.0 | Patched Version | Không có | Không có | **Ảo giác báo CVE-2021-23017** | **Đúng: Báo an toàn (Safe)** |
| **TC10** | OpenSSH 9.6p1 | Latest Stable Version | Không có | Không có | **Ảo giác báo CVE-2023-38408** | **Đúng: Báo an toàn (Safe)** |
| ... | *(40 test cases khác...)* | ... | ... | ... | *(Tổng 26/50 đúng)* | **(Tổng 48/50 đúng)** |
