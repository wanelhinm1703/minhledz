import React, { useState, useEffect, useRef } from "react";
import {
  FileText,
  FileDown,
  Download,
  Copy,
  Check,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Layout,
  Code,
  CheckCircle2,
  FileJson,
  Terminal,
  Layers,
  Award,
  BookOpen,
  ChevronDown,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

export const ReportViewer: React.FC = () => {
  const { activeTarget, appendTerminalLog } = useWorkspaceStore();
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [viewFormat, setViewFormat] = useState<"markdown" | "html" | "compliance" | "sarif">("markdown");
  const [showGuideModal, setShowGuideModal] = useState(false);
  const [showExportDropdown, setShowExportDropdown] = useState(false);
  const exportDropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        exportDropdownRef.current &&
        !exportDropdownRef.current.contains(event.target as Node)
      ) {
        setShowExportDropdown(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const targetKey = activeTarget
    ? activeTarget.normalized_value || activeTarget.name
    : "";

  const fetchReport = async () => {
    if (!targetKey) {
      setReportData(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`/api/reports/${encodeURIComponent(targetKey)}`);
      if (res.ok) {
        const data = await res.json();
        setReportData(data);
      } else {
        setReportData(null);
      }
    } catch (e) {
      console.error("Failed to load report", e);
      setReportData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [targetKey]);

  const handleGenerateReport = async () => {
    if (!targetKey) return;
    setLoading(true);
    try {
      const res = await fetch(
        `/api/reports/generate/${encodeURIComponent(targetKey)}`,
        {
          method: "POST",
        }
      );
      if (res.ok) {
        const data = await res.json();
        setReportData(data);
        appendTerminalLog(`[*] Generated full compliance report & SARIF for ${targetKey}`);
      }
    } catch (e) {
      console.error("Failed to generate report", e);
      appendTerminalLog(`[!] Failed to generate report: ${e}`);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = () => {
    const a = document.createElement("a");
    a.href = `/api/reports/${encodeURIComponent(targetKey)}/pdf?download=true`;
    a.download = `${targetKey}_pentest_report.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleDownloadMd = () => {
    if (!reportData?.markdown_content) return;
    const blob = new Blob([reportData.markdown_content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${targetKey}_pentest_report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleDownloadSarif = () => {
    if (!reportData?.sarif_content) return;
    const blob = new Blob([reportData.sarif_content], { type: "application/sarif+json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${targetKey}_report.sarif`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const compliance = reportData?.compliance_summary;

  return (
    <div className="flex-1 flex flex-col bg-[#0a0d14] text-zinc-300 overflow-hidden select-none">
      {/* Top Banner */}
      <div className="px-3 py-2 border-b border-[#1e293b] bg-[#0e1320] flex items-center justify-between gap-2 shadow-sm">
        <div className="flex items-center space-x-2.5 overflow-x-auto min-w-0">
          <div className="flex items-center space-x-1.5 text-zinc-200 font-bold text-xs shrink-0">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span className="tracking-wide">PENTEST REPORT</span>
          </div>
          <span className="text-[11px] px-2.5 py-0.5 rounded-lg bg-[#121829] border border-[#1e293b] text-zinc-300 shrink-0">
            Target: <strong className={targetKey ? "text-emerald-400 font-mono font-semibold" : "text-zinc-500 font-normal"}>{activeTarget?.name || targetKey || "Chưa chọn"}</strong>
          </span>

          {reportData && (
            <div className="flex items-center bg-[#0a0d14] border border-[#1e293b] rounded-xl p-0.5 text-xs shrink-0 shadow-inner">
              <button
                onClick={() => setViewFormat("markdown")}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg text-[11px] transition-all duration-150 ${
                  viewFormat === "markdown"
                    ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-xs"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
                title="Xem định dạng Markdown"
              >
                <Code className="w-3 h-3 text-cyan-400" />
                <span>Markdown</span>
              </button>
              <button
                onClick={() => setViewFormat("html")}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg text-[11px] transition-all duration-150 ${
                  viewFormat === "html"
                    ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-xs"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
                title="Xem trang HTML tương tác"
              >
                <Layout className="w-3 h-3 text-cyan-400" />
                <span>HTML</span>
              </button>
              <button
                onClick={() => setViewFormat("compliance")}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg text-[11px] transition-all duration-150 ${
                  viewFormat === "compliance"
                    ? "bg-gradient-to-r from-emerald-950 to-teal-950 text-emerald-300 border border-emerald-700/60 font-semibold shadow-xs"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
                title="Xem ma trận tuân thủ tiêu chuẩn"
              >
                <Award className="w-3 h-3 text-emerald-400" />
                <span>Compliance</span>
              </button>
              <button
                onClick={() => setViewFormat("sarif")}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg text-[11px] transition-all duration-150 ${
                  viewFormat === "sarif"
                    ? "bg-gradient-to-r from-amber-950 to-yellow-950 text-amber-300 border border-amber-700/60 font-semibold shadow-xs"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
                title="Xem chuẩn OASIS SARIF v2.1.0"
              >
                <FileJson className="w-3 h-3 text-amber-400" />
                <span>SARIF</span>
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-1.5 shrink-0">
          {reportData && (
            <>
              {/* Primary PDF Export Button */}
              <button
                onClick={handleDownloadPdf}
                className="flex items-center space-x-1 text-xs bg-rose-950/70 hover:bg-rose-900 border border-rose-700/80 text-rose-200 px-2.5 py-1 rounded transition font-semibold shadow-sm whitespace-nowrap"
                title="Xuất báo cáo PDF (Audit Report)"
              >
                <FileDown className="w-3.5 h-3.5 text-rose-400" />
                <span>Export PDF</span>
              </button>

              {/* Consolidated Export Dropdown for other formats */}
              <div className="relative" ref={exportDropdownRef}>
                <button
                  onClick={() => setShowExportDropdown(!showExportDropdown)}
                  className="flex items-center space-x-1 text-xs bg-zinc-900 hover:bg-zinc-800 text-zinc-300 px-2 py-1 rounded transition font-medium border border-zinc-700 whitespace-nowrap"
                  title="More Export Formats"
                >
                  <Download className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Export</span>
                  <ChevronDown className={`w-3 h-3 text-zinc-400 transition-transform ${showExportDropdown ? "rotate-180" : ""}`} />
                </button>

                {showExportDropdown && (
                  <div className="absolute right-0 mt-1.5 w-56 bg-[#18181b] border border-zinc-700 rounded-lg shadow-2xl py-1.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
                    <div className="px-3 py-1 text-[10px] uppercase font-bold text-zinc-500 tracking-wider">
                      Export Formats
                    </div>
                    <button
                      onClick={() => {
                        handleDownloadPdf();
                        setShowExportDropdown(false);
                      }}
                      className="w-full flex items-center space-x-2.5 px-3 py-2 text-xs text-left hover:bg-zinc-800 text-rose-300 hover:text-rose-200 transition"
                    >
                      <FileDown className="w-4 h-4 text-rose-400 shrink-0" />
                      <div>
                        <div className="font-semibold">Audit PDF Report</div>
                        <div className="text-[10px] text-zinc-400">Executive & Technical Summary</div>
                      </div>
                    </button>
                    <button
                      onClick={() => {
                        handleDownloadMd();
                        setShowExportDropdown(false);
                      }}
                      className="w-full flex items-center space-x-2.5 px-3 py-2 text-xs text-left hover:bg-zinc-800 text-cyan-300 hover:text-cyan-200 transition"
                    >
                      <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                      <div>
                        <div className="font-medium">Markdown (.md)</div>
                        <div className="text-[10px] text-zinc-400">Standard audit report text</div>
                      </div>
                    </button>
                    <button
                      onClick={() => {
                        handleDownloadSarif();
                        setShowExportDropdown(false);
                      }}
                      className="w-full flex items-center space-x-2.5 px-3 py-2 text-xs text-left hover:bg-zinc-800 text-amber-300 hover:text-amber-200 transition"
                    >
                      <FileJson className="w-4 h-4 text-amber-400 shrink-0" />
                      <div>
                        <div className="font-medium">SARIF 2.1.0 (.sarif)</div>
                        <div className="text-[10px] text-zinc-400">CI/CD & GitHub Security tab</div>
                      </div>
                    </button>
                  </div>
                )}
              </div>

              {/* CI/CD Guide */}
              <button
                onClick={() => setShowGuideModal(true)}
                className="flex items-center space-x-1 text-xs bg-zinc-900 hover:bg-zinc-800 text-cyan-400 px-2 py-1 rounded transition font-medium border border-cyan-900/60 whitespace-nowrap"
                title="View GitHub Actions & GitLab CI integration guidance"
              >
                <BookOpen className="w-3.5 h-3.5" />
                <span>CI/CD</span>
              </button>

              {/* Copy */}
              <button
                onClick={() => handleCopy(viewFormat === "sarif" ? reportData.sarif_content : reportData.markdown_content)}
                className="flex items-center space-x-1 text-xs bg-zinc-900 hover:bg-zinc-800 text-zinc-200 px-2 py-1 rounded transition font-medium border border-zinc-700 whitespace-nowrap"
                title="Copy current view content to clipboard"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-zinc-400" />}
                <span>{copied ? "Copied" : "Copy"}</span>
              </button>
            </>
          )}

          {/* Regenerate Button */}
          <button
            onClick={handleGenerateReport}
            disabled={loading}
            className="flex items-center space-x-1.5 bg-cyan-700/80 hover:bg-cyan-600 border border-cyan-500/60 disabled:opacity-50 text-white text-xs px-2.5 py-1 rounded transition font-semibold whitespace-nowrap shadow-sm"
            title="Tái tạo báo cáo đầy đủ với dữ liệu mới nhất"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>{loading ? "Generating..." : reportData ? "Regenerate" : "Generate"}</span>
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-4 w-full h-full">
        {loading ? (
          <div className="flex flex-col items-center justify-center h-64 space-y-3 text-zinc-400">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs">Đang tổng hợp dữ liệu, ánh xạ tiêu chuẩn quốc tế và xuất SARIF...</span>
          </div>
        ) : reportData ? (
          viewFormat === "html" ? (
            <div className="w-full h-full rounded-xl overflow-hidden border border-zinc-800 shadow-2xl bg-[#0f172a]">
              <iframe
                src={`/api/reports/${encodeURIComponent(targetKey)}/html`}
                title="HTML Report Preview"
                className="w-full h-full border-0"
              />
            </div>
          ) : viewFormat === "sarif" ? (
            <div className="max-w-5xl mx-auto bg-[#101012] border border-zinc-800 rounded-xl p-6 shadow-2xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800 text-xs">
                <div className="flex items-center space-x-2 text-amber-400 font-semibold">
                  <FileJson className="w-4 h-4" />
                  <span>OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format)</span>
                </div>
                <span className="text-[11px] text-zinc-400 font-mono">
                  Schema: sarif-schema-2.1.0.json | Target: {targetKey}
                </span>
              </div>
              <pre className="whitespace-pre-wrap font-mono text-xs text-amber-200/90 bg-[#0d0d10] p-4 rounded-lg border border-zinc-800/80 overflow-x-auto max-h-[70vh]">
                {reportData.sarif_content || "No SARIF content generated yet."}
              </pre>
            </div>
          ) : viewFormat === "compliance" ? (
            <div className="max-w-5xl mx-auto space-y-6">
              {/* Compliance Score Card */}
              <div className="bg-[#121215] border border-zinc-800 rounded-xl p-6 shadow-xl flex items-center justify-between">
                <div>
                  <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-zinc-400">
                    <Award className="w-4 h-4 text-emerald-400" />
                    <span>Đánh giá Hiện trạng An ninh & Mức độ Tuân thủ Tiêu chuẩn</span>
                  </div>
                  <h2 className="text-lg font-bold text-zinc-100 mt-1">
                    Trạng thái Đánh giá Tiêu chuẩn Quốc tế (Compliance 2.0)
                  </h2>
                  <div className="flex items-center space-x-3 mt-3">
                    <span
                      className={`text-xs px-2.5 py-1 rounded font-bold font-mono ${
                        compliance?.critical_high_count > 0
                          ? "bg-red-950/60 text-red-400 border border-red-800"
                          : "bg-emerald-950/60 text-emerald-400 border border-emerald-800"
                      }`}
                    >
                      {compliance?.status === "PASSED"
                        ? "ĐẠT (PASSED)"
                        : compliance?.status === "FAILED"
                        ? "KHÔNG ĐẠT (FAILED)"
                        : compliance?.status || "CHỜ ĐỐI SOÁT"}
                    </span>
                    <span className="text-xs text-zinc-400">
                      Vi phạm đang tồn tại:{" "}
                      <strong className="text-zinc-200">
                        {compliance?.total_active_violations || 0}
                      </strong>
                    </span>
                    <span className="text-xs text-zinc-400">
                      Nghiêm trọng / Cao:{" "}
                      <strong className="text-red-400">
                        {compliance?.critical_high_count || 0}
                      </strong>
                    </span>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-xs text-zinc-400">Điểm Đánh giá Tuân thủ</div>
                  <div
                    className={`text-4xl font-extrabold font-mono mt-0.5 ${
                      (compliance?.compliance_score || 100) >= 80
                        ? "text-emerald-400"
                        : (compliance?.compliance_score || 100) >= 50
                        ? "text-amber-400"
                        : "text-red-400"
                    }`}
                  >
                    {compliance?.compliance_score || 100}/100
                  </div>
                </div>
              </div>

              {/* OWASP Top 10 Breakdown */}
              <div className="bg-[#121215] border border-zinc-800 rounded-xl p-6 space-y-3">
                <h3 className="text-sm font-bold text-cyan-300 flex items-center space-x-2">
                  <Layers className="w-4 h-4" />
                  <span>Độ phủ Khung Tiêu chuẩn OWASP Top 10 (2021/2025)</span>
                </h3>
                <p className="text-xs text-zinc-400">
                  Phát hiện lỗ hổng được ánh xạ tự động vào danh mục kiểm toán bảo mật ứng dụng OWASP:
                </p>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  {compliance?.owasp_top_10_breakdown && Object.keys(compliance.owasp_top_10_breakdown).length > 0 ? (
                    Object.entries(compliance.owasp_top_10_breakdown).map(([k, v]) => (
                      <div
                        key={k}
                        className="p-3 bg-zinc-900 border border-zinc-800 rounded flex items-center justify-between text-xs"
                      >
                        <span className="font-semibold text-zinc-200">OWASP {k}</span>
                        <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-300 font-mono font-bold">
                          {String(v)} vi phạm
                        </span>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 bg-zinc-900 border border-zinc-800 rounded text-xs text-emerald-400 col-span-2">
                      ✓ Không có vi phạm OWASP Top 10 nào được ghi nhận trên mục tiêu này.
                    </div>
                  )}
                </div>
              </div>

              {/* CWE Top 25 Hit List */}
              <div className="bg-[#121215] border border-zinc-800 rounded-xl p-6 space-y-3">
                <h3 className="text-sm font-bold text-amber-300 flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-amber-400" />
                  <span>Danh sách Điểm yếu Nguy hiểm nhất MITRE CWE Top 25</span>
                </h3>
                {compliance?.cwe_top_25_hits && compliance.cwe_top_25_hits.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-zinc-800 text-zinc-400">
                          <th className="py-2 px-3">Thứ hạng Top 25</th>
                          <th className="py-2 px-3">Mã CWE</th>
                          <th className="py-2 px-3">Tên Điểm yếu Phần mềm</th>
                          <th className="py-2 px-3">Mức độ Rủi ro</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-zinc-800/60">
                        {compliance.cwe_top_25_hits.map((h: any, idx: number) => (
                          <tr key={idx} className="hover:bg-zinc-900/50 font-mono">
                            <td className="py-2 px-3 text-amber-400 font-bold">#{h.rank}</td>
                            <td className="py-2 px-3 text-cyan-300">{h.cwe_id}</td>
                            <td className="py-2 px-3 text-zinc-200 font-sans">{h.name}</td>
                            <td className="py-2 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300">
                                {h.severity}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded text-xs text-emerald-400">
                    ✓ Không phát hiện lỗ hổng nào thuộc danh sách CWE Top 25 nguy hiểm nhất.
                  </div>
                )}
              </div>

              {/* NIST SP 800-115 & CIS Controls */}
              <div className="bg-[#121215] border border-zinc-800 rounded-xl p-6 space-y-3">
                <h3 className="text-sm font-bold text-indigo-300 flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-indigo-400" />
                  <span>Đối chiếu Tiêu chuẩn NIST SP 800-115 & CIS Controls v8</span>
                </h3>
                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded space-y-1.5">
                    <span className="font-semibold text-zinc-300">Các phần đánh giá NIST SP 800-115:</span>
                    <ul className="list-disc list-inside space-y-1 text-zinc-400">
                      {(compliance?.nist_sp_800_115_sections || ["§4.2 Port Scanning (Quét cổng)", "§4.4 Web App Scanning (Quét Web)"]).map(
                        (s: string, idx: number) => (
                          <li key={idx} className="font-mono text-[11px] text-cyan-300">
                            {s}
                          </li>
                        )
                      )}
                    </ul>
                  </div>

                  <div className="p-3 bg-zinc-900 border border-zinc-800 rounded space-y-1.5">
                    <span className="font-semibold text-zinc-300">Biện pháp kiểm soát CIS Controls v8:</span>
                    <ul className="list-disc list-inside space-y-1 text-zinc-400">
                      {(compliance?.cis_controls_v8 || ["CIS Control 7 (Quản lý Lỗ hổng)", "CIS Control 16 (Bảo mật Ứng dụng)"]).map(
                        (c: string, idx: number) => (
                          <li key={idx} className="font-mono text-[11px] text-indigo-300">
                            {c}
                          </li>
                        )
                      )}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="max-w-5xl mx-auto bg-[#0e1320] border border-[#1e293b] rounded-xl p-8 shadow-2xl space-y-6 text-zinc-200 font-sans text-sm leading-relaxed">
              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-zinc-200 bg-transparent selection:bg-cyan-500/30">
                {reportData.markdown_content}
              </pre>
            </div>
          )
        ) : !targetKey ? (
          <div className="flex flex-col items-center justify-center h-80 space-y-4 text-center">
            <ShieldAlert className="w-12 h-12 text-zinc-600" />
            <div className="space-y-1">
              <h4 className="text-sm font-bold text-zinc-300">Chưa chọn mục tiêu</h4>
              <p className="text-xs text-zinc-500 max-w-sm">
                Vui lòng thêm hoặc chọn một mục tiêu trong Workspace Explorer bên trái để xem hoặc khởi tạo báo cáo kiểm thử bảo mật.
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center h-80 space-y-4 text-center">
            <ShieldCheck className="w-12 h-12 text-zinc-600" />
            <div className="space-y-1">
              <h4 className="text-sm font-bold text-zinc-300">Chưa có báo cáo cho mục tiêu này</h4>
              <p className="text-xs text-zinc-500 max-w-sm">
                Khởi tạo báo cáo kiểm thử hoàn chỉnh bao gồm các định dạng PDF, Markdown, HTML, SARIF và Ma trận Tuân thủ.
              </p>
            </div>
            <button
              onClick={handleGenerateReport}
              className="flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs px-4 py-2 rounded transition font-medium shadow-md"
            >
              <Sparkles className="w-4 h-4" />
              <span>Tạo Báo cáo Ngay</span>
            </button>
          </div>
        )}
      </div>

      {/* DevSecOps Guide Modal */}
      {showGuideModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-[#18181b] border border-zinc-700 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center space-x-2 text-cyan-400 font-bold text-sm">
                <Terminal className="w-4 h-4" />
                <span>Tài liệu Tích hợp DevSecOps CI/CD (SARIF 2.1.0)</span>
              </div>
              <button
                onClick={() => setShowGuideModal(false)}
                className="text-zinc-500 hover:text-zinc-300 px-1 py-0.5 rounded"
              >
                ✕
              </button>
            </div>

            <p className="text-zinc-300">
              Bạn có thể tích hợp trực tiếp file <strong>.SARIF</strong> vào quy trình tự động hóa GitHub Actions hoặc GitLab CI để kích hoạt cơ chế tự động chặn build (Break-Build Policy) khi phát hiện lỗ hổng nghiêm trọng:
            </p>

            <div className="space-y-3">
              <div>
                <span className="font-semibold text-emerald-400">1. GitHub Actions (Tải SARIF lên Code Scanning):</span>
                <pre className="mt-1 p-3 rounded bg-zinc-950 border border-zinc-800 text-[11px] font-mono text-zinc-300 overflow-x-auto">
{`- name: Upload SARIF to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'toolkit/10-reports/${targetKey}_report.sarif'`}
                </pre>
              </div>

              <div>
                <span className="font-semibold text-indigo-400">2. Chính sách Break-Build (Chặn hợp nhất PR nếu có lỗ hổng Critical):</span>
                <pre className="mt-1 p-3 rounded bg-zinc-950 border border-zinc-800 text-[11px] font-mono text-zinc-300 overflow-x-auto">
{`# File cấu hình: .github/workflows/ai-pentest-scan.yml đã được tạo sẵn trong dự án!`}
                </pre>
              </div>
            </div>

            <div className="pt-3 border-t border-zinc-800 flex justify-end">
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-medium text-xs"
              >
                Đã hiểu
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
