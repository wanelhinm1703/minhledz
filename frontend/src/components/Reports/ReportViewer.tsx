import React, { useState, useEffect } from 'react'
import {
  FileText,
  Download,
  Copy,
  Check,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  Layout,
  Code,
} from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const ReportViewer: React.FC = () => {
  const { activeTarget } = useWorkspaceStore();
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [viewFormat, setViewFormat] = useState<'markdown' | 'html'>('markdown');

  const fetchReport = async () => {
    if (!activeTarget) return;
    setLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const res = await fetch(`/api/reports/${encodeURIComponent(targetKey)}`);
      if (res.ok) {
        const data = await res.json();
        setReportData(data);
      } else {
        setReportData(null);
      }
    } catch (e) {
      console.error('Failed to load report', e);
      setReportData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [activeTarget]);

  const handleGenerateReport = async () => {
    if (!activeTarget) return;
    setLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const res = await fetch(`/api/reports/generate/${encodeURIComponent(targetKey)}`, {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setReportData(data);
      }
    } catch (e) {
      console.error('Failed to generate report', e);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!reportData?.markdown_content) return;
    navigator.clipboard.writeText(reportData.markdown_content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!reportData?.markdown_content) return;
    const blob = new Blob([reportData.markdown_content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeTarget?.name || 'security'}_pentest_report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const targetKey = activeTarget ? (activeTarget.normalized_value || activeTarget.name) : '';

  return (
    <div className="flex-1 flex flex-col bg-[#141416] text-zinc-300 overflow-hidden select-none">
      {/* Top Banner */}
      <div className="p-3 border-b border-[#27272a] bg-[#101012] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 text-zinc-200 font-bold text-xs">
            <FileText className="w-4 h-4 text-cyan-400" />
            <span>PENTEST ASSESSMENT REPORT GENERATOR</span>
          </div>
          <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 font-normal">
            Target: <strong className="text-emerald-400">{activeTarget?.name || 'None'}</strong>
          </span>

          {reportData && (
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded p-0.5 text-xs">
              <button
                onClick={() => setViewFormat('markdown')}
                className={`flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] transition ${viewFormat === 'markdown'
                    ? 'bg-zinc-800 text-cyan-400 font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200'
                  }`}
              >
                <Code className="w-3 h-3" />
                <span>Markdown</span>
              </button>
              <button
                onClick={() => setViewFormat('html')}
                className={`flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] transition ${viewFormat === 'html'
                    ? 'bg-zinc-800 text-cyan-400 font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200'
                  }`}
              >
                <Layout className="w-3 h-3" />
                <span>Styled HTML</span>
              </button>
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {reportData && (
            <>
              <button
                onClick={handleCopy}
                className="flex items-center space-x-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-2.5 py-1.5 rounded transition font-medium border border-zinc-700"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy MD'}</span>
              </button>
              <button
                onClick={handleDownload}
                className="flex items-center space-x-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-2.5 py-1.5 rounded transition font-medium border border-zinc-700"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .MD</span>
              </button>
            </>
          )}
          <button
            onClick={handleGenerateReport}
            disabled={loading || !activeTarget}
            className="flex items-center space-x-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded transition font-medium"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{reportData ? 'Regenerate Report' : 'Generate Full Report'}</span>
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-4 w-full h-full">
        {loading ? (
          <div className="flex flex-col items-center justify-center h-64 space-y-3 text-zinc-400">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="text-xs">Đang tổng hợp dữ liệu và biên soạn báo cáo...</span>
          </div>
        ) : reportData ? (
          viewFormat === 'html' ? (
            <div className="w-full h-full rounded-xl overflow-hidden border border-zinc-800 shadow-2xl bg-[#0f172a]">
              <iframe
                src={`/api/reports/${encodeURIComponent(targetKey)}/html`}
                title="HTML Report Preview"
                className="w-full h-full border-0"
              />
            </div>
          ) : (
            <div className="max-w-5xl mx-auto bg-[#101012] border border-zinc-800 rounded-xl p-8 shadow-2xl space-y-6 text-zinc-300 font-sans text-xs leading-relaxed">
              <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-zinc-300 bg-transparent">
                {reportData.markdown_content}
              </pre>
            </div>
          )
        ) : (
          <div className="flex flex-col items-center justify-center h-80 space-y-4 text-center">
            <ShieldCheck className="w-12 h-12 text-zinc-600" />
            <div className="space-y-1">
              <h4 className="text-sm font-bold text-zinc-300">Chưa có báo cáo cho target này</h4>
              <p className="text-xs text-zinc-500 max-w-sm">
                Bấm <strong>"Generate Full Report"</strong> ở góc phải để tạo báo cáo kiểm thử hoàn chỉnh định dạng Markdown và HTML kèm lộ trình khắc phục.
              </p>
            </div>
            <button
              onClick={handleGenerateReport}
              disabled={!activeTarget}
              className="flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs px-4 py-2 rounded transition font-medium shadow-md"
            >
              <Sparkles className="w-4 h-4" />
              <span>Generate Report Now</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
