import React from "react";
import { X, FileCode, Copy, Check } from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

export const MainPanel: React.FC = () => {
  const { openTabs, activeTabId, setActiveTab, closeTab } = useWorkspaceStore();
  const [copied, setCopied] = React.useState(false);

  const activeTab = openTabs.find((t) => t.id === activeTabId);

  const handleCopy = () => {
    if (activeTab) {
      navigator.clipboard.writeText(activeTab.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!activeTab) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center bg-[#0a0d14] text-zinc-500 p-8 text-center select-none space-y-3">
        <div className="w-16 h-16 rounded-2xl bg-[#121829] border border-[#1e293b] flex items-center justify-center text-cyan-500 shadow-lg shadow-cyan-950/30">
          <FileCode className="w-8 h-8 stroke-1.5" />
        </div>
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-zinc-200">
            Security Workbench Editor
          </h3>
          <p className="text-xs text-zinc-400 max-w-sm leading-relaxed">
            Chọn một file bằng chứng từ Explorer để phân tích cấu trúc chứng cứ.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col bg-[#0a0d14] overflow-hidden">
      {/* Tabs Bar */}
      <div className="h-9 bg-[#0e1320] border-b border-[#1e293b] flex items-center overflow-x-auto select-none">
        {openTabs.map((tab) => (
          <div
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-3 py-2 border-r border-[#1e293b] text-xs cursor-pointer transition-colors ${
              tab.id === activeTabId
                ? "bg-[#0a0d14] text-cyan-300 border-t-2 border-t-cyan-400 font-semibold shadow-inner"
                : "text-zinc-400 hover:bg-[#151c2e] hover:text-zinc-200"
            }`}
          >
            <FileCode className="w-3 h-3 text-cyan-400 shrink-0" />
            <span className="truncate max-w-[140px] font-mono text-[11px]">{tab.title}</span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                closeTab(tab.id);
              }}
              className="p-0.5 hover:bg-[#1e293b] rounded text-zinc-500 hover:text-zinc-200 transition"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        ))}
      </div>

      {/* Editor Content Header */}
      <div className="h-8 bg-[#111827] border-b border-[#1e293b] flex items-center justify-between px-4 text-xs text-zinc-400">
        <div className="flex items-center space-x-2 truncate">
          <span className="text-zinc-500 text-[10px]">Đường dẫn:</span>
          <span className="truncate font-mono text-[11px] text-cyan-400/90">
            {activeTab.path}
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center space-x-1.5 px-2 py-0.5 rounded bg-[#151c2e] hover:bg-[#1e293b] border border-[#1e293b] text-zinc-300 hover:text-cyan-300 transition text-[11px]"
        >
          {copied ? (
            <Check className="w-3 h-3 text-emerald-400" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
          <span>{copied ? "Đã chép" : "Sao chép"}</span>
        </button>
      </div>

      {/* Content Viewer */}
      <div className="flex-1 overflow-auto p-4 font-mono text-xs bg-[#0a0d14]">
        <pre className="text-zinc-200 leading-relaxed whitespace-pre-wrap selection:bg-cyan-500/30">
          {activeTab.content}
        </pre>
      </div>
    </div>
  );
};
