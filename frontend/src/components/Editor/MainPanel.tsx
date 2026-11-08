import React from 'react'
import { X, FileCode, Copy, Check } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

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
      <div className="flex-1 flex flex-col items-center justify-center bg-[#18181b] text-zinc-500 p-8 text-center select-none">
        <FileCode className="w-16 h-16 text-zinc-700 mb-4 stroke-1" />
        <h3 className="text-sm font-semibold text-zinc-400 mb-1">Security Workbench Editor</h3>
        <p className="text-xs text-zinc-600 max-w-sm">
          Select an evidence file (e.g. <code className="text-cyan-400">nmap_result.json</code>, <code className="text-emerald-400">nuclei_result.json</code>) from the Explorer to inspect structured evidence.
        </p>
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col bg-[#18181b] overflow-hidden">
      {/* Tabs Bar */}
      <div className="h-9 bg-[#121214] border-b border-[#27272a] flex items-center overflow-x-auto select-none">
        {openTabs.map((tab) => (
          <div
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-3 py-2 border-r border-[#27272a] text-xs cursor-pointer transition ${tab.id === activeTabId
                ? 'bg-[#18181b] text-cyan-300 border-t-2 border-t-cyan-500 font-medium'
                : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
          >
            <span className="truncate max-w-[140px]">{tab.title}</span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                closeTab(tab.id);
              }}
              className="p-0.5 hover:bg-zinc-700 rounded text-zinc-500 hover:text-zinc-200 transition"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        ))}
      </div>

      {/* Editor Content Header */}
      <div className="h-8 bg-[#1a1a1f] border-b border-[#27272a] flex items-center justify-between px-4 text-xs text-zinc-400">
        <span className="truncate font-mono text-[11px] text-zinc-500">{activeTab.path}</span>
        <button
          onClick={handleCopy}
          className="flex items-center space-x-1 hover:text-zinc-200 transition text-[11px]"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied!' : 'Copy'}</span>
        </button>
      </div>

      {/* Content Viewer */}
      <div className="flex-1 overflow-auto p-4 font-mono text-xs bg-[#18181b]">
        <pre className="text-zinc-300 leading-relaxed whitespace-pre-wrap">{activeTab.content}</pre>
      </div>
    </div>
  );
};
