import React from "react";
import {
  Shield,
  Plus,
  RefreshCw,
  LayoutGrid,
  FileCode,
  FileText,
  Network,
  Cpu,
  PanelLeft,
  PanelRight,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

export const Header: React.FC = () => {
  const {
    activeTarget,
    setTargetModalOpen,
    selectedProvider,
    setSelectedProvider,
    fetchInitialData,
    activeView,
    setActiveView,
    isExplorerOpen,
    toggleExplorer,
    isChatOpen,
    toggleChat,
  } = useWorkspaceStore();

  return (
    <header className="h-13 bg-[#0e1320] border-b border-[#1e293b] flex items-center justify-between px-4 select-none z-20 shadow-lg shadow-black/40">
      <div className="flex items-center space-x-4">
        {/* Brand Logo & Version */}
        <div className="flex items-center space-x-2.5">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 flex items-center justify-center shadow-md shadow-cyan-950/60">
            <div className="w-full h-full bg-[#0a0d14] rounded-[6px] flex items-center justify-center">
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="font-extrabold tracking-wider text-sm bg-gradient-to-r from-cyan-300 via-teal-200 to-blue-400 bg-clip-text text-transparent">
              AI-PENTEST COPILOT
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-semibold tracking-wide">
              v5.0 IDE
            </span>
          </div>
        </div>

        {/* Toggle Explorer Button */}
        <button
          onClick={toggleExplorer}
          title={isExplorerOpen ? "Đóng Workspace Explorer (Ctrl+B)" : "Mở Workspace Explorer (Ctrl+B)"}
          className={`p-1.5 rounded-lg transition-all border ${
            isExplorerOpen
              ? "bg-[#141c2e] text-cyan-400 border-cyan-800/60 shadow-sm"
              : "text-zinc-500 hover:text-zinc-200 border-transparent hover:border-[#1e293b] hover:bg-[#141c2e]/60"
          }`}
        >
          <PanelLeft className="w-4 h-4" />
        </button>

        {/* Segmented Control Tabs */}
        <div className="hidden sm:flex items-center bg-[#0a0d14]/90 border border-[#1e293b] rounded-xl p-1 text-xs shadow-inner">
          <button
            onClick={() => setActiveView("editor")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all duration-150 ${
              activeView === "editor"
                ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-sm"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-[#141c2e]/60 font-medium"
            }`}
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
            <span>Files & Editor</span>
          </button>
          <button
            onClick={() => setActiveView("findings")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all duration-150 ${
              activeView === "findings"
                ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-sm"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-[#141c2e]/60 font-medium"
            }`}
          >
            <LayoutGrid className="w-3.5 h-3.5 text-cyan-400" />
            <span>Findings Manager</span>
          </button>
          <button
            onClick={() => setActiveView("reports")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all duration-150 ${
              activeView === "reports"
                ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-sm"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-[#141c2e]/60 font-medium"
            }`}
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Pentest Report</span>
          </button>
          <button
            onClick={() => setActiveView("topology")}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg transition-all duration-150 ${
              activeView === "topology"
                ? "bg-gradient-to-r from-cyan-950 to-blue-950 text-cyan-300 border border-cyan-700/60 font-semibold shadow-sm"
                : "text-zinc-400 hover:text-zinc-200 hover:bg-[#141c2e]/60 font-medium"
            }`}
          >
            <Network className="w-3.5 h-3.5 text-cyan-400" />
            <span>Attack Graph</span>
          </button>
        </div>
      </div>

      {/* Right Actions */}
      <div className="flex items-center space-x-3">
        {/* Active Target Pill */}
        {activeTarget && (
          <div className="flex items-center space-x-2 text-xs bg-[#121829] border border-[#1e293b] px-3 py-1.5 rounded-lg shadow-sm">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-zinc-400 text-[11px]">Target:</span>
            <span className="text-emerald-400 font-mono font-semibold">
              {activeTarget.name}
            </span>
            <span className="text-[10px] text-zinc-500 font-mono uppercase bg-[#0a0d14] px-1.5 py-0.5 rounded border border-[#1e293b]">
              {activeTarget.type}
            </span>
          </div>
        )}

        {/* Add Target Button */}
        <button
          onClick={() => setTargetModalOpen(true)}
          className="flex items-center space-x-1.5 text-xs bg-gradient-to-r from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500 text-white px-3 py-1.5 rounded-lg transition-all duration-150 font-medium shadow-sm shadow-cyan-950/60 hover:shadow-cyan-900/40"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Target</span>
        </button>

        {/* AI Model Selector */}
        <div className="flex items-center space-x-1.5 text-xs bg-[#121829] border border-cyan-800/60 px-2.5 py-1.5 rounded-lg shadow-sm">
          <Cpu className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <select
            value={selectedProvider}
            onChange={(e) => setSelectedProvider(e.target.value)}
            className="bg-transparent text-cyan-200 focus:outline-none cursor-pointer font-medium text-xs pr-1"
          >
            <option value="gemini" className="bg-[#0e1320] text-cyan-300 font-bold">
              ✨ Gemini Flash
            </option>
            <option value="GPT-4o-mini" className="bg-[#0e1320] text-zinc-200">
              GPT-4o-mini
            </option>
            <option value="Claude-3-5-Sonnet" className="bg-[#0e1320] text-zinc-200">
              Claude-3-5-Sonnet
            </option>
            <option value="Ollama-Llama-3.1" className="bg-[#0e1320] text-zinc-200">
              Ollama (Llama-3.1)
            </option>
            <option value="offline" className="bg-[#0e1320] text-zinc-200">
              Local Offline Engine
            </option>
          </select>
        </div>

        {/* Refresh Button */}
        <button
          onClick={() => fetchInitialData()}
          title="Làm mới dữ liệu"
          className="p-1.5 hover:bg-[#1c253d] rounded-lg text-zinc-400 hover:text-cyan-300 transition-colors border border-transparent hover:border-[#1e293b]"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        {/* Toggle Chat Copilot Button */}
        <button
          onClick={toggleChat}
          title={isChatOpen ? "Thu gọn Copilot" : "Mở rộng Copilot"}
          className={`p-1.5 rounded-lg transition-all border ${
            isChatOpen
              ? "bg-[#141c2e] text-cyan-400 border-cyan-800/60 shadow-sm"
              : "text-zinc-500 hover:text-zinc-200 border-transparent hover:border-[#1e293b] hover:bg-[#141c2e]/60"
          }`}
        >
          <PanelRight className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
