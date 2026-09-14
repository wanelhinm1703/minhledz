import React from 'react'
import { Shield, Plus, Terminal, RefreshCw } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const Header: React.FC = () => {
  const { activeTarget, setTargetModalOpen, selectedProvider, setSelectedProvider, fetchInitialData } = useWorkspaceStore();

  return (
    <header className="h-12 bg-[#121214] border-b border-[#27272a] flex items-center justify-between px-4 select-none z-10">
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2 text-cyan-400 font-bold tracking-wider">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span>AI-PENTEST COPILOT</span>
        </div>
        <span className="text-xs px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 font-normal">v5.0 IDE</span>
      </div>

      <div className="flex items-center space-x-4">
        {activeTarget && (
          <div className="flex items-center space-x-2 text-xs bg-zinc-900 border border-zinc-700 px-3 py-1 rounded">
            <span className="text-zinc-400">Target:</span>
            <span className="text-emerald-400 font-medium">{activeTarget.name}</span>
            <span className="text-zinc-500">({activeTarget.type})</span>
          </div>
        )}

        <button
          onClick={() => setTargetModalOpen(true)}
          className="flex items-center space-x-1 text-xs bg-cyan-600 hover:bg-cyan-500 text-white px-3 py-1.5 rounded transition font-medium"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Target</span>
        </button>

        <div className="flex items-center space-x-2 text-xs bg-zinc-900 border border-zinc-800 px-2 py-1 rounded">
          <span className="text-zinc-500">AI:</span>
          <select
            value={selectedProvider}
            onChange={(e) => setSelectedProvider(e.target.value)}
            className="bg-transparent text-zinc-300 focus:outline-none cursor-pointer"
          >
            <option value="GPT-4o-mini">GPT-4o-mini</option>
            <option value="Claude-3-5-Sonnet">Claude-3-5-Sonnet</option>
            <option value="Ollama-Llama-3.1">Ollama (Llama-3.1)</option>
            <option value="Custom-Local">Custom Local</option>
          </select>
        </div>

        <button
          onClick={() => fetchInitialData()}
          title="Refresh Workspace"
          className="p-1.5 hover:bg-zinc-800 rounded text-zinc-400 hover:text-zinc-200 transition"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
