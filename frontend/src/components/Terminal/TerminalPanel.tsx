import React from 'react'
import { Terminal as TerminalIcon, Trash2 } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const TerminalPanel: React.FC = () => {
  const { terminalLogs } = useWorkspaceStore();

  return (
    <div className="h-40 bg-[#101012] border-t border-[#27272a] flex flex-col font-mono text-xs select-none">
      <div className="h-7 bg-[#141416] border-b border-[#27272a] px-3 flex items-center justify-between text-zinc-400">
        <div className="flex items-center space-x-2">
          <TerminalIcon className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-[11px] uppercase tracking-wider">Console & Tool Output</span>
        </div>
        <span className="text-[10px] text-zinc-500">Live Execution Log</span>
      </div>

      <div className="flex-1 p-2 overflow-y-auto space-y-0.5 text-zinc-300 font-mono text-[11px]">
        {terminalLogs.map((log, i) => (
          <div key={i} className="leading-relaxed">
            {log.startsWith('[+]') ? (
              <span className="text-emerald-400">{log}</span>
            ) : log.startsWith('[!]') ? (
              <span className="text-red-400">{log}</span>
            ) : log.startsWith('[*]') ? (
              <span className="text-cyan-400">{log}</span>
            ) : (
              <span className="text-zinc-400">{log}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
