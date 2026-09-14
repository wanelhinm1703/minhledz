import React, { useState } from 'react'
import { Folder, FileCode, ChevronRight, ChevronDown, Crosshair, FileText, Activity } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const ExplorerPanel: React.FC = () => {
  const { targets, scans, activeTarget, setActiveTarget, openFile } = useWorkspaceStore();
  const [openSections, setOpenSections] = useState<{ [key: string]: boolean }>({
    targets: true,
    scans: true,
  });

  const toggle = (sec: string) => {
    setOpenSections((prev) => ({ ...prev, [sec]: !prev[sec] }));
  };

  return (
    <aside className="w-64 bg-[#121214] border-r border-[#27272a] flex flex-col h-full select-none text-xs">
      <div className="p-3 border-b border-[#27272a] text-zinc-400 font-semibold uppercase tracking-wider flex items-center justify-between">
        <span>Workspace Explorer</span>
      </div>

      <div className="flex-1 overflow-y-auto p-2 space-y-3">
        {/* Targets Section */}
        <div>
          <button
            onClick={() => toggle('targets')}
            className="w-full flex items-center space-x-1.5 text-zinc-400 hover:text-zinc-200 font-bold py-1"
          >
            {openSections.targets ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
            <span>TARGETS ({targets.length})</span>
          </button>

          {openSections.targets && (
            <div className="ml-4 mt-1 space-y-0.5">
              {targets.map((t) => (
                <div
                  key={t.target_id}
                  onClick={() => setActiveTarget(t)}
                  className={`flex items-center justify-between px-2 py-1 rounded cursor-pointer transition ${
                    activeTarget?.target_id === t.target_id
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60'
                      : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'
                  }`}
                >
                  <span className="truncate">{t.name}</span>
                  <span className="text-[10px] text-zinc-500 uppercase">{t.type}</span>
                </div>
              ))}
              {targets.length === 0 && <span className="text-zinc-600 text-[11px]">No targets added yet.</span>}
            </div>
          )}
        </div>

        {/* Scans & Evidence Section */}
        <div>
          <button
            onClick={() => toggle('scans')}
            className="w-full flex items-center space-x-1.5 text-zinc-400 hover:text-zinc-200 font-bold py-1"
          >
            {openSections.scans ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
            <span>SCANS & EVIDENCE</span>
          </button>

          {openSections.scans && (
            <div className="ml-2 mt-1 space-y-2">
              {scans.map((scan) => (
                <div key={scan.target_id} className="space-y-1">
                  <div className="text-zinc-400 font-medium px-2 py-0.5 flex items-center space-x-1 text-[11px]">
                    <Folder className="w-3 h-3 text-amber-500" />
                    <span className="truncate">{scan.target_id}</span>
                  </div>
                  <div className="ml-4 space-y-0.5">
                    {scan.evidence_files.map((file) => (
                      <button
                        key={file.rel_path}
                        onClick={() => openFile({ name: file.name, rel_path: file.rel_path })}
                        className="w-full text-left flex items-center space-x-1.5 px-2 py-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-cyan-300 transition text-[11px]"
                      >
                        {file.type === 'structured' ? (
                          <FileCode className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                        ) : (
                          <FileText className="w-3 h-3 text-zinc-500 flex-shrink-0" />
                        )}
                        <span className="truncate">{file.name}</span>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
              {scans.length === 0 && <span className="text-zinc-600 text-[11px] ml-4">No scans found.</span>}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
