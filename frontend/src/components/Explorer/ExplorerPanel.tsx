import React, { useState } from 'react'
import { Folder, FolderOpen, FileCode, ChevronRight, ChevronDown, Crosshair, FileText, Activity, Trash2 } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const ExplorerPanel: React.FC = () => {
  const { targets, scans, activeTarget, setActiveTarget, deleteTarget, deleteScan, openFile } = useWorkspaceStore();
  const [openSections, setOpenSections] = useState<{ [key: string]: boolean }>({
    targets: true,
    scans: true,
  });
  const [openFolders, setOpenFolders] = useState<{ [key: string]: boolean }>({});

  const toggle = (sec: string) => {
    setOpenSections((prev) => ({ ...prev, [sec]: !prev[sec] }));
  };

  const toggleFolder = (targetId: string) => {
    setOpenFolders((prev) => {
      // If not explicitly set, default was open (true), so invert to false
      const current = prev[targetId] !== undefined ? prev[targetId] : true;
      return { ...prev, [targetId]: !current };
    });
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
                  className={`group flex items-center justify-between px-2 py-1 rounded cursor-pointer transition ${activeTarget?.target_id === t.target_id
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60'
                      : 'text-zinc-400 hover:bg-zinc-800/50 hover:text-zinc-200'
                    }`}
                >
                  <div className="flex items-center space-x-1.5 truncate">
                    <span className="truncate">{t.name}</span>
                    <span className="text-[9px] text-zinc-500 uppercase">({t.type})</span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      if (window.confirm(`Xóa target "${t.name}" khỏi workspace?`)) {
                        deleteTarget(t.target_id);
                      }
                    }}
                    title="Xóa target"
                    className="opacity-0 group-hover:opacity-100 hover:text-red-400 p-0.5 rounded transition text-zinc-500"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
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
              {scans.map((scan) => {
                const isFolderOpen = openFolders[scan.target_id] !== undefined ? openFolders[scan.target_id] : true;

                return (
                  <div key={scan.target_id} className="space-y-0.5">
                    {/* Folder Header with Toggle and Delete */}
                    <div className="group flex items-center justify-between px-1.5 py-1 rounded hover:bg-zinc-800/60 cursor-pointer text-[11px] transition">
                      <div
                        onClick={() => toggleFolder(scan.target_id)}
                        className="flex items-center space-x-1.5 truncate flex-1"
                      >
                        {isFolderOpen ? (
                          <ChevronDown className="w-3 h-3 text-zinc-500 flex-shrink-0" />
                        ) : (
                          <ChevronRight className="w-3 h-3 text-zinc-500 flex-shrink-0" />
                        )}
                        {isFolderOpen ? (
                          <FolderOpen className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                        ) : (
                          <Folder className="w-3.5 h-3.5 text-amber-500 flex-shrink-0" />
                        )}
                        <span className="truncate text-zinc-300 font-medium" title={scan.target_id}>
                          {scan.target_id}
                        </span>
                        <span className="text-[9px] text-zinc-500 font-mono">
                          ({scan.evidence_files.length})
                        </span>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(`Xóa toàn bộ file scan của "${scan.target_id}" khỏi workspace?`)) {
                            deleteScan(scan.target_id);
                          }
                        }}
                        title="Xóa thư mục scan này"
                        className="opacity-0 group-hover:opacity-100 hover:text-red-400 p-0.5 rounded transition text-zinc-500 ml-1"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>

                    {/* Files List when Expanded */}
                    {isFolderOpen && (
                      <div className="ml-4 space-y-0.5 border-l border-zinc-800/70 pl-1">
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
                    )}
                  </div>
                );
              })}
              {scans.length === 0 && <span className="text-zinc-600 text-[11px] ml-4">No scans found.</span>}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
