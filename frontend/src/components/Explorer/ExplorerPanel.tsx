import React, { useState } from "react";
import {
  Folder,
  FolderOpen,
  FileCode,
  ChevronRight,
  ChevronDown,
  Crosshair,
  FileText,
  Activity,
  Trash2,
  FolderTree,
  PanelLeftClose,
  ChevronsDownUp,
  ChevronsUpDown,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

interface ExplorerPanelProps {
  onClose?: () => void;
}

export const ExplorerPanel: React.FC<ExplorerPanelProps> = ({ onClose }) => {
  const {
    targets,
    scans,
    activeTarget,
    setActiveTarget,
    deleteTarget,
    deleteScan,
    openFile,
  } = useWorkspaceStore();
  const [openSections, setOpenSections] = useState<{ [key: string]: boolean }>({
    targets: true,
    scans: true,
  });
  const [openFolders, setOpenFolders] = useState<{ [key: string]: boolean }>({});
  const [allCollapsed, setAllCollapsed] = useState(false);

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

  const toggleAllFolders = () => {
    if (allCollapsed) {
      // Expand all
      setOpenSections({ targets: true, scans: true });
      const newFolders: Record<string, boolean> = {};
      scans.forEach((scan) => {
        newFolders[scan.target_id] = true;
        scan.evidence_files.forEach((file) => {
          if (file.tool) newFolders[`${scan.target_id}:${file.tool}`] = true;
        });
        if (scan.tool_statuses) {
          Object.keys(scan.tool_statuses).forEach((t) => {
            newFolders[`${scan.target_id}:${t}`] = true;
          });
        }
      });
      setOpenFolders(newFolders);
      setAllCollapsed(false);
    } else {
      // Collapse all
      const newFolders: Record<string, boolean> = {};
      scans.forEach((scan) => {
        newFolders[scan.target_id] = false;
        scan.evidence_files.forEach((file) => {
          if (file.tool) newFolders[`${scan.target_id}:${file.tool}`] = false;
        });
        if (scan.tool_statuses) {
          Object.keys(scan.tool_statuses).forEach((t) => {
            newFolders[`${scan.target_id}:${t}`] = false;
          });
        }
      });
      setOpenFolders(newFolders);
      setAllCollapsed(true);
    }
  };

  return (
    <aside className="w-full bg-[#0e1320] border-r border-[#1e293b] flex flex-col h-full select-none text-xs">
      <div className="p-3 border-b border-[#1e293b] text-zinc-300 font-semibold uppercase tracking-wider flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <FolderTree className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-bold text-zinc-200">Workspace Explorer</span>
        </div>
        <div className="flex items-center space-x-1">
          <button
            onClick={toggleAllFolders}
            title={allCollapsed ? "Mở rộng tất cả thư mục scan (Expand all)" : "Thu gọn tất cả thư mục scan (Collapse all)"}
            className="p-1 hover:bg-[#151c2e] text-zinc-400 hover:text-cyan-300 rounded transition"
          >
            {allCollapsed ? (
              <ChevronsUpDown className="w-3.5 h-3.5" />
            ) : (
              <ChevronsDownUp className="w-3.5 h-3.5" />
            )}
          </button>
          {onClose && (
            <button
              onClick={onClose}
              title="Thu gọn panel Explorer (Đóng vào)"
              className="p-1 hover:bg-[#151c2e] text-zinc-400 hover:text-cyan-300 rounded transition"
            >
              <PanelLeftClose className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-2 space-y-3">
        {/* Targets Section */}
        <div>
          <button
            onClick={() => toggle("targets")}
            className="w-full flex items-center justify-between text-zinc-400 hover:text-zinc-200 font-bold py-1.5 px-1 rounded hover:bg-[#121829] transition"
          >
            <div className="flex items-center space-x-1.5">
              {openSections.targets ? (
                <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5 text-zinc-500" />
              )}
              <Crosshair className="w-3.5 h-3.5 text-cyan-400" />
              <span className="tracking-wide text-[11px]">TARGETS</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-[#151c2e] text-zinc-400 border border-[#1e293b]">
              {targets.length}
            </span>
          </button>

          {openSections.targets && (
            <div className="ml-2 mt-1 space-y-1">
              {targets.map((t) => (
                <div
                  key={t.target_id}
                  onClick={() => setActiveTarget(t)}
                  className={`group flex items-center justify-between px-2 py-1.5 rounded-lg cursor-pointer transition-all duration-150 ${
                    activeTarget?.target_id === t.target_id
                      ? "bg-cyan-950/60 text-cyan-300 border-l-2 border-cyan-400 border-y border-r border-cyan-800/40 shadow-sm shadow-cyan-950/40 font-medium"
                      : "text-zinc-400 hover:bg-[#151c2e] hover:text-zinc-200 border border-transparent"
                  }`}
                >
                  <div className="flex items-center space-x-1.5 truncate">
                    <span className="truncate">{t.name}</span>
                    <span className="text-[9px] text-zinc-500 font-mono uppercase bg-[#0a0d14] px-1 py-0.2 rounded border border-[#1e293b]">
                      {t.type}
                    </span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      if (
                        window.confirm(`Xóa target "${t.name}" khỏi workspace?`)
                      ) {
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
              {targets.length === 0 && (
                <span className="text-zinc-600 text-[11px] block pl-2 py-1">
                  Chưa có target nào được thêm.
                </span>
              )}
            </div>
          )}
        </div>

        {/* Scans & Evidence Section */}
        <div>
          <button
            onClick={() => toggle("scans")}
            className="w-full flex items-center justify-between text-zinc-400 hover:text-zinc-200 font-bold py-1.5 px-1 rounded hover:bg-[#121829] transition"
          >
            <div className="flex items-center space-x-1.5">
              {openSections.scans ? (
                <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
              ) : (
                <ChevronRight className="w-3.5 h-3.5 text-zinc-500" />
              )}
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span className="tracking-wide text-[11px]">SCANS & EVIDENCE</span>
            </div>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-[#151c2e] text-zinc-400 border border-[#1e293b]">
              {scans.length}
            </span>
          </button>

          {openSections.scans && (
            <div className="ml-1 mt-1 space-y-1.5">
              {scans.map((scan) => {
                const isFolderOpen =
                  openFolders[scan.target_id] !== undefined
                    ? openFolders[scan.target_id]
                    : true;

                return (
                  <div key={scan.target_id} className="space-y-0.5">
                    {/* Folder Header with Toggle and Delete */}
                    <div className="group flex items-center justify-between px-2 py-1 rounded-lg hover:bg-[#151c2e] cursor-pointer text-[11px] transition">
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
                        <span
                          className="truncate text-zinc-200 font-medium"
                          title={scan.target_id}
                        >
                          {scan.target_id}
                        </span>
                        <span className="text-[9px] text-zinc-500 font-mono">
                          ({scan.evidence_files.length})
                        </span>
                      </div>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (
                            window.confirm(
                              `Xóa toàn bộ file scan của "${scan.target_id}" khỏi workspace?`,
                            )
                          ) {
                            deleteScan(scan.target_id);
                          }
                        }}
                        title="Xóa thư mục scan này"
                        className="opacity-0 group-hover:opacity-100 hover:text-red-400 p-0.5 rounded transition text-zinc-500 ml-1"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>

                    {/* Tool Tree when Target is Expanded */}
                    {isFolderOpen && (
                      <div className="ml-3.5 space-y-1 border-l border-[#1e293b] pl-2 pt-0.5">
                        {(() => {
                          const toolGroups =
                            scan.evidence_files.reduce<
                              Record<string, typeof scan.evidence_files>
                            >((acc, file) => {
                              const t = file.tool || "general";
                              if (!acc[t]) acc[t] = [];
                              acc[t].push(file);
                              return acc;
                            }, {});

                          if (scan.tool_statuses) {
                            Object.keys(scan.tool_statuses).forEach((t) => {
                              if (!toolGroups[t]) {
                                toolGroups[t] = [];
                              }
                            });
                          }

                          return Object.entries(toolGroups).map(
                            ([toolName, toolFiles]) => {
                              const toolFolderKey = `${scan.target_id}:${toolName}`;
                              const isToolOpen =
                                openFolders[toolFolderKey] !== undefined
                                  ? openFolders[toolFolderKey]
                                  : true;
                              const st = scan.tool_statuses?.[toolName];
                              const mode = st?.mode || "real";
                              const isFailed = mode === "failed";
                              const isSim = mode === "simulated";

                              return (
                                <div
                                  key={toolFolderKey}
                                  className="space-y-0.5"
                                >
                                  {/* Subfolder Header: Tool */}
                                  <div
                                    onClick={() => toggleFolder(toolFolderKey)}
                                    className="flex items-center justify-between px-1.5 py-1 rounded hover:bg-[#151c2e] cursor-pointer text-[11px] transition select-none"
                                  >
                                    <div className="flex items-center space-x-1.5 truncate flex-1">
                                      {isToolOpen ? (
                                        <ChevronDown className="w-2.5 h-2.5 text-zinc-500 flex-shrink-0" />
                                      ) : (
                                        <ChevronRight className="w-2.5 h-2.5 text-zinc-500 flex-shrink-0" />
                                      )}
                                      {isToolOpen ? (
                                        <FolderOpen className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                                      ) : (
                                        <Folder className="w-3 h-3 text-cyan-500 flex-shrink-0" />
                                      )}
                                      <span className="font-semibold uppercase text-[10px] tracking-wider text-cyan-300">
                                        {toolName}
                                      </span>
                                      <span className="text-[9px] text-zinc-500 font-mono">
                                        ({toolFiles.length})
                                      </span>
                                    </div>

                                    {st && (
                                      <span
                                        title={`${toolName}: ${mode} ${st.reason ? `(${st.reason})` : ""}`}
                                        className={`px-1.5 py-0.2 rounded text-[8px] font-mono uppercase font-semibold ml-1 ${
                                          isFailed
                                            ? "bg-red-950/80 text-red-400 border border-red-800"
                                            : isSim
                                              ? "bg-amber-950/80 text-amber-400 border border-amber-800"
                                              : "bg-emerald-950/80 text-emerald-400 border border-emerald-800"
                                        }`}
                                      >
                                        {isFailed
                                          ? "FAIL"
                                          : isSim
                                            ? "SIM"
                                            : "REAL"}
                                      </span>
                                    )}
                                  </div>

                                  {/* Files inside this Tool */}
                                  {isToolOpen && (
                                    <div className="ml-3.5 space-y-0.5 border-l border-[#1e293b]/70 pl-2">
                                      {toolFiles.map((file) => (
                                        <button
                                          key={file.rel_path}
                                          onClick={() =>
                                            openFile({
                                              name: file.name,
                                              rel_path: file.rel_path,
                                            })
                                          }
                                          className="w-full text-left flex items-center space-x-1.5 px-2 py-1 rounded hover:bg-[#151c2e] text-zinc-400 hover:text-cyan-300 transition text-[11px]"
                                        >
                                          {file.type === "structured" ? (
                                            <FileCode className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                                          ) : file.type === "status" ? (
                                            <Activity className="w-3 h-3 text-emerald-400 flex-shrink-0" />
                                          ) : file.type === "simulated" ? (
                                            <FileText className="w-3 h-3 text-amber-400 flex-shrink-0" />
                                          ) : (
                                            <FileText className="w-3 h-3 text-zinc-500 flex-shrink-0" />
                                          )}
                                          <span className="truncate flex-1 font-mono text-[10.5px]">
                                            {file.name}
                                          </span>
                                          {file.type === "simulated" && (
                                            <span className="text-[8px] font-mono text-amber-400 bg-amber-950/80 px-1 py-0.2 rounded border border-amber-800/60">
                                              SIM
                                            </span>
                                          )}
                                          {file.type === "status" && (
                                            <span className="text-[8px] font-mono text-emerald-400 bg-emerald-950/80 px-1 py-0.2 rounded border border-emerald-800/60">
                                              STATUS
                                            </span>
                                          )}
                                        </button>
                                      ))}
                                      {toolFiles.length === 0 && (
                                        <span className="text-[10px] text-zinc-600 italic px-2 py-0.5 block">
                                          Không có file kết quả
                                        </span>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            },
                          );
                        })()}
                      </div>
                    )}
                  </div>
                );
              })}
              {scans.length === 0 && (
                <span className="text-zinc-600 text-[11px] block pl-2 py-1">
                  Chưa có dữ liệu quét nào.
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};
