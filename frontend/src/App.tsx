import React, { useEffect, useRef, useState } from "react";
import {
  Group,
  Panel,
  PanelImperativeHandle,
  useDefaultLayout,
} from "react-resizable-panels";
import {
  FolderTree,
  Sparkles,
  PanelLeftOpen,
  PanelRightOpen,
} from "lucide-react";
import { Header } from "./components/Layout/Header";
import { ExplorerPanel } from "./components/Explorer/ExplorerPanel";
import { MainPanel } from "./components/Editor/MainPanel";
import { FindingsManager } from "./components/Findings/FindingsManager";
import { ReportViewer } from "./components/Reports/ReportViewer";
import { TopologyViewer } from "./components/Topology/TopologyViewer";
import { ChatPanel } from "./components/Chat/ChatPanel";
import { TerminalPanel } from "./components/Terminal/TerminalPanel";
import { TargetInputModal } from "./components/Target/TargetInputModal";
import { useWorkspaceStore } from "./store/workspaceStore";
import { ResizeHandle } from "./components/common/ResizeHandle";

export const App: React.FC = () => {
  const {
    fetchInitialData,
    activeView,
    isExplorerOpen,
    isChatOpen,
    setExplorerOpen,
    setChatOpen,
    toggleExplorer,
    toggleChat,
  } = useWorkspaceStore();

  const explorerPanelRef = useRef<PanelImperativeHandle | null>(null);
  const chatPanelRef = useRef<PanelImperativeHandle | null>(null);
  const terminalPanelRef = useRef<PanelImperativeHandle | null>(null);
  const [isTerminalExpanded, setIsTerminalExpanded] = useState(false);

  // Persistent user-selected widths (in percentage)
  const savedExplorerSize = useRef<number>((() => {
    try {
      const saved = localStorage.getItem("explorer_panel_size_pct");
      if (saved) {
        const val = parseFloat(saved);
        if (!isNaN(val) && val >= 10 && val <= 45) return val;
      }
    } catch {}
    return 18;
  })());

  const savedChatSize = useRef<number>((() => {
    try {
      const saved = localStorage.getItem("chat_panel_size_pct");
      if (saved) {
        const val = parseFloat(saved);
        if (!isNaN(val) && val >= 15 && val <= 50) return val;
      }
    } catch {}
    return 25;
  })());

  const horizontalLayout = useDefaultLayout({ id: "copilot-layout-horizontal" });
  const verticalLayout = useDefaultLayout({ id: "copilot-layout-vertical" });

  useEffect(() => {
    fetchInitialData();
  }, []);

  // Keyboard Shortcuts: Ctrl+B (Explorer), Ctrl+Shift+L (Chat)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleExplorer();
      }
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "l") {
        e.preventDefault();
        toggleChat();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [toggleExplorer, toggleChat]);

  // Synchronize Explorer Open/Close while keeping the exact width
  useEffect(() => {
    const panel = explorerPanelRef.current;
    if (!panel) return;
    if (isExplorerOpen) {
      if (panel.isCollapsed()) {
        panel.expand();
        if (savedExplorerSize.current) {
          panel.resize(`${savedExplorerSize.current}%`);
        }
      }
    } else {
      if (!panel.isCollapsed()) {
        const curr = panel.getSize()?.asPercentage;
        if (curr && curr > 2) {
          savedExplorerSize.current = curr;
          try {
            localStorage.setItem("explorer_panel_size_pct", curr.toFixed(2));
          } catch {}
        }
        panel.collapse();
      }
    }
  }, [isExplorerOpen]);

  // Synchronize Chat Open/Close while keeping the exact width
  useEffect(() => {
    const panel = chatPanelRef.current;
    if (!panel) return;
    if (isChatOpen) {
      if (panel.isCollapsed()) {
        panel.expand();
        if (savedChatSize.current) {
          panel.resize(`${savedChatSize.current}%`);
        }
      }
    } else {
      if (!panel.isCollapsed()) {
        const curr = panel.getSize()?.asPercentage;
        if (curr && curr > 2) {
          savedChatSize.current = curr;
          try {
            localStorage.setItem("chat_panel_size_pct", curr.toFixed(2));
          } catch {}
        }
        panel.collapse();
      }
    }
  }, [isChatOpen]);

  // Record resize events to preserve width
  const handleExplorerResize = (size: { asPercentage: number; inPixels: number }) => {
    if (size.asPercentage > 2) {
      savedExplorerSize.current = size.asPercentage;
      try {
        localStorage.setItem("explorer_panel_size_pct", size.asPercentage.toFixed(2));
      } catch {}
      if (!isExplorerOpen) {
        setExplorerOpen(true);
      }
    } else {
      if (isExplorerOpen) {
        setExplorerOpen(false);
      }
    }
  };

  const handleChatResize = (size: { asPercentage: number; inPixels: number }) => {
    if (size.asPercentage > 2) {
      savedChatSize.current = size.asPercentage;
      try {
        localStorage.setItem("chat_panel_size_pct", size.asPercentage.toFixed(2));
      } catch {}
      if (!isChatOpen) {
        setChatOpen(true);
      }
    } else {
      if (isChatOpen) {
        setChatOpen(false);
      }
    }
  };

  const handleToggleTerminal = () => {
    const panel = terminalPanelRef.current;
    if (panel) {
      if (isTerminalExpanded) {
        panel.resize("35%");
        setIsTerminalExpanded(false);
      } else {
        panel.resize("75%");
        setIsTerminalExpanded(true);
      }
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen bg-[#0a0d14] overflow-hidden text-zinc-100 font-sans">
      <Header />
      <div className="flex-1 flex overflow-hidden">
        {/* Collapsed Left Rail (When Explorer is Closed) */}
        {!isExplorerOpen && (
          <div
            onClick={() => setExplorerOpen(true)}
            className="w-9 bg-[#0e1320] border-r border-[#1e293b] flex flex-col items-center py-3 gap-4 cursor-pointer hover:bg-[#121829] transition-all select-none shrink-0 group z-10"
            title="Mở rộng Workspace Explorer (Ctrl+B)"
          >
            <button
              onClick={(e) => {
                e.stopPropagation();
                setExplorerOpen(true);
              }}
              className="p-1 rounded-md text-zinc-400 group-hover:text-cyan-300 hover:bg-[#1c253d] transition-colors"
              title="Mở rộng Workspace Explorer"
            >
              <PanelLeftOpen className="w-4 h-4" />
            </button>
            <FolderTree className="w-4 h-4 text-cyan-500/80 group-hover:text-cyan-400 transition-colors" />
            <div className="flex-1 flex items-center justify-center">
              <span className="[writing-mode:vertical-lr] rotate-180 text-[10px] font-mono tracking-widest font-bold text-zinc-500 group-hover:text-zinc-300 transition-colors uppercase">
                Explorer
              </span>
            </div>
          </div>
        )}

        <Group
          {...horizontalLayout}
          orientation="horizontal"
          id="copilot-layout-horizontal"
          className="h-full w-full flex-1"
        >
          {/* Left Panel: Explorer */}
          <Panel
            id="explorer-panel"
            panelRef={explorerPanelRef}
            collapsible={true}
            collapsedSize={0}
            defaultSize={`${savedExplorerSize.current}%`}
            minSize="10%"
            maxSize="45%"
            onResize={handleExplorerResize}
            className={`h-full overflow-hidden ${!isExplorerOpen ? "!hidden !w-0 !min-w-0 pointer-events-none" : ""}`}
          >
            <ExplorerPanel onClose={() => setExplorerOpen(false)} />
          </Panel>

          {/* Resizer between Explorer and Main Content */}
          <ResizeHandle
            orientation="horizontal"
            id="handle-explorer"
            className={!isExplorerOpen ? "!hidden pointer-events-none" : ""}
          />

          {/* Center Panel: Editor / Findings / Reports / Topology */}
          <Panel
            id="center-content-panel"
            minSize="30%"
            className="h-full overflow-hidden"
          >
            <div className="h-full w-full flex flex-col overflow-hidden">
              {activeView === "findings" ? (
                <FindingsManager />
              ) : activeView === "reports" ? (
                <ReportViewer />
              ) : activeView === "topology" ? (
                <TopologyViewer />
              ) : (
                <Group
                  {...verticalLayout}
                  orientation="vertical"
                  id="copilot-layout-vertical"
                  className="h-full w-full"
                >
                  <Panel
                    id="editor-panel"
                    defaultSize="65%"
                    minSize="20%"
                    className="h-full overflow-hidden"
                  >
                    <MainPanel />
                  </Panel>

                  {/* Resizer between Editor and Terminal */}
                  <ResizeHandle orientation="vertical" id="handle-terminal" />

                  <Panel
                    id="terminal-panel"
                    panelRef={terminalPanelRef}
                    defaultSize="35%"
                    minSize="12%"
                    maxSize="85%"
                    className="h-full overflow-hidden"
                  >
                    <TerminalPanel
                      isExpanded={isTerminalExpanded}
                      onToggleExpand={handleToggleTerminal}
                    />
                  </Panel>
                </Group>
              )}
            </div>
          </Panel>

          {/* Resizer between Main Content and Chat Copilot */}
          <ResizeHandle
            orientation="horizontal"
            id="handle-chat"
            className={!isChatOpen ? "!hidden pointer-events-none" : ""}
          />

          {/* Right Panel: Chat Copilot */}
          <Panel
            id="chat-panel"
            panelRef={chatPanelRef}
            collapsible={true}
            collapsedSize={0}
            defaultSize={`${savedChatSize.current}%`}
            minSize="15%"
            maxSize="50%"
            onResize={handleChatResize}
            className={`h-full overflow-hidden ${!isChatOpen ? "!hidden !w-0 !min-w-0 pointer-events-none" : ""}`}
          >
            <ChatPanel onClose={() => setChatOpen(false)} />
          </Panel>
        </Group>

        {/* Collapsed Right Rail (When Chat is Closed) */}
        {!isChatOpen && (
          <div
            onClick={() => setChatOpen(true)}
            className="w-9 bg-[#0e1320] border-l border-[#1e293b] flex flex-col items-center py-3 gap-4 cursor-pointer hover:bg-[#121829] transition-all select-none shrink-0 group z-10"
            title="Mở rộng AI-Pentest Copilot (Ctrl+Shift+L)"
          >
            <button
              onClick={(e) => {
                e.stopPropagation();
                setChatOpen(true);
              }}
              className="p-1 rounded-md text-zinc-400 group-hover:text-cyan-300 hover:bg-[#1c253d] transition-colors"
              title="Mở rộng AI-Pentest Copilot"
            >
              <PanelRightOpen className="w-4 h-4" />
            </button>
            <Sparkles className="w-4 h-4 text-cyan-400 animate-pulse" />
            <div className="flex-1 flex items-center justify-center">
              <span className="[writing-mode:vertical-lr] rotate-180 text-[10px] font-mono tracking-widest font-bold text-zinc-500 group-hover:text-cyan-300 transition-colors uppercase">
                AI Copilot
              </span>
            </div>
          </div>
        )}
      </div>
      <TargetInputModal />
    </div>
  );
};

export default App;
