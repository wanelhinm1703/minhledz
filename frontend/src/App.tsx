import React, { useEffect } from 'react'
import { Header } from './components/Layout/Header'
import { ExplorerPanel } from './components/Explorer/ExplorerPanel'
import { MainPanel } from './components/Editor/MainPanel'
import { ChatPanel } from './components/Chat/ChatPanel'
import { TerminalPanel } from './components/Terminal/TerminalPanel'
import { TargetInputModal } from './components/Target/TargetInputModal'
import { useWorkspaceStore } from './store/workspaceStore'

export const App: React.FC = () => {
  const { fetchInitialData } = useWorkspaceStore();

  useEffect(() => {
    fetchInitialData();
  }, []);

  return (
    <div className="flex flex-col h-screen w-screen bg-[#18181b] overflow-hidden text-zinc-200 font-mono">
      <Header />
      <div className="flex-1 flex overflow-hidden">
        <ExplorerPanel />
        <div className="flex-1 flex flex-col overflow-hidden">
          <MainPanel />
          <TerminalPanel />
        </div>
        <ChatPanel />
      </div>
      <TargetInputModal />
    </div>
  );
};

export default App;
