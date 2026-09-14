import { create } from 'zustand'

export interface TargetItem {
  target_id: string;
  name: string;
  type: string;
  normalized_value: string;
  host: string;
  status: string;
}

export interface ScanRecord {
  target_id: string;
  tools: string[];
  evidence_files: Array<{
    name: string;
    tool: string;
    type: string;
    rel_path: string;
  }>;
}

export interface OpenTab {
  id: string;
  title: string;
  path: string;
  content: string;
  isJson: boolean;
}

interface WorkspaceState {
  targets: TargetItem[];
  scans: ScanRecord[];
  activeTarget: TargetItem | null;
  openTabs: OpenTab[];
  activeTabId: string | null;
  terminalLogs: string[];
  isTargetModalOpen: boolean;
  selectedProvider: string;
  activeView: 'editor' | 'findings' | 'reports';
  
  setTargets: (targets: TargetItem[]) => void;
  setScans: (scans: ScanRecord[]) => void;
  setActiveTarget: (target: TargetItem | null) => void;
  setActiveView: (view: 'editor' | 'findings' | 'reports') => void;
  openFile: (file: { name: string; rel_path: string }) => Promise<void>;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  appendTerminalLog: (log: string) => void;
  setTargetModalOpen: (open: boolean) => void;
  setSelectedProvider: (provider: string) => void;
  fetchInitialData: () => Promise<void>;
}

export const useWorkspaceStore = create<WorkspaceState>((set, get) => ({
  targets: [],
  scans: [],
  activeTarget: null,
  openTabs: [],
  activeTabId: null,
  terminalLogs: [
    "[*] AI-Pentest Copilot Workspace Initialized.",
    "[*] Connected to Backend API: http://127.0.0.1:8000",
    "[*] Knowledge Base ready: 539 CVEs | 52 CWEs loaded.",
  ],
  isTargetModalOpen: false,
  selectedProvider: "GPT-4o-mini",
  activeView: "editor",

  setTargets: (targets) => set({ targets }),
  setScans: (scans) => set({ scans }),
  setActiveTarget: (target) => set({ activeTarget: target }),
  setActiveView: (activeView) => set({ activeView }),
  setTargetModalOpen: (open) => set({ isTargetModalOpen: open }),
  setSelectedProvider: (provider) => set({ selectedProvider: provider }),

  appendTerminalLog: (log) =>
    set((state) => ({ terminalLogs: [...state.terminalLogs, log] })),

  setActiveTab: (id) => set({ activeTabId: id }),

  closeTab: (id) =>
    set((state) => {
      const nextTabs = state.openTabs.filter((t) => t.id !== id);
      const nextActiveId =
        state.activeTabId === id
          ? nextTabs.length > 0
            ? nextTabs[nextTabs.length - 1].id
            : null
          : state.activeTabId;
      return { openTabs: nextTabs, activeTabId: nextActiveId };
    }),

  openFile: async ({ name, rel_path }) => {
    const { openTabs } = get();
    const existing = openTabs.find((t) => t.path === rel_path);
    if (existing) {
      set({ activeTabId: existing.id });
      return;
    }

    try {
      const res = await fetch(`/api/scans/file?path=${encodeURIComponent(rel_path)}`);
      if (!res.ok) throw new Error("Failed to load file");
      const data = await res.json();
      
      let formattedContent = data.content;
      if (data.is_json) {
        try {
          formattedContent = JSON.stringify(JSON.parse(data.content), null, 2);
        } catch {
          // keep original
        }
      }

      const newTab: OpenTab = {
        id: rel_path,
        title: name,
        path: rel_path,
        content: formattedContent,
        isJson: data.is_json,
      };

      set({
        openTabs: [...openTabs, newTab],
        activeTabId: newTab.id,
      });
    } catch (err: any) {
      get().appendTerminalLog(`[!] Error loading file ${rel_path}: ${err.message}`);
    }
  },

  fetchInitialData: async () => {
    try {
      const [targetsRes, scansRes] = await Promise.all([
        fetch('/api/targets'),
        fetch('/api/scans'),
      ]);
      if (targetsRes.ok) {
        const targets = await targetsRes.json();
        set({ targets, activeTarget: targets[0] || null });
      }
      if (scansRes.ok) {
        const scans = await scansRes.json();
        set({ scans });
      }
    } catch (err) {
      console.error("Failed to load workspace data:", err);
    }
  },
}));
