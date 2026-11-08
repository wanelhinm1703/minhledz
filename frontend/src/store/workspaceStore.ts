import { create } from 'zustand'

export interface TargetItem {
  target_id: string;
  name: string;
  type: string;
  normalized_value: string;
  host: string;
  status: string;
  environment?: string;
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
  deleteTarget: (target_id: string) => Promise<void>;
  deleteScan: (target_id: string) => Promise<void>;
  refreshScans: () => Promise<void>;
  clearTerminalLogs: () => void;
  executeCommand: (command: string) => Promise<void>;
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
  selectedProvider: "gemini",
  activeView: "editor",

  setTargets: (targets) => set({ targets }),
  setScans: (scans) => set({ scans }),
  setActiveTarget: (target) => set({ activeTarget: target }),
  setActiveView: (activeView) => set({ activeView }),
  setTargetModalOpen: (open) => set({ isTargetModalOpen: open }),
  setSelectedProvider: (provider) => {
    set({ selectedProvider: provider });
    fetch('/api/llm/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider }),
    }).catch((e) => console.error('Failed to sync provider with backend', e));
  },

  deleteTarget: async (target_id: string) => {
    try {
      const res = await fetch(`/api/targets/${encodeURIComponent(target_id)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        const nextTargets = get().targets.filter((t) => t.target_id !== target_id);
        const nextActive = get().activeTarget?.target_id === target_id
          ? (nextTargets.length > 0 ? nextTargets[0] : null)
          : get().activeTarget;
        set({ targets: nextTargets, activeTarget: nextActive });
        get().appendTerminalLog(`[*] Deleted target: ${target_id}`);
      }
    } catch (err: any) {
      get().appendTerminalLog(`[!] Failed to delete target ${target_id}: ${err.message}`);
    }
  },

  refreshScans: async () => {
    try {
      const res = await fetch('/api/scans');
      if (res.ok) {
        const scans = await res.json();
        set({ scans });
      }
    } catch (e) {
      console.error('Failed to refresh scans', e);
    }
  },

  deleteScan: async (target_id: string) => {
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(target_id)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        get().appendTerminalLog(`[*] Đã xóa toàn bộ dữ liệu scan của: ${target_id}`);
        await get().refreshScans();
      }
    } catch (err: any) {
      get().appendTerminalLog(`[!] Lỗi khi xóa scan ${target_id}: ${err.message}`);
    }
  },

  clearTerminalLogs: () => set({ terminalLogs: [] }),

  executeCommand: async (command: string) => {
    const cmd = command.trim();
    if (!cmd) return;

    get().appendTerminalLog(`$ ${cmd}`);
    try {
      const res = await fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: cmd,
          target_id: get().activeTarget?.target_id || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        get().appendTerminalLog(`[!] Error: ${data.detail || 'Lệnh thực thi thất bại'}`);
        return;
      }

      if (data.stdout) {
        const lines = data.stdout.split('\n');
        for (const line of lines) {
          if (line.trim()) get().appendTerminalLog(line);
        }
      }
      if (data.stderr) {
        const errLines = data.stderr.split('\n');
        for (const line of errLines) {
          if (line.trim()) get().appendTerminalLog(`[!] ${line}`);
        }
      }

      get().appendTerminalLog(`[*] Hoàn thành (exit code ${data.exit_code}) trong ${data.duration_seconds}s`);

      // Auto refresh scans if scanner command was run
      if (
        cmd.includes('pipeline_runner') ||
        cmd.includes('run_nmap') ||
        cmd.includes('run_naabu') ||
        cmd.includes('run_httpx') ||
        cmd.includes('run_nuclei') ||
        cmd.includes('nmap')
      ) {
        await get().refreshScans();
      }
    } catch (err: any) {
      get().appendTerminalLog(`[!] Lỗi kết nối khi chạy lệnh: ${err.message}`);
    }
  },

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
