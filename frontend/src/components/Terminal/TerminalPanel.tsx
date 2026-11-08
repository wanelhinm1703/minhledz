import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  Terminal as TerminalIcon,
  Play,
  Square,
  Trash2,
  Maximize2,
  Minimize2,
  Sparkles,
  Loader2,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

interface TerminalPanelProps {
  isExpanded?: boolean;
  onToggleExpand?: () => void;
}

export const TerminalPanel: React.FC<TerminalPanelProps> = ({
  isExpanded: isExpandedProp,
  onToggleExpand,
}) => {
  const {
    terminalLogs,
    clearTerminalLogs,
    appendTerminalLog,
    refreshScans,
    activeTarget,
  } = useWorkspaceStore();
  const [inputCmd, setInputCmd] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [internalExpanded, setInternalExpanded] = useState(false);
  const isExpanded = isExpandedProp !== undefined ? isExpandedProp : internalExpanded;
  const [currentCwd, setCurrentCwd] = useState("~");
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number>(-1);

  const logsEndRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [terminalLogs]);

  // Setup WebSocket connection for real-time live streaming
  const connectWs = useCallback(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "localhost:8000";
    const wsUrl = `${protocol}//${host}/ws/terminal`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        const { type, data, code, duration, cwd, message } = payload;

        if (type === "ready") {
          if (cwd) {
            const rel = cwd.split("ai-pentest-copilot").pop() || "";
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, "/")}` : "~");
          }
        } else if (type === "stdout") {
          appendTerminalLog(data);
        } else if (type === "stderr") {
          appendTerminalLog(`[!] ${data}`);
        } else if (type === "clear") {
          clearTerminalLogs();
        } else if (type === "exit") {
          setIsRunning(false);
          appendTerminalLog(
            `[*] Exit code: ${code} (completed in ${duration}s)`,
          );
          if (cwd) {
            const rel = cwd.split("ai-pentest-copilot").pop() || "";
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, "/")}` : "~");
          }
          refreshScans();
          inputRef.current?.focus();
        }
      } catch (err) {
        console.error("Terminal WS error", err);
      }
    };

    ws.onclose = () => {
      wsRef.current = null;
    };
  }, [appendTerminalLog, clearTerminalLogs, refreshScans]);

  useEffect(() => {
    connectWs();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [connectWs]);

  // Determine current active target host for presets
  const rawHost =
    activeTarget?.host ||
    activeTarget?.normalized_value ||
    activeTarget?.name ||
    "192.168.100.153";
  const cleanHost = rawHost
    .replace("http://", "")
    .replace("https://", "")
    .replace("target-", "")
    .replace("/", "")
    .split(":")[0];

  const presets = [
    {
      id: "pipeline",
      label: "🚀 Full Pipeline",
      cmd: `python toolkit/scripts/pipeline_runner.py --target ${cleanHost}`,
    },
    {
      id: "nmap",
      label: "🔍 Nmap Scan",
      cmd: `python toolkit/scripts/run_nmap.py --target ${cleanHost} --output-dir toolkit/03-network/scans/target-${cleanHost}/nmap`,
    },
    {
      id: "naabu",
      label: "⚡ Naabu Fast Port",
      cmd: `python toolkit/scripts/run_naabu.py --target ${cleanHost} --output-dir toolkit/03-network/scans/target-${cleanHost}/naabu`,
    },
    {
      id: "httpx",
      label: "🌐 HTTPx Web Probe",
      cmd: `python toolkit/scripts/run_httpx.py --target http://${cleanHost} --output-dir toolkit/04-web/scans/target-${cleanHost}/httpx`,
    },
    {
      id: "ping",
      label: "📡 Ping Probe",
      cmd: `ping -c 4 ${cleanHost}`,
    },
  ];

  const handleRunCommand = (cmdToRun?: string) => {
    const command = (cmdToRun !== undefined ? cmdToRun : inputCmd).trim();
    if (!command || isRunning) return;

    // Handle clear screen locally
    if (command.toLowerCase() === "clear" || command.toLowerCase() === "cls") {
      clearTerminalLogs();
      setInputCmd("");
      return;
    }

    setHistory((prev) => [command, ...prev]);
    setHistoryIdx(-1);
    setInputCmd("");
    setIsRunning(true);

    appendTerminalLog(`$ ${command}`);

    // Send via WebSocket for live streaming if connected
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "execute", command }));
    } else {
      // Reconnect WS or execute via REST
      fetch("/api/terminal/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command }),
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.status === "clear") {
            clearTerminalLogs();
            return;
          }
          if (data.stdout) {
            data.stdout.split("\n").forEach((l: string) => {
              if (l.trim()) appendTerminalLog(l);
            });
          }
          if (data.stderr) {
            data.stderr.split("\n").forEach((l: string) => {
              if (l.trim()) appendTerminalLog(`[!] ${l}`);
            });
          }
          appendTerminalLog(
            `[*] Exit code: ${data.exit_code} (${data.duration_seconds}s)`,
          );
          if (data.cwd) {
            const rel = data.cwd.split("ai-pentest-copilot").pop() || "";
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, "/")}` : "~");
          }
          refreshScans();
        })
        .catch((err) => {
          appendTerminalLog(`[!] Connection error: ${err.message}`);
        })
        .finally(() => {
          setIsRunning(false);
          inputRef.current?.focus();
        });
    }
  };

  const handleKillProcess = () => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: "kill" }));
    }
    setIsRunning(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleRunCommand();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length > 0 && historyIdx < history.length - 1) {
        const nextIdx = historyIdx + 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx > 0) {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      } else if (historyIdx === 0) {
        setHistoryIdx(-1);
        setInputCmd("");
      }
    }
  };

  return (
    <div className="h-full w-full bg-[#070a10] flex flex-col font-mono text-xs select-none">
      {/* Header Bar */}
      <div className="h-8 bg-[#0c101c] border-b border-[#1e293b] px-3 flex items-center justify-between text-zinc-400">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <TerminalIcon className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-semibold text-[11px] uppercase tracking-wider text-zinc-200">
              Terminal & Execution Engine
            </span>
          </div>
          {activeTarget && (
            <span className="text-[10px] text-zinc-400 bg-[#121829] px-2 py-0.5 rounded-md border border-[#1e293b] font-mono">
              target: <span className="text-emerald-400 font-semibold">{cleanHost}</span>
            </span>
          )}
        </div>

        {/* Quick presets & action controls */}
        <div className="flex items-center space-x-2">
          {/* Quick presets dropdown / pills */}
          <div className="hidden md:flex items-center space-x-1">
            <span className="text-[10px] text-zinc-500 mr-1 flex items-center space-x-0.5">
              <Sparkles className="w-2.5 h-2.5 text-cyan-400" />
              <span>Gợi ý:</span>
            </span>
            {presets.slice(0, 3).map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setInputCmd(p.cmd);
                  inputRef.current?.focus();
                }}
                title={p.cmd}
                className="text-[10px] px-2 py-0.5 rounded-md bg-[#121829] hover:bg-[#1c253d] text-zinc-300 hover:text-cyan-300 border border-[#1e293b] transition-colors"
              >
                {p.label}
              </button>
            ))}
          </div>

          <button
            onClick={clearTerminalLogs}
            title="Xóa màn hình terminal"
            className="p-1 hover:text-zinc-200 hover:bg-[#151c2e] rounded transition text-zinc-400"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => {
              if (onToggleExpand) {
                onToggleExpand();
              } else {
                setInternalExpanded(!internalExpanded);
              }
            }}
            title={isExpanded ? "Thu nhỏ terminal" : "Phóng to terminal"}
            className="p-1 hover:text-zinc-200 hover:bg-[#151c2e] rounded transition text-zinc-400"
          >
            {isExpanded ? (
              <Minimize2 className="w-3.5 h-3.5" />
            ) : (
              <Maximize2 className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Output Console Stream */}
      <div className="flex-1 p-3 overflow-y-auto space-y-0.5 text-zinc-200 font-mono text-[11.5px] leading-relaxed selection:bg-cyan-500/30 bg-[#070a10]">
        {terminalLogs.map((log, i) => (
          <div key={i} className="break-all whitespace-pre-wrap">
            {log.startsWith("$ ") ? (
              <span className="text-cyan-300 font-bold">{log}</span>
            ) : log.startsWith("[+]") ? (
              <span className="text-emerald-400 font-medium">{log}</span>
            ) : log.startsWith("[!]") ? (
              <span className="text-rose-400 font-medium">{log}</span>
            ) : log.startsWith("[*]") ? (
              <span className="text-cyan-400 font-medium">{log}</span>
            ) : (
              <span className="text-zinc-300">{log}</span>
            )}
          </div>
        ))}
        {isRunning && (
          <div className="flex items-center space-x-2 text-cyan-400 text-[11px] py-1">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Đang thực thi lệnh thực tế trên host...</span>
          </div>
        )}
        <div ref={logsEndRef} />
      </div>

      {/* Interactive Command Input Prompt */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleRunCommand();
        }}
        className="h-8.5 bg-[#0c101c] border-t border-[#1e293b] px-3 flex items-center space-x-2"
      >
        <span className="font-bold text-[11px] select-none flex items-center space-x-1 flex-shrink-0 font-mono">
          <span className="text-emerald-400">kali@copilot</span>
          <span className="text-zinc-500">:</span>
          <span className="text-cyan-400">{currentCwd}</span>
          <span className="text-zinc-400">$</span>
        </span>
        <input
          ref={inputRef}
          type="text"
          value={inputCmd}
          disabled={isRunning}
          onChange={(e) => setInputCmd(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={isRunning ? "Đang thực thi lệnh..." : ""}
          className="flex-1 bg-transparent border-none text-zinc-100 placeholder-zinc-600 focus:outline-none text-[11.5px] font-mono disabled:opacity-50"
        />
        {isRunning ? (
          <button
            type="button"
            onClick={handleKillProcess}
            title="Dừng tiến trình đang chạy (Ctrl+C)"
            className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white rounded-md text-[10px] flex items-center space-x-1 transition shadow-sm font-semibold"
          >
            <Square className="w-2.5 h-2.5 fill-white" />
            <span>Dừng</span>
          </button>
        ) : (
          <button
            type="submit"
            disabled={!inputCmd.trim()}
            title="Thực thi lệnh (Enter)"
            className="px-2.5 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded-md text-[10px] flex items-center space-x-1 transition shadow-sm font-semibold"
          >
            <Play className="w-2.5 h-2.5" />
            <span>Chạy</span>
          </button>
        )}
      </form>
    </div>
  );
};
