import React, { useState, useRef, useEffect, useCallback } from 'react'
import { Terminal as TerminalIcon, Play, Square, Trash2, Maximize2, Minimize2, Sparkles, Loader2 } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const TerminalPanel: React.FC = () => {
  const { terminalLogs, clearTerminalLogs, appendTerminalLog, refreshScans, activeTarget } = useWorkspaceStore();
  const [inputCmd, setInputCmd] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [currentCwd, setCurrentCwd] = useState('~');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState<number>(-1);

  const logsEndRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [terminalLogs]);

  // Setup WebSocket connection for real-time live streaming
  const connectWs = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:8000';
    const wsUrl = `${protocol}//${host}/ws/terminal`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        const { type, data, code, duration, cwd, message } = payload;

        if (type === 'ready') {
          if (message) appendTerminalLog(`[*] ${message}`);
          if (cwd) {
            const rel = cwd.split('ai-pentest-copilot').pop() || '';
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, '/')}` : '~');
          }
        } else if (type === 'stdout') {
          appendTerminalLog(data);
        } else if (type === 'stderr') {
          appendTerminalLog(`[!] ${data}`);
        } else if (type === 'clear') {
          clearTerminalLogs();
        } else if (type === 'exit') {
          setIsRunning(false);
          appendTerminalLog(`[*] Exit code: ${code} (completed in ${duration}s)`);
          if (cwd) {
            const rel = cwd.split('ai-pentest-copilot').pop() || '';
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, '/')}` : '~');
          }
          refreshScans();
          inputRef.current?.focus();
        }
      } catch (err) {
        console.error('Terminal WS error', err);
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
  const rawHost = activeTarget?.host || activeTarget?.normalized_value || activeTarget?.name || '192.168.100.153';
  const cleanHost = rawHost.replace('http://', '').replace('https://', '').replace('/', '').split(':')[0];

  const presets = [
    {
      id: 'pipeline',
      label: '🚀 Full Pipeline',
      cmd: `python toolkit/scripts/pipeline_runner.py --target ${cleanHost}`,
    },
    {
      id: 'nmap',
      label: '🔍 Nmap Scan',
      cmd: `python toolkit/scripts/run_nmap.py --target ${cleanHost} --output-dir toolkit/03-network/scans/target-${cleanHost}/nmap`,
    },
    {
      id: 'naabu',
      label: '⚡ Naabu Fast Port',
      cmd: `python toolkit/scripts/run_naabu.py --target ${cleanHost} --output-dir toolkit/03-network/scans/target-${cleanHost}/naabu`,
    },
    {
      id: 'httpx',
      label: '🌐 HTTPx Web Probe',
      cmd: `python toolkit/scripts/run_httpx.py --target http://${cleanHost} --output-dir toolkit/04-web/scans/target-${cleanHost}/httpx`,
    },
    {
      id: 'ping',
      label: '📡 Ping Probe',
      cmd: `ping -n 4 ${cleanHost}`,
    },
  ];

  const handleRunCommand = (cmdToRun?: string) => {
    const command = (cmdToRun !== undefined ? cmdToRun : inputCmd).trim();
    if (!command || isRunning) return;

    // Handle clear screen locally
    if (command.toLowerCase() === 'clear' || command.toLowerCase() === 'cls') {
      clearTerminalLogs();
      setInputCmd('');
      return;
    }

    setHistory((prev) => [command, ...prev]);
    setHistoryIdx(-1);
    setInputCmd('');
    setIsRunning(true);

    appendTerminalLog(`$ ${command}`);

    // Send via WebSocket for live streaming if connected
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'execute', command }));
    } else {
      // Reconnect WS or execute via REST
      fetch('/api/terminal/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.status === 'clear') {
            clearTerminalLogs();
            return;
          }
          if (data.stdout) {
            data.stdout.split('\n').forEach((l: string) => {
              if (l.trim()) appendTerminalLog(l);
            });
          }
          if (data.stderr) {
            data.stderr.split('\n').forEach((l: string) => {
              if (l.trim()) appendTerminalLog(`[!] ${l}`);
            });
          }
          appendTerminalLog(`[*] Exit code: ${data.exit_code} (${data.duration_seconds}s)`);
          if (data.cwd) {
            const rel = data.cwd.split('ai-pentest-copilot').pop() || '';
            setCurrentCwd(rel ? `~${rel.replace(/\\/g, '/')}` : '~');
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
      wsRef.current.send(JSON.stringify({ type: 'kill' }));
    }
    setIsRunning(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleRunCommand();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length > 0 && historyIdx < history.length - 1) {
        const nextIdx = historyIdx + 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIdx > 0) {
        const nextIdx = historyIdx - 1;
        setHistoryIdx(nextIdx);
        setInputCmd(history[nextIdx]);
      } else if (historyIdx === 0) {
        setHistoryIdx(-1);
        setInputCmd('');
      }
    }
  };

  return (
    <div
      className={`${isExpanded ? 'h-80' : 'h-48'
        } bg-[#101012] border-t border-[#27272a] flex flex-col font-mono text-xs select-none transition-all duration-200`}
    >
      {/* Header Bar */}
      <div className="h-7 bg-[#141416] border-b border-[#27272a] px-3 flex items-center justify-between text-zinc-400">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <TerminalIcon className="w-3.5 h-3.5 text-cyan-400" />
            <span className="font-semibold text-[11px] uppercase tracking-wider text-zinc-200">
              Terminal & Execution Engine
            </span>
          </div>
          {activeTarget && (
            <span className="text-[10px] text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">
              target: <span className="text-emerald-400">{cleanHost}</span>
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
                className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-cyan-300 border border-zinc-800 transition"
              >
                {p.label}
              </button>
            ))}
          </div>

          <button
            onClick={clearTerminalLogs}
            title="Xóa màn hình terminal"
            className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded transition"
          >
            <Trash2 className="w-3 h-3" />
          </button>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            title={isExpanded ? 'Thu nhỏ terminal' : 'Phóng to terminal'}
            className="p-1 hover:text-zinc-200 hover:bg-zinc-800 rounded transition"
          >
            {isExpanded ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
          </button>
        </div>
      </div>

      {/* Output Console Stream */}
      <div className="flex-1 p-2.5 overflow-y-auto space-y-0.5 text-zinc-300 font-mono text-[11px] leading-relaxed">
        {terminalLogs.map((log, i) => (
          <div key={i} className="break-all whitespace-pre-wrap">
            {log.startsWith('$ ') ? (
              <span className="text-cyan-300 font-bold">{log}</span>
            ) : log.startsWith('[+]') ? (
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
        {isRunning && (
          <div className="flex items-center space-x-2 text-cyan-400 text-[11px] py-1">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Đang thực thi lệnh trên host...</span>
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
        className="h-8 bg-[#141416] border-t border-[#27272a] px-2 flex items-center space-x-2"
      >
        <span className="text-cyan-400 font-bold text-[11px] select-none flex items-center space-x-1 flex-shrink-0">
          <span className="text-emerald-400">copilot@pentest</span>
          <span className="text-zinc-500">:</span>
          <span className="text-cyan-300">{currentCwd}</span>
          <span className="text-zinc-400">$</span>
        </span>
        <input
          ref={inputRef}
          type="text"
          value={inputCmd}
          disabled={isRunning}
          onChange={(e) => setInputCmd(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={
            isRunning
              ? 'Lệnh đang chạy (bấm Dừng hoặc Ctrl+C để hủy)...'
              : `Nhập lệnh thực thi (ví dụ: ls -la, ping ${cleanHost}, python toolkit/scripts/run_naabu.py...)...`
          }
          className="flex-1 bg-transparent border-none text-zinc-100 placeholder-zinc-600 focus:outline-none text-[11px] font-mono disabled:opacity-50"
        />
        {isRunning ? (
          <button
            type="button"
            onClick={handleKillProcess}
            title="Dừng tiến trình đang chạy (Ctrl+C)"
            className="px-2 py-0.5 bg-red-600 hover:bg-red-500 text-white rounded text-[10px] flex items-center space-x-1 transition"
          >
            <Square className="w-2.5 h-2.5 fill-white" />
            <span>Dừng</span>
          </button>
        ) : (
          <button
            type="submit"
            disabled={!inputCmd.trim()}
            title="Thực thi lệnh (Enter)"
            className="px-2 py-0.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded text-[10px] flex items-center space-x-1 transition"
          >
            <Play className="w-2.5 h-2.5" />
            <span>Chạy</span>
          </button>
        )}
      </form>
    </div>
  );
};
