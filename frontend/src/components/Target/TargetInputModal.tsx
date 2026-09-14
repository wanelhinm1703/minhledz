import React, { useState } from 'react'
import { X, Search, CheckCircle, AlertTriangle, Play, ShieldAlert } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const TargetInputModal: React.FC = () => {
  const { isTargetModalOpen, setTargetModalOpen, fetchInitialData, appendTerminalLog } = useWorkspaceStore();
  const [inputVal, setInputVal] = useState('http://192.168.56.101:3000');
  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  if (!isTargetModalOpen) return null;

  const handleDetect = async () => {
    if (!inputVal.trim()) return;
    setDetecting(true);
    setError(null);
    setDetection(null);

    try {
      const res = await fetch('/api/targets/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: inputVal.trim() }),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Target detection failed');
      }
      const data = await res.json();
      setDetection(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setDetecting(false);
    }
  };

  const handleScan = async () => {
    if (!detection || !detection.scope.allowed) return;
    setScanning(true);
    appendTerminalLog(`[*] Initiating Recon Pipeline for: ${inputVal}`);

    try {
      const res = await fetch('/api/recon/trigger', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: inputVal.trim() }),
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Recon trigger failed');
      }
      const data = await res.json();
      appendTerminalLog(`[+] Recon completed! Tools: ${data.manifest.tools_executed.join(', ')}`);
      await fetchInitialData();
      setTargetModalOpen(false);
    } catch (err: any) {
      appendTerminalLog(`[!] Error running scan: ${err.message}`);
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#18181b] border border-[#27272a] rounded-lg w-full max-w-lg overflow-hidden shadow-2xl">
        <div className="px-4 py-3 bg-[#121214] border-b border-[#27272a] flex items-center justify-between">
          <h3 className="text-sm font-semibold text-zinc-200">Dynamic Target Ingestion</h3>
          <button onClick={() => setTargetModalOpen(false)} className="text-zinc-400 hover:text-zinc-200">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 space-y-4 text-xs">
          <div>
            <label className="block text-zinc-400 mb-1.5 font-medium">Target Input (IP, URL, CIDR, Domain, Host:Port):</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="e.g. 192.168.56.101, http://192.168.56.101:3000"
                className="flex-1 bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-zinc-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <button
                onClick={handleDetect}
                disabled={detecting}
                className="bg-zinc-700 hover:bg-zinc-600 text-white px-3 py-1.5 rounded flex items-center space-x-1 font-medium transition"
              >
                <Search className="w-3.5 h-3.5" />
                <span>{detecting ? 'Detecting...' : 'Detect'}</span>
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-950/50 border border-red-800 text-red-300 p-2.5 rounded flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {detection && (
            <div className="bg-zinc-900/80 border border-zinc-800 p-3 rounded space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-zinc-400">Target Type:</span>
                <span className="text-cyan-400 font-bold uppercase">{detection.target_type}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-zinc-400">Normalized:</span>
                <span className="text-zinc-200 font-mono">{detection.normalized_value}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-zinc-400">Scope Authorization:</span>
                {detection.scope.allowed ? (
                  <span className="flex items-center space-x-1 text-emerald-400 font-medium">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Authorized</span>
                  </span>
                ) : (
                  <span className="flex items-center space-x-1 text-red-400 font-medium">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>BLOCKED (Out of Scope)</span>
                  </span>
                )}
              </div>
              <div>
                <span className="text-zinc-400 block mb-1">Recommended Tools:</span>
                <div className="flex flex-wrap gap-1">
                  {detection.recommended_tools.map((tool: string) => (
                    <span key={tool} className="bg-cyan-950 text-cyan-300 border border-cyan-800/80 px-2 py-0.5 rounded text-[10px] uppercase font-semibold">
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="px-4 py-3 bg-[#121214] border-t border-[#27272a] flex justify-end space-x-2 text-xs">
          <button
            onClick={() => setTargetModalOpen(false)}
            className="px-3 py-1.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition"
          >
            Cancel
          </button>
          <button
            onClick={handleScan}
            disabled={!detection || !detection.scope.allowed || scanning}
            className={`flex items-center space-x-1.5 px-4 py-1.5 rounded font-medium transition ${
              detection && detection.scope.allowed && !scanning
                ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{scanning ? 'Executing Scan...' : 'Confirm & Scan'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
