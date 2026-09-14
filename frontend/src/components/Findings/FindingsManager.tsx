import React, { useState, useEffect } from 'react'
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  FileCode,
  Sparkles,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  Play,
  Terminal,
  Copy,
  Check,
} from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export interface EvidenceItem {
  tool: string;
  file_path: string;
  matched_text: string;
  timestamp?: string;
}

export interface Finding {
  id: string;
  target_id: string;
  title: string;
  cve_id?: string;
  cwe_id?: string;
  cvss_score: number;
  cvss_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'CANDIDATE' | 'UNVERIFIED' | 'VERIFIED' | 'FALSE_POSITIVE' | 'RESOLVED';
  affected_asset: string;
  description: string;
  remediation?: string;
  evidence_chain: EvidenceItem[];
  created_at: string;
  updated_at: string;
}

interface VerificationStep {
  step_number: number;
  name: string;
  description: string;
  command: string;
  is_safe_readonly: boolean;
  expected_evidence: string;
  remediation_check?: string;
}

interface VerificationPlan {
  finding_id: string;
  target_id: string;
  title: string;
  steps: VerificationStep[];
}

export const FindingsManager: React.FC = () => {
  const { activeTarget, openFile, setActiveView } = useWorkspaceStore();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  // Verification Plan state
  const [verificationPlan, setVerificationPlan] = useState<VerificationPlan | null>(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [executingStep, setExecutingStep] = useState<number | null>(null);
  const [stepOutputs, setStepOutputs] = useState<Record<number, { output: string; isVuln: boolean }>>({});
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      let url = '/api/findings';
      if (activeTarget) {
        url += `?target_id=${encodeURIComponent(activeTarget.normalized_value || activeTarget.name)}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
        if (data.length > 0 && !selectedFinding) {
          setSelectedFinding(data[0]);
        }
      }
    } catch (e) {
      console.error('Failed to fetch findings', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [activeTarget]);

  // Load verification plan when finding is selected
  useEffect(() => {
    if (!selectedFinding) {
      setVerificationPlan(null);
      setStepOutputs({});
      return;
    }

    setPlanLoading(true);
    setStepOutputs({});
    fetch(`/api/verification/plan/${selectedFinding.id}`)
      .then((res) => (res.ok ? res.json() : null))
      .then((plan) => {
        setVerificationPlan(plan);
      })
      .catch((err) => console.error('Failed to load plan', err))
      .finally(() => setPlanLoading(false));
  }, [selectedFinding]);

  const handleGenerate = async () => {
    if (!activeTarget) return;
    setLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const res = await fetch(`/api/findings/generate/${encodeURIComponent(targetKey)}`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchFindings();
      }
    } catch (e) {
      console.error('Failed to generate findings', e);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${findingId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const updated = await res.json();
        setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
        if (selectedFinding?.id === findingId) {
          setSelectedFinding(updated);
        }
      }
    } catch (e) {
      console.error('Failed to update status', e);
    }
  };

  const handleExecuteStep = async (step: VerificationStep) => {
    setExecutingStep(step.step_number);
    try {
      const res = await fetch('/api/verification/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: step.command }),
      });
      if (res.ok) {
        const result = await res.json();
        setStepOutputs((prev) => ({
          ...prev,
          [step.step_number]: {
            output: result.output,
            isVuln: result.is_vulnerable_indicated,
          },
        }));
      }
    } catch (err) {
      console.error('Failed to execute check', err);
    } finally {
      setExecutingStep(null);
    }
  };

  const handleCopyCmd = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleOpenEvidence = (ev: EvidenceItem) => {
    const filename = ev.file_path.split('/').pop() || 'evidence';
    openFile({ name: filename, rel_path: ev.file_path });
    setActiveView('editor');
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950/80 border border-red-700 text-red-400">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950/80 border border-orange-700 text-orange-400">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 border border-amber-700 text-amber-400">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950/80 border border-blue-700 text-blue-400">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-zinc-800 border border-zinc-700 text-zinc-400">INFO</span>;
    }
  };

  const getStatusBadge = (stat: string) => {
    switch (stat) {
      case 'VERIFIED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-950/80 border border-emerald-600 text-emerald-300 flex items-center space-x-1"><CheckCircle2 className="w-2.5 h-2.5" /><span>VERIFIED</span></span>;
      case 'FALSE_POSITIVE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-zinc-800 border border-zinc-600 text-zinc-400 line-through">FALSE POSITIVE</span>;
      case 'RESOLVED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-950/80 border border-cyan-600 text-cyan-300">RESOLVED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-950/60 border border-amber-800 text-amber-300">CANDIDATE</span>;
    }
  };

  const filtered = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.cvss_severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(q)) ||
        f.affected_asset.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const countSev = (sev: string) => findings.filter((f) => f.cvss_severity === sev).length;

  return (
    <div className="flex-1 flex flex-col bg-[#141416] text-zinc-300 overflow-hidden select-none">
      {/* Top Banner */}
      <div className="p-3 border-b border-[#27272a] bg-[#101012] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 text-zinc-200 font-bold text-xs">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>FINDINGS BUILDER & VULNERABILITY MANAGEMENT</span>
          </div>
          <div className="flex items-center space-x-2 text-[11px]">
            <span className="px-2 py-0.5 rounded bg-red-950/60 border border-red-800/80 text-red-300 font-semibold">
              Critical: {countSev('CRITICAL')}
            </span>
            <span className="px-2 py-0.5 rounded bg-orange-950/60 border border-orange-800/80 text-orange-300 font-semibold">
              High: {countSev('HIGH')}
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800/80 text-amber-300 font-semibold">
              Medium: {countSev('MEDIUM')}
            </span>
            <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-400">
              Total: {findings.length}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleGenerate}
            disabled={loading || !activeTarget}
            className="flex items-center space-x-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded transition font-medium"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Auto-Generate from Scans</span>
          </button>
          <button
            onClick={fetchFindings}
            className="p-1.5 hover:bg-zinc-800 rounded text-zinc-400 hover:text-zinc-200 transition"
            title="Refresh findings"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="px-3 py-2 border-b border-[#27272a] bg-[#121214] flex items-center space-x-3 text-xs">
        <div className="flex items-center space-x-1 bg-zinc-900 border border-zinc-700 rounded px-2 py-1 flex-1 max-w-xs">
          <Search className="w-3 h-3 text-zinc-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Tìm theo CVE, title, asset..."
            className="bg-transparent text-zinc-200 focus:outline-none text-xs w-full"
          />
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-zinc-500 text-[11px]">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-zinc-500 text-[11px]">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 focus:outline-none"
          >
            <option value="ALL">All Statuses</option>
            <option value="CANDIDATE">Candidate</option>
            <option value="VERIFIED">Verified</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>
      </div>

      {/* Main Split */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Findings List */}
        <div className="w-5/12 border-r border-[#27272a] overflow-y-auto p-2 space-y-1.5">
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-zinc-500 text-xs">
              Chưa có finding nào cho tiêu chí đã chọn. Bấm "Auto-Generate from Scans" để tổng hợp chứng cứ từ kết quả scan.
            </div>
          ) : (
            filtered.map((f) => (
              <div
                key={f.id}
                onClick={() => setSelectedFinding(f)}
                className={`p-2.5 rounded border transition cursor-pointer flex flex-col space-y-1.5 ${
                  selectedFinding?.id === f.id
                    ? 'bg-zinc-900 border-cyan-600/80 shadow-sm'
                    : 'bg-[#18181c] border-zinc-800 hover:border-zinc-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {getSeverityBadge(f.cvss_severity)}
                    {f.cve_id && (
                      <span className="font-mono text-cyan-400 text-[11px] font-semibold">
                        {f.cve_id}
                      </span>
                    )}
                  </div>
                  {getStatusBadge(f.status)}
                </div>

                <div className="font-semibold text-xs text-zinc-200 line-clamp-1">
                  {f.title}
                </div>

                <div className="flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                  <span>Asset: <strong className="text-zinc-400">{f.affected_asset}</strong></span>
                  <span>Evidence: {f.evidence_chain.length} tool(s)</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Right: Detailed Inspector & Verification Runner */}
        <div className="w-7/12 overflow-y-auto p-4 bg-[#121214]">
          {selectedFinding ? (
            <div className="space-y-4">
              {/* Header */}
              <div className="space-y-1 border-b border-zinc-800 pb-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-zinc-500">{selectedFinding.id}</span>
                  <div className="flex items-center space-x-2">
                    {getSeverityBadge(selectedFinding.cvss_severity)}
                    {getStatusBadge(selectedFinding.status)}
                  </div>
                </div>
                <h3 className="text-sm font-bold text-zinc-100">{selectedFinding.title}</h3>
                <div className="flex items-center space-x-4 text-xs font-mono text-zinc-400">
                  <span>Target: <strong className="text-emerald-400">{selectedFinding.target_id}</strong></span>
                  <span>Asset: <strong className="text-zinc-200">{selectedFinding.affected_asset}</strong></span>
                  <span>CVSS: <strong className="text-orange-400">{selectedFinding.cvss_score.toFixed(1)}</strong></span>
                </div>
              </div>

              {/* Status Action Workflow */}
              <div className="bg-zinc-900 border border-zinc-800 rounded p-2.5 flex items-center justify-between">
                <span className="text-xs text-zinc-400">Workflow Action:</span>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleUpdateStatus(selectedFinding.id, 'VERIFIED')}
                    className="px-2.5 py-1 rounded text-xs bg-emerald-700 hover:bg-emerald-600 text-white font-medium transition flex items-center space-x-1"
                  >
                    <CheckCircle2 className="w-3 h-3" />
                    <span>Mark Verified</span>
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedFinding.id, 'FALSE_POSITIVE')}
                    className="px-2 py-1 rounded text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition"
                  >
                    False Positive
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedFinding.id, 'RESOLVED')}
                    className="px-2 py-1 rounded text-xs bg-cyan-800 hover:bg-cyan-700 text-white transition"
                  >
                    Resolve
                  </button>
                </div>
              </div>

              {/* Safe Verification Execution Panel (NEW M6) */}
              <div className="space-y-2 border border-cyan-900/60 bg-cyan-950/20 rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-bold text-cyan-400 flex items-center space-x-1.5 uppercase tracking-wider">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>Kế hoạch kiểm chứng an toàn (Safe Read-Only Verification)</span>
                  </div>
                  {planLoading && <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />}
                </div>

                {verificationPlan ? (
                  <div className="space-y-2 mt-2">
                    {verificationPlan.steps.map((step) => {
                      const result = stepOutputs[step.step_number];
                      const isRunning = executingStep === step.step_number;

                      return (
                        <div
                          key={step.step_number}
                          className="bg-[#0e141e] border border-cyan-950/80 rounded p-2.5 space-y-1.5 text-xs"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-zinc-200">
                              {step.step_number}. {step.name}
                            </span>
                            <div className="flex items-center space-x-1.5">
                              <button
                                onClick={() => handleCopyCmd(step.command)}
                                className="px-1.5 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center space-x-1"
                              >
                                {copiedCmd === step.command ? (
                                  <Check className="w-2.5 h-2.5 text-emerald-400" />
                                ) : (
                                  <Copy className="w-2.5 h-2.5" />
                                )}
                                <span>Copy</span>
                              </button>
                              <button
                                onClick={() => handleExecuteStep(step)}
                                disabled={isRunning}
                                className="px-2 py-0.5 rounded bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-[10px] font-medium flex items-center space-x-1 transition"
                              >
                                {isRunning ? (
                                  <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                                ) : (
                                  <Play className="w-2.5 h-2.5" />
                                )}
                                <span>{isRunning ? 'Checking...' : 'Run Safe Check'}</span>
                              </button>
                            </div>
                          </div>

                          <div className="text-[11px] text-zinc-400">{step.description}</div>

                          <div className="bg-black/60 p-1.5 rounded font-mono text-[10px] text-cyan-300 flex items-center justify-between">
                            <code>{step.command}</code>
                          </div>

                          {/* Live Execution Output */}
                          {result && (
                            <div className="mt-1.5 pt-1.5 border-t border-zinc-800 space-y-1">
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="font-semibold text-zinc-400">Terminal Output:</span>
                                {result.isVuln ? (
                                  <span className="text-red-400 font-bold flex items-center space-x-1">
                                    <AlertTriangle className="w-3 h-3 text-red-400" />
                                    <span>Vulnerability Indicated!</span>
                                  </span>
                                ) : (
                                  <span className="text-emerald-400 font-medium">Safe Response</span>
                                )}
                              </div>
                              <pre className="bg-zinc-950 p-2 rounded text-[10px] font-mono text-zinc-300 whitespace-pre-wrap border border-zinc-800">
                                {result.output}
                              </pre>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-[11px] text-zinc-500 py-2">
                    Đang chuẩn bị kế hoạch kiểm chứng an toàn...
                  </div>
                )}
              </div>

              {/* Description */}
              <div className="space-y-1">
                <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Mô tả chi tiết</div>
                <div className="text-xs leading-relaxed text-zinc-300 bg-zinc-900/60 p-3 rounded border border-zinc-800 whitespace-pre-wrap">
                  {selectedFinding.description}
                </div>
              </div>

              {/* Evidence Chain */}
              <div className="space-y-2">
                <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Chuỗi chứng cứ thực nghiệm (Evidence Chain)</span>
                  <span className="text-zinc-500 font-mono text-[10px]">{selectedFinding.evidence_chain.length} entries</span>
                </div>
                <div className="space-y-2">
                  {selectedFinding.evidence_chain.map((ev, idx) => (
                    <div
                      key={idx}
                      className="bg-black/40 border border-zinc-800 rounded p-2.5 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-800 text-[10px] uppercase font-bold text-cyan-400">
                          Tool: {ev.tool}
                        </span>
                        <button
                          onClick={() => handleOpenEvidence(ev)}
                          className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 underline"
                        >
                          <FileCode className="w-3 h-3" />
                          <span>Xem file raw trong IDE</span>
                        </button>
                      </div>
                      <div className="text-[11px] text-zinc-400 font-mono break-all">
                        {ev.file_path}
                      </div>
                      <div className="bg-zinc-950 p-2 rounded text-[11px] text-zinc-300 font-mono whitespace-pre-wrap border border-zinc-900">
                        {ev.matched_text}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Remediation */}
              {selectedFinding.remediation && (
                <div className="space-y-1">
                  <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Khuyến nghị khắc phục (Remediation)</span>
                  </div>
                  <div className="text-xs text-zinc-300 bg-emerald-950/20 border border-emerald-900/60 p-3 rounded leading-relaxed">
                    {selectedFinding.remediation}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-8 text-center text-zinc-500 text-xs">
              Chọn một finding bên trái để xem chi tiết chứng cứ và kế hoạch kiểm chứng an toàn.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
