import React, { useState, useEffect, useMemo } from "react";
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
  ChevronDown,
  ShieldCheck,
  Play,
  Terminal,
  Copy,
  Check,
  Flame,
  TrendingUp,
  Globe,
  Database,
  Zap,
  Plus,
  Radio,
  Layers,
  Tag,
  ArrowRight,
  Crosshair,
  Server,
  Target,
  X,
} from "lucide-react";

import { useWorkspaceStore } from "../../store/workspaceStore";

export interface EvidenceItem {
  tool: string;
  file_path: string;
  matched_text: string;
  timestamp?: string;
  trustworthy?: boolean;
  is_simulated?: boolean;
}

export interface Finding {
  id: string;
  target_id: string;
  title: string;
  cve_id?: string;
  cwe_id?: string;
  cvss_score: number;
  cvss_severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss_v4_score?: number;
  cvss_v4_severity?: string;
  cvss_v4_vector?: string;
  is_cisa_kev?: boolean;
  epss_score?: number;
  epss_percentile?: number;
  status:
    "CANDIDATE" | "UNVERIFIED" | "VERIFIED" | "FALSE_POSITIVE" | "RESOLVED";
  affected_asset: string;
  description: string;
  remediation?: string;
  evidence_chain: EvidenceItem[];
  trustworthy?: boolean;
  is_simulated?: boolean;
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

export interface CVECandidate {
  cve_id: string;
  cwe_ids: string[];
  cvss_score: number;
  cvss_severity?: string;
  cvss_v4_score?: number;
  cvss_v4_severity?: string;
  cvss_v4_vector?: string;
  is_cisa_kev?: boolean;
  epss_score?: number;
  epss_percentile?: number;
  description: string;
  origin?: "dual" | "online_intel" | "offline_kb" | string;
  source?: string;
  source_url?: string;
  references?: string[];
  confidence?: number;
}

export interface DiscoveredTargetService {
  port: number;
  protocol: string;
  service_name: string;
  product: string;
  raw_product: string;
  version: string;
  cpe: string[];
  source: string;
  label: string;
}

export const FindingsManager: React.FC = () => {
  const { activeTarget, openFile, setActiveView } = useWorkspaceStore();

  // Sub-Tab Switcher: 'findings' | 'checker'
  const [activeSubTab, setActiveSubTab] = useState<"findings" | "checker">("findings");

  // Findings List state
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  // Verification Plan state
  const [verificationPlan, setVerificationPlan] =
    useState<VerificationPlan | null>(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [executingStep, setExecutingStep] = useState<number | null>(null);
  const [stepOutputs, setStepOutputs] = useState<
    Record<number, { output: string; isVuln: boolean }>
  >({});
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  // Target-Bound Discovered Services state
  const [discoveredServices, setDiscoveredServices] = useState<DiscoveredTargetService[]>([]);
  const [servicesLoading, setServicesLoading] = useState(false);
  const [selectedServiceIdx, setSelectedServiceIdx] = useState<number>(0);
  const [isManualOverride, setIsManualOverride] = useState(false);
  const [isServicesCollapsed, setIsServicesCollapsed] = useState(false);

  // Vulnerability Checker state
  const [intelProduct, setIntelProduct] = useState("");
  const [intelVersion, setIntelVersion] = useState("");
  const [intelMode, setIntelMode] = useState<"dual" | "online" | "offline">("dual");
  const [intelLoading, setIntelLoading] = useState(false);
  const [intelResults, setIntelResults] = useState<CVECandidate[]>([]);
  const [intelSearched, setIntelSearched] = useState(false);
  const [selectedIntelCve, setSelectedIntelCve] = useState<CVECandidate | null>(null);
  const [addedCveStatus, setAddedCveStatus] = useState<Record<string, string>>({});
  const [intelQueryError, setIntelQueryError] = useState<string | null>(null);
  const [copiedProbe, setCopiedProbe] = useState(false);
  const [deduping, setDeduping] = useState(false);
  const [dedupMsg, setDedupMsg] = useState<string | null>(null);

  // Batch Recon Online Correlation state
  const [batchCorrelating, setBatchCorrelating] = useState(false);
  const [serviceIntelSummary, setServiceIntelSummary] = useState<
    Record<string, { count: number; hasKev: boolean; maxCvss: number; candidates: CVECandidate[] }>
  >({});

  const handleDeduplicate = async () => {
    if (!activeTarget) return;
    setDeduping(true);
    setDedupMsg(null);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const url = `/api/findings/deduplicate?target_id=${encodeURIComponent(targetKey)}`;
      const res = await fetch(url, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        setDedupMsg(data.message || "Đã gộp trùng lặp thành công!");
        await fetchFindings();
        setTimeout(() => setDedupMsg(null), 5000);
      }
    } catch (e: any) {
      console.error("Failed to deduplicate", e);
    } finally {
      setDeduping(false);
    }
  };

  const fetchFindings = async () => {
    if (!activeTarget) {
      setFindings([]);
      setSelectedFinding(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const res = await fetch(`/api/findings?target_id=${encodeURIComponent(targetKey)}`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
        if (data.length > 0) {
          setSelectedFinding(data[0]);
        } else {
          setSelectedFinding(null);
        }
      } else {
        setFindings([]);
        setSelectedFinding(null);
      }
    } catch (e) {
      console.error("Failed to fetch findings", e);
      setFindings([]);
      setSelectedFinding(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    fetchTargetServices();
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
      .catch((err) => console.error("Failed to load plan", err))
      .finally(() => setPlanLoading(false));
  }, [selectedFinding]);

  const handleGenerate = async () => {
    if (!activeTarget) return;
    setLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name;
      const res = await fetch(
        `/api/findings/generate/${encodeURIComponent(targetKey)}`,
        {
          method: "POST",
        },
      );
      if (res.ok) {
        await fetchFindings();
      }
    } catch (e) {
      console.error("Failed to generate findings", e);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateStatus = async (findingId: string, newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${findingId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const updated = await res.json();
        setFindings((prev) =>
          prev.map((f) => (f.id === findingId ? updated : f)),
        );
        if (selectedFinding?.id === findingId) {
          setSelectedFinding(updated);
        }
      }
    } catch (e) {
      console.error("Failed to update status", e);
    }
  };

  const handleExecuteStep = async (step: VerificationStep) => {
    setExecutingStep(step.step_number);
    try {
      const res = await fetch("/api/verification/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
      console.error("Execute step failed", err);
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
    const fileName = ev.file_path.split("/").pop() || "evidence.txt";
    openFile({ name: fileName, rel_path: ev.file_path });
    setActiveView("editor");
  };

  // Run Vulnerability Intel Check
  const handleRunIntelCheck = async (
    prod = intelProduct,
    ver = intelVersion,
    mode = intelMode,
  ) => {
    if (!prod.trim()) return;
    setIntelLoading(true);
    setIntelQueryError(null);
    setIntelSearched(true);
    try {
      let url = `/api/vulnerabilities/correlate?product=${encodeURIComponent(prod.trim())}&mode=${mode}&limit=30`;
      if (ver.trim()) {
        url += `&version=${encodeURIComponent(ver.trim())}`;
      }
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        const cands: CVECandidate[] = data.candidates || [];
        setIntelResults(cands);
        setSelectedIntelCve(cands.length > 0 ? cands[0] : null);
      } else {
        setIntelQueryError(`Lỗi máy chủ (${res.status}): Không thể tra cứu lỗ hổng.`);
        setIntelResults([]);
      }
    } catch (err: any) {
      setIntelQueryError(err.message || "Lỗi kết nối tra cứu.");
      setIntelResults([]);
    } finally {
      setIntelLoading(false);
    }
  };

  // Fetch Discovered Target Services from Nmap scans, Web scans, and Findings
  const fetchTargetServices = async () => {
    if (!activeTarget) {
      setDiscoveredServices([]);
      return;
    }
    setServicesLoading(true);
    try {
      const targetKey = activeTarget.normalized_value || activeTarget.name || activeTarget.target_id;
      const res = await fetch(`/api/targets/${encodeURIComponent(targetKey)}/services`);
      if (res.ok) {
        const data = await res.json();
        const svcs: DiscoveredTargetService[] = data.services || [];
        setDiscoveredServices(svcs);
        if (svcs.length > 0) {
          setSelectedServiceIdx(0);
          const first = svcs[0];
          setIntelProduct(first.product);
          setIntelVersion(first.version);
          setIsManualOverride(false);
          // Auto-trigger intel check immediately for the active target's primary service!
          handleRunIntelCheck(first.product, first.version, intelMode);
        } else {
          setIntelProduct("");
          setIntelVersion("");
          setIntelResults([]);
          setSelectedIntelCve(null);
        }
      }
    } catch (e) {
      console.error("Failed to fetch target services", e);
    } finally {
      setServicesLoading(false);
    }
  };

  const handleSelectService = (idx: number) => {
    setSelectedServiceIdx(idx);
    setIsManualOverride(false);
    const svc = discoveredServices[idx];
    if (svc) {
      setIntelProduct(svc.product);
      setIntelVersion(svc.version);
      const key = `${svc.port}:${svc.product}`.toLowerCase();
      if (serviceIntelSummary[key]?.candidates?.length) {
        setIntelResults(serviceIntelSummary[key].candidates);
        setSelectedIntelCve(serviceIntelSummary[key].candidates[0] || null);
        setIntelSearched(true);
      } else {
        handleRunIntelCheck(svc.product, svc.version, intelMode);
      }
    }
  };

  // Batch correlate all discovered services for the active target
  const handleCorrelateTargetServicesAll = async () => {
    if (!activeTarget) return;
    const targetKey = activeTarget.normalized_value || activeTarget.name || activeTarget.target_id;
    setBatchCorrelating(true);
    setIntelQueryError(null);
    try {
      let results: any[] = [];
      let success = false;

      // 1. Try primary batch route /api/vulnerabilities/correlate-target/{target_id}
      try {
        const res = await fetch(
          `/api/vulnerabilities/correlate-target/${encodeURIComponent(targetKey)}?mode=${intelMode}&limit_per_service=20`
        );
        if (res.ok) {
          const data = await res.json();
          results = data.results || [];
          success = true;
        }
      } catch {}

      // 2. Try alias route /api/targets/{target_id}/correlate if primary failed
      if (!success) {
        try {
          const res2 = await fetch(
            `/api/targets/${encodeURIComponent(targetKey)}/correlate?mode=${intelMode}&limit_per_service=20`
          );
          if (res2.ok) {
            const data2 = await res2.json();
            results = data2.results || [];
            success = true;
          }
        } catch {}
      }

      // 3. Resilient client-side fallback: parallel fetch per discovered service
      if (!success) {
        if (discoveredServices.length > 0) {
          const fetchedResults = await Promise.all(
            discoveredServices.map(async (svc) => {
              if (!svc.product) {
                return {
                  service: svc,
                  product: "",
                  version: "",
                  candidates: [],
                  total_cves: 0,
                  has_kev: false,
                  max_cvss: 0,
                };
              }
              try {
                const qRes = await fetch(
                  `/api/vulnerabilities/correlate?product=${encodeURIComponent(svc.product)}&version=${encodeURIComponent(svc.version || "")}&limit=20&mode=${intelMode}`
                );
                if (qRes.ok) {
                  const cData = await qRes.json();
                  const candidates: CVECandidate[] = cData.candidates || [];
                  const hasKev = candidates.some((c) => c.is_cisa_kev);
                  const maxCvss = candidates.reduce((max, c) => Math.max(max, c.cvss_score || 0), 0);
                  return {
                    service: svc,
                    product: svc.product,
                    version: svc.version,
                    candidates,
                    total_cves: candidates.length,
                    has_kev: hasKev,
                    max_cvss: maxCvss,
                  };
                }
              } catch (e) {
                console.warn("Service correlate fetch failed for", svc.product, e);
              }
              return {
                service: svc,
                product: svc.product,
                version: svc.version,
                candidates: [],
                total_cves: 0,
                has_kev: false,
                max_cvss: 0,
              };
            })
          );
          results = fetchedResults;
          success = true;
        } else {
          setIntelQueryError("Chưa phát hiện dịch vụ nào cho mục tiêu này để đối soát.");
          return;
        }
      }

      if (success) {
        const summaryMap: Record<
          string,
          { count: number; hasKev: boolean; maxCvss: number; candidates: CVECandidate[] }
        > = {};
        let allCands: CVECandidate[] = [];

        results.forEach((r: any) => {
          const key = `${r.service?.port || 0}:${r.product}`.toLowerCase();
          summaryMap[key] = {
            count: r.total_cves,
            hasKev: r.has_kev,
            maxCvss: r.max_cvss,
            candidates: r.candidates || [],
          };
          if (r.candidates && r.candidates.length > 0) {
            allCands = allCands.concat(r.candidates);
          }
        });

        setServiceIntelSummary(summaryMap);

        const currSvc = discoveredServices[selectedServiceIdx];
        const currKey = currSvc ? `${currSvc.port}:${currSvc.product}`.toLowerCase() : "";
        if (currKey && summaryMap[currKey]?.candidates?.length) {
          setIntelResults(summaryMap[currKey].candidates);
          setSelectedIntelCve(summaryMap[currKey].candidates[0]);
        } else if (allCands.length > 0) {
          setIntelResults(allCands);
          setSelectedIntelCve(allCands[0]);
        }
        setIntelSearched(true);
      }
    } catch (err: any) {
      setIntelQueryError(err.message || "Lỗi kết nối đối soát trực tuyến.");
    } finally {
      setBatchCorrelating(false);
    }
  };

  const handleChangeIntelMode = (newMode: "dual" | "online" | "offline") => {
    setIntelMode(newMode);
    if (intelProduct.trim()) {
      handleRunIntelCheck(intelProduct, intelVersion, newMode);
    }
  };

  // When switching to checker tab, auto-query if not queried yet
  useEffect(() => {
    if (activeSubTab === "checker" && discoveredServices.length > 0 && !intelSearched) {
      const curr = discoveredServices[selectedServiceIdx] || discoveredServices[0];
      if (curr && curr.product) {
        setIntelProduct(curr.product);
        setIntelVersion(curr.version);
        handleRunIntelCheck(curr.product, curr.version, intelMode);
      }
    }
  }, [activeSubTab, discoveredServices]);

  // Add Candidate to Target Findings
  const handleAddToTargetFindings = async (cand: CVECandidate) => {
    if (!activeTarget) {
      alert("Vui lòng chọn hoặc thêm mục tiêu (Target) trước khi thêm finding!");
      return;
    }
    const targetKey = activeTarget.normalized_value || activeTarget.name;
    const activeSvc = discoveredServices[selectedServiceIdx];
    const assetPort = activeSvc && activeSvc.port > 0 ? `:${activeSvc.port}` : "";
    const affectedAsset = `${activeTarget.host || targetKey}${assetPort || ":" + intelProduct.toLowerCase()}`;

    const body = {
      target_id: targetKey,
      title: `${intelProduct} ${intelVersion ? intelVersion + " " : ""}[${cand.origin?.toUpperCase() || "INTEL"}] — ${cand.cve_id}`,
      cve_id: cand.cve_id,
      cwe_id: cand.cwe_ids?.[0] || "CWE-20",
      cvss_score: cand.cvss_score || 7.5,
      cvss_severity: cand.cvss_severity || "HIGH",
      cvss_v4_score: cand.cvss_v4_score,
      cvss_v4_severity: cand.cvss_v4_severity,
      is_cisa_kev: !!cand.is_cisa_kev,
      epss_score: cand.epss_score,
      epss_percentile: cand.epss_percentile,
      status: "CANDIDATE",
      affected_asset: affectedAsset,
      description: `[Nguồn: ${cand.source || "Threat Intel"}] ${cand.description}`,
      remediation: `Nâng cấp ${intelProduct} lên phiên bản mới nhất đã được vá lỗi (${cand.cve_id}). Tham khảo: ${cand.source_url || "https://nvd.nist.gov"}.`,
      evidence_chain: [
        {
          tool: cand.origin === "online_intel" ? "osv_online" : cand.origin === "dual" ? "dual_intel" : "kb_offline",
          file_path: cand.source_url || "https://api.osv.dev",
          matched_text: `${intelProduct} ${intelVersion} verified against ${cand.source || "Knowledge Base"}. Origin: ${cand.origin}`,
          trustworthy: true,
          is_simulated: false,
        },
      ],
      trustworthy: true,
      is_simulated: false,
    };

    try {
      const res = await fetch("/api/findings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        setAddedCveStatus((prev) => ({ ...prev, [cand.cve_id]: "added" }));
        fetchFindings();
      } else {
        setAddedCveStatus((prev) => ({ ...prev, [cand.cve_id]: "error" }));
      }
    } catch {
      setAddedCveStatus((prev) => ({ ...prev, [cand.cve_id]: "error" }));
    }
  };

  // Quick suggestions from active target findings or popular targets
  const targetServices = useMemo(() => {
    if (discoveredServices.length > 0) {
      return discoveredServices.map((s) => ({
        name: s.label,
        prod: s.product,
        ver: s.version,
      }));
    }
    const list: Array<{ name: string; prod: string; ver: string }> = [];
    findings.forEach((f) => {
      const match = f.title.match(/(Apache|OpenSSH|nginx|Log4j|MySQL|Redis|PHP|ProFTPD|vsftpd|Samba)\s*([0-9\.]+[\w\.\-]*)/i);
      if (match) {
        const prod = match[1];
        const ver = match[2];
        if (!list.some((item) => item.prod.toLowerCase() === prod.toLowerCase() && item.ver === ver)) {
          list.push({ name: `${prod} ${ver}`, prod, ver });
        }
      }
    });
    if (list.length === 0) {
      list.push(
        { name: "Apache 2.4.49", prod: "Apache", ver: "2.4.49" },
        { name: "OpenSSH 8.2p1", prod: "OpenSSH", ver: "8.2p1" },
        { name: "Log4j 2.14.1", prod: "Log4j", ver: "2.14.1" },
        { name: "nginx 1.18.0", prod: "nginx", ver: "1.18.0" },
      );
    }
    return list;
  }, [discoveredServices, findings]);

  // Deduplicated intel results
  const uniqueIntelResults = useMemo(() => {
    const seen = new Set<string>();
    return intelResults.filter((c) => {
      const key = (c.cve_id || "").toUpperCase().trim();
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [intelResults]);

  // Filter findings
  const filtered = findings.filter((f) => {
    if (severityFilter !== "ALL" && f.cvss_severity !== severityFilter) {
      return false;
    }
    if (statusFilter !== "ALL" && f.status !== statusFilter) {
      return false;
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(q)) ||
        f.affected_asset.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const countSev = (sev: string) =>
    findings.filter((f) => f.cvss_severity === sev).length;

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case "CRITICAL":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-red-950/80 border border-red-800 text-red-300">
            NGHIÊM TRỌNG
          </span>
        );
      case "HIGH":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-orange-950/80 border border-orange-800 text-orange-300">
            MỨC CAO
          </span>
        );
      case "MEDIUM":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-amber-950/80 border border-amber-800 text-amber-300">
            TRUNG BÌNH
          </span>
        );
      case "LOW":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-blue-950/80 border border-blue-800 text-blue-300">
            MỨC THẤP
          </span>
        );
      default:
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-bold bg-zinc-800 border border-zinc-700 text-zinc-400">
            THÔNG TIN
          </span>
        );
    }
  };

  const getOriginBadge = (origin?: string, source?: string) => {
    if (origin === "dual" || (source && source.toLowerCase().includes("dual"))) {
      return (
        <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-950/80 border border-purple-700/80 text-purple-300 flex items-center space-x-1">
          <Zap className="w-2.5 h-2.5" />
          <span>ĐỐI SOÁT KÉP</span>
        </span>
      );
    }
    if (origin === "online_intel" || (source && (source.toLowerCase().includes("online") || source.toLowerCase().includes("osv")))) {
      return (
        <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 flex items-center space-x-1">
          <Globe className="w-2.5 h-2.5" />
          <span>TÌNH BÁO ONLINE</span>
        </span>
      );
    }
    return (
      <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-zinc-900 border border-zinc-700 text-zinc-400 flex items-center space-x-1">
        <Database className="w-2.5 h-2.5" />
        <span>CSDL NỘI BỘ</span>
      </span>
    );
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "VERIFIED":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-emerald-950/60 border border-emerald-800 text-emerald-300">
            Đã xác thực
          </span>
        );
      case "FALSE_POSITIVE":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-zinc-800 border border-zinc-700 text-zinc-400">
            Báo động giả
          </span>
        );
      case "RESOLVED":
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-cyan-950/60 border border-cyan-800 text-cyan-300">
            Đã xử lý
          </span>
        );
      default:
        return (
          <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-amber-950/60 border border-amber-800 text-amber-300">
            Tiềm ẩn
          </span>
        );
    }
  };

  return (
    <div className="flex-1 min-h-0 flex flex-col bg-[#0a0d14] text-zinc-300 overflow-hidden select-none">
      {/* Top Banner with Sub-Tab Switcher */}
      <div className="px-3.5 py-2 border-b border-[#1e293b] bg-[#0c101c] flex items-center justify-between gap-3 text-xs shrink-0 select-none font-sans">
        <div className="flex items-center gap-3 min-w-0">
          {/* Logo / Section Badge */}
          <div className="flex items-center gap-1.5 shrink-0">
            <div className="w-6 h-6 rounded-md bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shadow-sm">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>
            <span className="font-bold text-xs tracking-wide text-zinc-200 hidden sm:inline whitespace-nowrap">
              FINDINGS & INTEL
            </span>
          </div>

          {/* Sub-Tab Navigation */}
          <div className="flex items-center bg-[#070a11] border border-[#1e293b] rounded-lg p-0.5 text-xs shadow-inner shrink-0">
            <button
              onClick={() => setActiveSubTab("findings")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all duration-150 whitespace-nowrap ${
                activeSubTab === "findings"
                  ? "bg-[#141d33] text-cyan-300 border border-cyan-700/50 font-semibold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
              <span>Target Findings</span>
              <span
                className={`px-1.5 py-0.2 text-[10px] font-mono rounded-full ${
                  activeSubTab === "findings"
                    ? "bg-cyan-900/70 text-cyan-200 border border-cyan-700/60"
                    : "bg-zinc-800 text-zinc-400"
                }`}
              >
                {findings.length}
              </span>
            </button>
            <button
              onClick={() => setActiveSubTab("checker")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-md transition-all duration-150 whitespace-nowrap ${
                activeSubTab === "checker"
                  ? "bg-[#1c1530] text-purple-300 border border-purple-700/50 font-semibold shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Search className="w-3.5 h-3.5 text-purple-400" />
              <span>Vulnerability Intel & Checker</span>
              <span className="px-1.5 py-0.2 text-[9px] font-mono rounded bg-purple-900/60 border border-purple-700/60 text-purple-300">
                Dual-Mode
              </span>
            </button>
          </div>
        </div>

        {/* Action / Stats Area */}
        <div className="flex items-center gap-2 shrink-0">
          {activeSubTab === "findings" ? (
            <>
              {/* Compact Severity Pill Dashboard */}
              <div className="hidden md:flex items-center gap-2 bg-[#070a11] px-2.5 py-1 rounded-lg border border-[#1e293b] text-xs font-mono whitespace-nowrap shadow-inner">
                <span className="flex items-center gap-1.5 text-rose-400 font-semibold" title="Nghiêm trọng (Critical)">
                  <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                  <span className="text-[10px] text-zinc-400 font-sans font-normal">Crit:</span>
                  <span>{countSev("CRITICAL")}</span>
                </span>
                <span className="text-zinc-700">|</span>
                <span className="flex items-center gap-1.5 text-amber-400 font-semibold" title="Mức cao (High)">
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                  <span className="text-[10px] text-zinc-400 font-sans font-normal">High:</span>
                  <span>{countSev("HIGH")}</span>
                </span>
                <span className="text-zinc-700">|</span>
                <span className="flex items-center gap-1.5 text-yellow-400 font-semibold" title="Trung bình (Medium)">
                  <span className="w-2 h-2 rounded-full bg-yellow-500" />
                  <span className="text-[10px] text-zinc-400 font-sans font-normal">Med:</span>
                  <span>{countSev("MEDIUM")}</span>
                </span>
              </div>

              {/* Deduplicate Button */}
              <button
                onClick={handleDeduplicate}
                disabled={deduping || loading || !activeTarget || findings.length === 0}
                className="h-7.5 px-2.5 rounded-lg bg-[#121829] hover:bg-[#1a233b] border border-[#1e293b] hover:border-cyan-700/60 text-zinc-200 text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm whitespace-nowrap disabled:opacity-50"
                title="Gộp các lỗ hổng trùng lặp từ nhiều công cụ quét về 1 bản ghi duy nhất"
              >
                <Layers
                  className={`w-3.5 h-3.5 text-cyan-400 ${deduping ? "animate-spin" : ""}`}
                />
                <span>Gộp trùng lặp</span>
              </button>

              {/* Generate from Scans Button */}
              <button
                onClick={handleGenerate}
                disabled={loading || !activeTarget}
                className="h-7.5 px-3 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium flex items-center gap-1.5 transition-all shadow-sm whitespace-nowrap disabled:opacity-50"
                title="Tự động phân tích và tạo findings từ kết quả quét (Nmap, Nuclei, Nikto...)"
              >
                <Sparkles className="w-3.5 h-3.5 text-cyan-200" />
                <span>Tạo từ kết quả quét</span>
              </button>

              {/* Refresh Button */}
              <button
                onClick={fetchFindings}
                className="h-7.5 w-7.5 rounded-lg bg-[#121829] hover:bg-[#1a233b] border border-[#1e293b] text-zinc-400 hover:text-cyan-300 flex items-center justify-center transition-all shadow-sm shrink-0"
                title="Làm mới findings"
              >
                <RefreshCw
                  className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
                />
              </button>
            </>
          ) : (
            <div className="flex items-center gap-2 text-xs whitespace-nowrap">
              <span className="text-zinc-400 text-[11px] font-medium">Mục tiêu gắn kết:</span>
              <span className="inline-flex items-center gap-1.5 font-mono text-emerald-400 font-semibold bg-emerald-950/40 border border-emerald-800/60 px-2.5 py-1 rounded-md text-xs shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                <span>{activeTarget ? (activeTarget.name || activeTarget.normalized_value) : "Chưa chọn (hãy chọn target)"}</span>
              </span>
              {discoveredServices.length > 0 && (
                <span className="hidden sm:inline-flex px-2 py-0.5 rounded-md bg-[#121829] border border-[#1e293b] text-cyan-400 font-mono text-[11px]">
                  {discoveredServices.length} services
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Deduplication Notification Toast */}
      {dedupMsg && (
        <div className="px-4 py-2 bg-emerald-950/90 border-b border-emerald-600 text-emerald-200 text-xs flex items-center justify-between shadow-md">
          <span className="flex items-center space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span className="font-medium">{dedupMsg}</span>
          </span>
          <button
            onClick={() => setDedupMsg(null)}
            className="text-emerald-400 hover:text-emerald-100 text-xs px-1.5 py-0.5 rounded hover:bg-emerald-900/50"
          >
            Đóng ✕
          </button>
        </div>
      )}

      {/* ==================== SUB-TAB 1: TARGET FINDINGS ==================== */}
      {activeSubTab === "findings" && (
        <div className="flex-1 min-h-0 flex flex-col overflow-hidden bg-[#0a0d14]">
          {/* Filter Bar */}
          <div className="px-3 py-2 border-b border-[#1e293b] bg-[#0c101c] flex items-center space-x-3 text-xs shrink-0">
            <div className="flex items-center space-x-1.5 bg-[#121829] border border-[#1e293b] rounded-lg px-2.5 py-1.5 flex-1 max-w-xs focus-within:border-cyan-500 transition-colors">
              <Search className="w-3.5 h-3.5 text-zinc-500" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Tìm theo CVE, tiêu đề, mục tiêu..."
                className="bg-transparent text-zinc-100 placeholder-zinc-500 focus:outline-none text-xs w-full font-mono"
              />
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-zinc-400 text-[11px]">Mức độ:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#121829] border border-[#1e293b] rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none cursor-pointer"
              >
                <option value="ALL">Tất cả mức độ</option>
                <option value="CRITICAL">Nghiêm trọng (Critical)</option>
                <option value="HIGH">Mức cao (High)</option>
                <option value="MEDIUM">Trung bình (Medium)</option>
                <option value="LOW">Mức thấp (Low)</option>
                <option value="INFO">Thông tin (Info)</option>
              </select>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-zinc-400 text-[11px]">Trạng thái:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-[#121829] border border-[#1e293b] rounded-lg px-2.5 py-1.5 text-xs text-zinc-300 focus:outline-none cursor-pointer"
              >
                <option value="ALL">Tất cả trạng thái</option>
                <option value="CANDIDATE">Tiềm ẩn (Candidate)</option>
                <option value="VERIFIED">Đã xác thực (Verified)</option>
                <option value="FALSE_POSITIVE">Báo động giả (False Positive)</option>
                <option value="RESOLVED">Đã xử lý (Resolved)</option>
              </select>
            </div>
          </div>

          {/* Main Split */}
          {!activeTarget ? (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center mx-auto text-cyan-400 shadow-inner">
                <Target className="w-8 h-8" />
              </div>
              <div className="space-y-1 max-w-md">
                <h3 className="text-base font-bold text-zinc-100">
                  Chưa chọn mục tiêu phân tích
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  Vui lòng thêm hoặc chọn một mục tiêu trong thanh bên trái (Workspace Explorer) để xem danh sách lỗ hổng (Findings) và phân tích rủi ro bảo mật.
                </p>
              </div>
              <div className="inline-flex items-center space-x-2 text-xs font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 px-3.5 py-2 rounded-lg">
                <span>Workspace Explorer → + Thêm mục tiêu</span>
              </div>
            </div>
          ) : (
            <div className="flex-1 min-h-0 flex overflow-hidden">
              {/* Left: Findings List */}
              <div className="w-5/12 border-r border-[#1e293b] overflow-y-auto p-2.5 space-y-2 bg-[#0a0d14]">
                {findings.length === 0 ? (
                  <div className="p-8 text-center text-zinc-500 text-xs space-y-3">
                    <div>
                      Mục tiêu <strong className="text-zinc-200 font-mono">{activeTarget.name}</strong> chưa có phát hiện lỗ hổng nào.
                    </div>
                    <button
                      onClick={handleGenerate}
                      disabled={loading}
                      className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow transition"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Tạo từ kết quả quét</span>
                    </button>
                  </div>
                ) : filtered.length === 0 ? (
                  <div className="p-8 text-center text-zinc-500 text-xs">
                    Không có finding phù hợp với bộ lọc hiện tại.
                  </div>
                ) : (
                  filtered.map((f) => (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className={`p-2.5 rounded border transition cursor-pointer flex flex-col space-y-1.5 ${
                      selectedFinding?.id === f.id
                        ? "bg-zinc-900 border-cyan-600/80 shadow-sm"
                        : "bg-[#18181c] border-zinc-800 hover:border-zinc-700"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        {getSeverityBadge(f.cvss_severity)}
                        {f.cve_id && (
                          <span className="font-mono text-cyan-400 text-[11px] font-semibold">
                            {f.cve_id}
                          </span>
                        )}
                        {f.is_cisa_kev && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-950/90 border border-red-500 text-red-300 font-mono animate-pulse">
                            🔥 CISA KEV
                          </span>
                        )}
                        {f.epss_score !== undefined && f.epss_score !== null && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-950/90 border border-purple-600 text-purple-300 font-mono">
                            EPSS: {(f.epss_score * 100).toFixed(0)}%
                          </span>
                        )}
                        {(f.trustworthy === false || f.is_simulated) && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-950/90 border border-amber-600 text-amber-300 font-mono">
                            MÔ PHỎNG
                          </span>
                        )}
                      </div>
                      {getStatusBadge(f.status)}
                    </div>

                    <div className="font-semibold text-xs text-zinc-200 line-clamp-1">
                      {f.title}
                    </div>

                    {/* Source Tools & Consolidated Badges */}
                    {f.evidence_chain && f.evidence_chain.length > 0 && (
                      <div className="flex items-center space-x-1 flex-wrap gap-1">
                        {Array.from(
                          new Set(f.evidence_chain.map((e) => e.tool).filter(Boolean)),
                        ).map((toolName) => (
                          <span
                            key={toolName}
                            className="px-1.5 py-0.2 rounded text-[9px] font-mono font-medium bg-zinc-900 border border-zinc-700/80 text-cyan-300"
                          >
                            {toolName}
                          </span>
                        ))}
                        {f.evidence_chain.length > 1 && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-semibold bg-cyan-950/80 border border-cyan-700/80 text-cyan-300 flex items-center space-x-1">
                            <Layers className="w-2.5 h-2.5" />
                            <span>Gộp {f.evidence_chain.length} chứng cứ</span>
                          </span>
                        )}
                      </div>
                    )}

                    <div className="flex items-center justify-between text-[11px] text-zinc-500 font-mono pt-0.5">
                      <span>
                        Mục tiêu: <strong className="text-zinc-400">{f.affected_asset}</strong>
                      </span>
                      <span>{f.evidence_chain.length} bằng chứng</span>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Right: Detailed Inspector */}
            <div className="w-7/12 overflow-y-auto p-4 bg-[#121214]">
              {selectedFinding ? (
                <div className="space-y-4">
                  {/* Simulated Warning */}
                  {(selectedFinding.trustworthy === false || selectedFinding.is_simulated) && (
                    <div className="bg-amber-950/40 border border-amber-600/80 rounded p-3 flex items-start space-x-2.5 text-amber-200 text-xs">
                      <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <div className="font-bold text-amber-300 uppercase tracking-wide">
                          CẢNH BÁO: DỮ LIỆU MÔ PHỎNG (SIMULATED / UNVERIFIED FINDING)
                        </div>
                        <div className="text-[11px] text-amber-200/90 leading-relaxed">
                          Finding này được tạo từ công cụ chạy ở chế độ SIMULATED. Bằng chứng này <strong>chưa được xác thực trên môi trường thực</strong>.
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Header & Direct Clickable Links */}
                  <div className="space-y-2 border-b border-zinc-800 pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs text-zinc-500">
                          {selectedFinding.id}
                        </span>
                        {(selectedFinding.trustworthy === false || selectedFinding.is_simulated) && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-950 text-amber-300 border border-amber-600 font-mono">
                            CHỨNG CỨ MÔ PHỎNG
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-2">
                        {getSeverityBadge(selectedFinding.cvss_severity)}
                        {getStatusBadge(selectedFinding.status)}
                      </div>
                    </div>

                    <h3 className="text-sm font-bold text-zinc-100">
                      {selectedFinding.title}
                    </h3>

                    {/* Direct Authoritative Database Links */}
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      {selectedFinding.cve_id && (
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${selectedFinding.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Mở hồ sơ chính thức trên NIST NVD"
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/80 text-cyan-300 font-mono text-xs font-semibold hover:bg-cyan-900 transition"
                        >
                          <span>{selectedFinding.cve_id}</span>
                          <ExternalLink className="w-3 h-3 text-cyan-400" />
                        </a>
                      )}
                      {selectedFinding.cve_id && (
                        <a
                          href={`https://osv.dev/vulnerability/${selectedFinding.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Xem thông tin Open Source Vulnerability trên Google OSV.dev"
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 font-mono text-xs hover:bg-emerald-900 transition"
                        >
                          <Globe className="w-3 h-3 text-emerald-400" />
                          <span>Google OSV</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                      {selectedFinding.cve_id && (
                        <a
                          href={`https://www.exploit-db.com/search?cve=${selectedFinding.cve_id.replace("CVE-", "")}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Tra cứu Proof of Concept trên Exploit-DB"
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-purple-950/80 border border-purple-700/80 text-purple-300 font-mono text-xs hover:bg-purple-900 transition"
                        >
                          <Zap className="w-3 h-3 text-purple-400" />
                          <span>Exploit-DB</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                      {selectedFinding.cwe_id && (
                        <a
                          href={`https://cwe.mitre.org/data/definitions/${selectedFinding.cwe_id.replace(/\D/g, "")}.html`}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Xem phân loại MITRE CWE"
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-300 font-mono text-xs hover:bg-zinc-800 transition"
                        >
                          <span>{selectedFinding.cwe_id}</span>
                          <ExternalLink className="w-2.5 h-2.5 text-zinc-400" />
                        </a>
                      )}
                    </div>

                    <div className="flex items-center space-x-4 text-xs font-mono text-zinc-400 pt-1">
                      <span>
                        Mục tiêu: <strong className="text-emerald-400">{selectedFinding.target_id}</strong>
                      </span>
                      <span>
                        Thực thể: <strong className="text-zinc-200">{selectedFinding.affected_asset}</strong>
                      </span>
                      <span>
                        Điểm CVSS: <strong className="text-orange-400">{selectedFinding.cvss_score.toFixed(1)}</strong>
                      </span>
                    </div>
                  </div>

                  {/* Threat Intelligence & Live Exploitation Scoring */}
                  {(selectedFinding.is_cisa_kev ||
                    selectedFinding.epss_score !== undefined ||
                    selectedFinding.cvss_v4_score) && (
                    <div className="bg-gradient-to-r from-zinc-900 via-zinc-900 to-[#1e1520] border border-zinc-700/80 rounded-lg p-3 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider flex items-center space-x-1.5">
                          <Flame className="w-4 h-4 text-red-400" />
                          <span>Tình báo mối đe dọa trực tiếp (Live Threat Intel)</span>
                        </span>
                        <span className="text-[10px] text-zinc-500 font-mono">
                          CISA Catalog • FIRST EPSS • CVSS v4.0
                        </span>
                      </div>

                      <div className="grid grid-cols-3 gap-2 pt-1">
                        {/* CISA KEV Status with Link */}
                        <div className="bg-zinc-950/60 border border-zinc-800 rounded p-2 flex flex-col justify-between">
                          <span className="text-[10px] uppercase font-semibold text-zinc-400">
                            Danh mục CISA KEV
                          </span>
                          {selectedFinding.is_cisa_kev ? (
                            <a
                              href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mt-1 font-bold text-xs text-red-400 flex items-center space-x-1 animate-pulse hover:underline"
                            >
                              <span>🔥 Đang bị khai thác thực tế</span>
                              <ExternalLink className="w-2.5 h-2.5" />
                            </a>
                          ) : (
                            <span className="mt-1 text-xs text-zinc-500">Chưa ghi nhận KEV</span>
                          )}
                        </div>

                        {/* EPSS Score */}
                        <div className="bg-zinc-950/60 border border-zinc-800 rounded p-2 flex flex-col justify-between">
                          <span className="text-[10px] uppercase font-semibold text-zinc-400">
                            Xác suất bị khai thác (EPSS 30 ngày)
                          </span>
                          {selectedFinding.epss_score !== undefined && selectedFinding.epss_score !== null ? (
                            <div className="mt-1">
                              <span className="font-bold text-xs text-purple-300 font-mono">
                                {(selectedFinding.epss_score * 100).toFixed(1)}%
                              </span>
                              {selectedFinding.epss_percentile !== undefined && selectedFinding.epss_percentile !== null && (
                                <span className="text-[10px] text-zinc-400 ml-1.5 font-mono">
                                  ({(selectedFinding.epss_percentile * 100).toFixed(1)}%ile)
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className="mt-1 text-xs text-zinc-500">N/A</span>
                          )}
                        </div>

                        {/* CVSS v4.0 Score */}
                        <div className="bg-zinc-950/60 border border-zinc-800 rounded p-2 flex flex-col justify-between">
                          <span className="text-[10px] uppercase font-semibold text-zinc-400">
                            Điểm số CVSS v4.0
                          </span>
                          {selectedFinding.cvss_v4_score ? (
                            <div className="mt-1">
                              <span className="font-bold text-xs text-cyan-300 font-mono">
                                {selectedFinding.cvss_v4_score.toFixed(1)}
                              </span>
                              {selectedFinding.cvss_v4_severity && (
                                <span className="text-[10px] text-zinc-400 ml-1 font-semibold">
                                  [{selectedFinding.cvss_v4_severity}]
                                </span>
                              )}
                            </div>
                          ) : (
                            <span className="mt-1 text-xs text-zinc-500">
                              v3.1: {selectedFinding.cvss_score.toFixed(1)}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Status Action Workflow */}
                  <div className="bg-zinc-900 border border-zinc-800 rounded p-2.5 flex items-center justify-between">
                    <span className="text-xs text-zinc-400">Thao tác trạng thái:</span>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleUpdateStatus(selectedFinding.id, "VERIFIED")}
                        className="px-2.5 py-1 rounded text-xs bg-emerald-700 hover:bg-emerald-600 text-white font-medium transition flex items-center space-x-1"
                      >
                        <CheckCircle2 className="w-3 h-3" />
                        <span>Xác nhận tồn tại</span>
                      </button>
                      <button
                        onClick={() => handleUpdateStatus(selectedFinding.id, "FALSE_POSITIVE")}
                        className="px-2 py-1 rounded text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 transition"
                      >
                        Báo động giả
                      </button>
                      <button
                        onClick={() => handleUpdateStatus(selectedFinding.id, "RESOLVED")}
                        className="px-2 py-1 rounded text-xs bg-cyan-800 hover:bg-cyan-700 text-white transition"
                      >
                        Đã xử lý
                      </button>
                    </div>
                  </div>

                  {/* Safe Verification Execution Panel */}
                  <div className="space-y-2 border border-cyan-900/60 bg-cyan-950/20 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-bold text-cyan-400 flex items-center space-x-1.5 uppercase tracking-wider">
                        <ShieldCheck className="w-4 h-4 text-cyan-400" />
                        <span>Kế hoạch kiểm chứng an toàn (Safe Read-Only Verification)</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setActiveView("topology")}
                          className="flex items-center space-x-1 px-2 py-0.5 rounded bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 text-[10px] font-semibold transition"
                          title="Xem chuỗi tấn công (Attack Chain) trên Đồ thị Topology"
                        >
                          <Crosshair className="w-3 h-3" />
                          <span>Xem Attack Chain</span>
                        </button>
                        {planLoading && (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                        )}
                      </div>
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
                                    <span>Sao chép</span>
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
                                    <span>{isRunning ? "Đang kiểm tra..." : "Chạy kiểm tra an toàn"}</span>
                                  </button>
                                </div>
                              </div>

                              <div className="text-[11px] text-zinc-400">
                                {step.description}
                              </div>

                              <div className="bg-black/60 p-1.5 rounded font-mono text-[10px] text-cyan-300 flex items-center justify-between">
                                <code>{step.command}</code>
                              </div>

                              {result && (
                                <div className="mt-1.5 pt-1.5 border-t border-zinc-800 space-y-1">
                                  <div className="flex items-center justify-between text-[10px]">
                                    <span className="font-semibold text-zinc-400">
                                      Kết quả thực thi (Terminal Output):
                                    </span>
                                    {result.isVuln ? (
                                      <span className="text-red-400 font-bold flex items-center space-x-1">
                                        <AlertTriangle className="w-3 h-3 text-red-400" />
                                        <span>Phát hiện dấu hiệu lỗ hổng!</span>
                                      </span>
                                    ) : (
                                      <span className="text-emerald-400 font-medium">
                                        Phản hồi an toàn (Không phát hiện)
                                      </span>
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
                    <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                      Mô tả chi tiết
                    </div>
                    <div className="text-xs leading-relaxed text-zinc-300 bg-zinc-900/60 p-3 rounded border border-zinc-800 whitespace-pre-wrap">
                      {selectedFinding.description}
                    </div>
                  </div>

                  {/* Evidence Chain */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center justify-between">
                      <span>Chuỗi chứng cứ thực nghiệm (Evidence Chain)</span>
                      <span className="text-zinc-500 font-mono text-[10px]">
                        {selectedFinding.evidence_chain.length} entries
                      </span>
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
                            {ev.file_path.startsWith("http") ? (
                              <a
                                href={ev.file_path}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 underline"
                              >
                                <ExternalLink className="w-3 h-3" />
                                <span>Mở liên kết tham chiếu</span>
                              </a>
                            ) : (
                              <button
                                onClick={() => handleOpenEvidence(ev)}
                                className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 underline"
                              >
                                <FileCode className="w-3 h-3" />
                                <span>Xem file raw trong IDE</span>
                              </button>
                            )}
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
        )}
        </div>
      )}

      {/* ==================== SUB-TAB 2: VULNERABILITY INTEL & CHECKER ==================== */}
      {activeSubTab === "checker" && (
        <div className="flex-1 min-h-0 flex flex-col overflow-hidden bg-[#0a0d14]">
          {/* Query Bar: Bound to Active Target Scan Results */}
          <div className="p-3 border-b border-[#1e293b] bg-[#0c101c] space-y-2.5 shrink-0">
            {/* Target Status & Mode Bar */}
            <div className="flex flex-wrap items-center justify-between gap-2.5 bg-[#0e1320] px-3.5 py-2 rounded-lg border border-[#1e293b] font-sans">
              <div className="flex items-center gap-2 text-xs flex-wrap">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="text-zinc-400 font-medium">Mục tiêu Recon:</span>
                <span className="text-emerald-300 font-mono font-bold bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/60 flex items-center gap-1 shadow-sm">
                  <Radio className="w-3 h-3 text-emerald-400" />
                  <span>{activeTarget ? (activeTarget.name || activeTarget.normalized_value) : "Chưa chọn mục tiêu"}</span>
                </span>
                <span className="text-zinc-400 text-xs flex items-center gap-1 bg-[#0a0d14] px-2 py-0.5 rounded border border-[#1e293b]">
                  <Layers className="w-3 h-3 text-cyan-400" />
                  <span>Bám sát Recon: <strong className="text-cyan-300 font-mono">{discoveredServices.length}</strong> dịch vụ scan</span>
                </span>
              </div>

              {/* Mode Selector & Main Batch Online Action */}
              <div className="flex items-center gap-2 flex-wrap">
                {/* Mode Selector */}
                <div className="flex items-center bg-[#070a11] border border-[#1e293b] rounded-lg p-0.5 text-xs shadow-inner">
                  <button
                    type="button"
                    onClick={() => handleChangeIntelMode("dual")}
                    className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1 whitespace-nowrap ${
                      intelMode === "dual"
                        ? "bg-[#1c1530] text-purple-300 font-semibold border border-purple-700/60 shadow-sm"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    title="Chạy đồng thời đối soát chéo Online OSV và Offline KB"
                  >
                    <Zap className="w-3 h-3 text-purple-400" />
                    <span>Đối soát Kép (Dual)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleChangeIntelMode("online")}
                    className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1 whitespace-nowrap ${
                      intelMode === "online"
                        ? "bg-[#0d2618] text-emerald-300 font-semibold border border-emerald-700/60 shadow-sm"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    title="Tra cứu trực tiếp thời gian thực từ Google OSV.dev REST API"
                  >
                    <Globe className="w-3 h-3 text-emerald-400" />
                    <span>Trực tuyến (OSV)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleChangeIntelMode("offline")}
                    className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1 whitespace-nowrap ${
                      intelMode === "offline"
                        ? "bg-[#141d33] text-zinc-200 font-semibold border border-zinc-700/60 shadow-sm"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    title="Chỉ tra cứu dữ liệu SQLite Knowledge Base nội bộ"
                  >
                    <Database className="w-3 h-3 text-zinc-400" />
                    <span>Nội bộ (KB)</span>
                  </button>
                </div>

                {/* Batch Correlate Button */}
                {discoveredServices.length > 0 && (
                  <button
                    type="button"
                    onClick={handleCorrelateTargetServicesAll}
                    disabled={batchCorrelating || servicesLoading}
                    className="flex items-center gap-1.5 bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded-lg transition-all font-semibold shadow-sm cursor-pointer shrink-0 whitespace-nowrap"
                    title="Tự động tra cứu trực tuyến toàn bộ dịch vụ đã scan được"
                  >
                    <Zap className={`w-3.5 h-3.5 text-amber-300 ${batchCorrelating ? "animate-spin" : ""}`} />
                    <span>{batchCorrelating ? "Đang tra cứu..." : `Tra cứu Online Toàn Bộ (${discoveredServices.length})`}</span>
                  </button>
                )}

                {/* Refresh Services */}
                <button
                  type="button"
                  onClick={() => fetchTargetServices()}
                  disabled={servicesLoading}
                  className="text-xs px-2.5 py-1.5 rounded-lg bg-[#121829] hover:bg-[#1a233b] border border-[#1e293b] text-zinc-400 hover:text-zinc-200 transition-all flex items-center gap-1 cursor-pointer whitespace-nowrap shadow-sm"
                  title="Tải lại danh sách dịch vụ phát hiện từ kết quả quét mục tiêu"
                >
                  <RefreshCw className={`w-3 h-3 ${servicesLoading ? "animate-spin text-cyan-400" : ""}`} />
                  <span>Đồng bộ Scan</span>
                </button>

                {/* Custom Input Toggle */}
                <button
                  type="button"
                  onClick={() => setIsManualOverride(!isManualOverride)}
                  className={`text-xs px-2.5 py-1.5 rounded-lg transition-all border flex items-center gap-1 cursor-pointer whitespace-nowrap shadow-sm ${
                    isManualOverride
                      ? "bg-amber-950/60 border-amber-600/70 text-amber-300 font-semibold"
                      : "bg-[#121829] border-[#1e293b] text-zinc-400 hover:text-zinc-200"
                  }`}
                  title="Mở form nhập kiểm tra phần mềm tùy ý ngoài danh sách recon"
                >
                  <Tag className="w-3 h-3" />
                  <span>{isManualOverride ? "Đang mở ô nhập" : "Nhập tùy chỉnh"}</span>
                </button>
              </div>
            </div>

            {/* Recon Discovered Services Surface (Cards Grid) */}
            {!isManualOverride ? (
              <div className="bg-zinc-950/70 border border-zinc-800/90 rounded-lg p-2.5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-400 font-semibold flex items-center space-x-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Dịch vụ phát hiện từ Scan & Recon:</span>
                  </span>
                  {discoveredServices.length > 0 && (
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-zinc-400 hidden sm:inline">
                        Đang chọn: <strong className="text-cyan-300">{discoveredServices[selectedServiceIdx]?.label || intelProduct}</strong>
                      </span>
                      <button
                        type="button"
                        onClick={() => setIsServicesCollapsed(!isServicesCollapsed)}
                        className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/50 hover:bg-cyan-900/60 border border-cyan-800/60 transition cursor-pointer"
                        title={isServicesCollapsed ? "Mở rộng danh sách dịch vụ" : "Thu gọn danh sách dịch vụ"}
                      >
                        <ChevronDown className={`w-3 h-3 transition-transform duration-200 ${isServicesCollapsed ? "" : "rotate-180"}`} />
                        <span>{isServicesCollapsed ? `Hiện danh sách (${discoveredServices.length})` : "Thu gọn"}</span>
                      </button>
                    </div>
                  )}
                </div>

                {isServicesCollapsed && discoveredServices.length > 0 ? (
                  <div className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-[#101524] border border-cyan-900/40 text-xs">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-zinc-400 text-[11px] shrink-0">Đang chọn:</span>
                      <span className="text-cyan-300 font-mono font-bold truncate">
                        Port {discoveredServices[selectedServiceIdx]?.port}/{discoveredServices[selectedServiceIdx]?.protocol || "tcp"} — {discoveredServices[selectedServiceIdx]?.product} {discoveredServices[selectedServiceIdx]?.version || ""}
                      </span>
                      {serviceIntelSummary[`${discoveredServices[selectedServiceIdx]?.port}:${discoveredServices[selectedServiceIdx]?.product}`.toLowerCase()] && (
                        <span className="text-red-400 font-bold font-mono text-[10px] shrink-0">
                          ({serviceIntelSummary[`${discoveredServices[selectedServiceIdx]?.port}:${discoveredServices[selectedServiceIdx]?.product}`.toLowerCase()].count} CVEs)
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => handleSelectService(Math.max(0, selectedServiceIdx - 1))}
                        disabled={selectedServiceIdx <= 0}
                        className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-[11px] text-zinc-300 cursor-pointer font-mono"
                        title="Dịch vụ trước"
                      >
                        ◀
                      </button>
                      <span className="text-[11px] text-zinc-400 font-mono px-1">
                        {selectedServiceIdx + 1}/{discoveredServices.length}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleSelectService(Math.min(discoveredServices.length - 1, selectedServiceIdx + 1))}
                        disabled={selectedServiceIdx >= discoveredServices.length - 1}
                        className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 text-[11px] text-zinc-300 cursor-pointer font-mono"
                        title="Dịch vụ kế tiếp"
                      >
                        ▶
                      </button>
                    </div>
                  </div>
                ) : discoveredServices.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-40 overflow-y-auto pr-1 scrollbar-thin">
                    {discoveredServices.map((svc, idx) => {
                      const isSelected = selectedServiceIdx === idx;
                      const key = `${svc.port}:${svc.product}`.toLowerCase();
                      const summary = serviceIntelSummary[key];

                      return (
                        <button
                          key={idx}
                          type="button"
                          onClick={() => handleSelectService(idx)}
                          className={`text-left p-2.5 rounded-lg border transition cursor-pointer flex flex-col justify-between space-y-1.5 ${
                            isSelected
                              ? "bg-gradient-to-b from-cyan-950/80 to-zinc-900 border-cyan-500 shadow-md shadow-cyan-950/60 ring-1 ring-cyan-500/50"
                              : "bg-[#18181c] hover:bg-zinc-800/80 border-zinc-800 hover:border-zinc-700"
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-mono font-bold text-zinc-400 flex items-center space-x-1">
                              {svc.port === 80 || svc.port === 443 || svc.port === 8080 || svc.port === 3000 || svc.port === 8000 ? (
                                <Globe className="w-3 h-3 text-cyan-400" />
                              ) : (
                                <Server className="w-3 h-3 text-emerald-400" />
                              )}
                              <span>Port {svc.port}/{svc.protocol || "tcp"}</span>
                            </span>
                            <span className="text-[9px] font-mono uppercase px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                              {svc.source || "recon"}
                            </span>
                          </div>

                          <div>
                            <div className="text-xs font-bold text-zinc-100 truncate">
                              {svc.product}
                            </div>
                            <div className="text-[11px] font-mono text-cyan-300 font-semibold">
                              {svc.version ? `Phiên bản: ${svc.version}` : "Phiên bản: Chưa rõ"}
                            </div>
                          </div>

                          <div className="pt-1 border-t border-zinc-800/80 flex items-center justify-between text-[10px]">
                            {summary ? (
                              <div className="flex items-center space-x-1 flex-wrap">
                                <span className={`font-bold font-mono ${summary.count > 0 ? "text-red-400" : "text-emerald-400"}`}>
                                  {summary.count} CVEs
                                </span>
                                {summary.hasKev && (
                                  <span className="px-1 py-0.2 rounded bg-rose-950 text-rose-300 font-bold border border-rose-700">
                                    KEV
                                  </span>
                                )}
                                {summary.maxCvss > 0 && (
                                  <span className="text-amber-400 font-mono">
                                    CVSS {summary.maxCvss}
                                  </span>
                                )}
                              </div>
                            ) : isSelected && intelLoading ? (
                              <span className="text-cyan-400 flex items-center space-x-1">
                                <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                                <span>Đang tra cứu online...</span>
                              </span>
                            ) : (
                              <span className="text-zinc-500 flex items-center space-x-1">
                                <Globe className="w-2.5 h-2.5" />
                                <span>Tra cứu Online</span>
                              </span>
                            )}
                            <ChevronRight className={`w-3 h-3 ${isSelected ? "text-cyan-400" : "text-zinc-600"}`} />
                          </div>
                        </button>
                      );
                    })}
                  </div>
                ) : !servicesLoading && activeTarget ? (
                  <div className="flex items-center justify-between px-3 py-2 rounded bg-amber-950/30 border border-amber-900/50 text-xs text-amber-300">
                    <div className="flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>
                        Mục tiêu <strong className="text-amber-200">{activeTarget.name}</strong> chưa có dữ liệu quét cổng/dịch vụ (Nmap/HTTPX).
                      </span>
                    </div>
                    <button
                      onClick={() => setIsManualOverride(true)}
                      className="px-2 py-0.5 rounded bg-amber-900/60 hover:bg-amber-800/80 border border-amber-700 text-amber-100 text-[11px] font-semibold transition cursor-pointer"
                    >
                      Nhập phần mềm thủ công
                    </button>
                  </div>
                ) : !servicesLoading && !activeTarget ? (
                  <div className="flex items-center justify-between px-3 py-2 rounded bg-zinc-900/60 border border-zinc-800 text-xs text-zinc-400">
                    <div className="flex items-center space-x-2">
                      <Target className="w-4 h-4 text-cyan-400 shrink-0" />
                      <span>
                        Chưa chọn mục tiêu nào trong Workspace Explorer. Bạn có thể chọn target hoặc dùng chế độ nhập thủ công để tra cứu CVE/OSV.
                      </span>
                    </div>
                    <button
                      onClick={() => setIsManualOverride(true)}
                      className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-semibold transition cursor-pointer whitespace-nowrap"
                    >
                      Nhập phần mềm thủ công
                    </button>
                  </div>
                ) : null}
              </div>
            ) : (
              /* Custom Input Override Row */
              <div className="bg-amber-950/20 border border-amber-800/60 rounded-lg p-2.5 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-amber-300 font-semibold flex items-center space-x-1.5">
                    <Tag className="w-3.5 h-3.5 text-amber-400" />
                    <span>Chế độ nhập tùy chỉnh (Tra cứu phần mềm ngoài mục tiêu recon):</span>
                  </span>
                  <button
                    onClick={() => setIsManualOverride(false)}
                    className="text-[11px] text-zinc-400 hover:text-zinc-200 flex items-center space-x-1 cursor-pointer"
                  >
                    <X className="w-3 h-3" />
                    <span>Đóng, quay lại dữ liệu Recon</span>
                  </button>
                </div>

                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex items-center space-x-2 bg-zinc-900 border border-amber-700/60 rounded px-2.5 py-1.5 text-xs flex-1 min-w-[200px]">
                    <Tag className="w-3.5 h-3.5 text-amber-400" />
                    <span className="text-zinc-400 font-medium">Phần mềm/Dịch vụ:</span>
                    <input
                      type="text"
                      value={intelProduct}
                      onChange={(e) => setIntelProduct(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleRunIntelCheck()}
                      placeholder="VD: Apache, OpenSSH, nginx, Log4j..."
                      className="bg-transparent text-zinc-100 font-semibold focus:outline-none flex-1"
                    />
                  </div>

                  <div className="flex items-center space-x-2 bg-zinc-900 border border-amber-700/60 rounded px-2.5 py-1.5 text-xs w-48">
                    <span className="text-zinc-400 font-medium">Phiên bản:</span>
                    <input
                      type="text"
                      value={intelVersion}
                      onChange={(e) => setIntelVersion(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleRunIntelCheck()}
                      placeholder="VD: 2.4.49, 8.2p1"
                      className="bg-transparent text-zinc-100 font-mono font-semibold focus:outline-none flex-1"
                    />
                  </div>

                  <button
                    onClick={() => handleRunIntelCheck()}
                    disabled={intelLoading || !intelProduct.trim()}
                    className="flex items-center space-x-1.5 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 disabled:opacity-50 text-white text-xs px-4 py-1.5 rounded transition font-semibold shadow-sm shrink-0 cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${intelLoading ? "animate-spin" : ""}`} />
                    <span>{intelLoading ? "Đang đối soát..." : "Kiểm tra Lỗ hổng"}</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Results Area */}
          <div className="flex-1 min-h-0 flex overflow-hidden">
            {/* Left Column: Candidates List */}
            <div className="w-5/12 border-r border-[#1e293b] overflow-y-auto p-2.5 space-y-2 bg-[#0a0d14]">
              <div className="flex items-center justify-between px-1 text-[11px] text-zinc-400">
                <span>
                  Đối soát Online:{" "}
                  <strong className="text-cyan-400 font-mono">
                    {discoveredServices[selectedServiceIdx]
                      ? `${discoveredServices[selectedServiceIdx].label}`
                      : intelProduct ? `${intelProduct} ${intelVersion}` : "Mục tiêu"}
                  </strong>{" "}
                  (<strong className="text-cyan-300 font-mono">{uniqueIntelResults.length}</strong> CVEs)
                </span>
                {intelSearched && (
                  <span className="text-[10px] text-zinc-500">
                    Chế độ: <span className="uppercase font-semibold text-cyan-300">{intelMode === "dual" ? "Đối soát Kép (OSV + KB)" : intelMode === "online" ? "Trực tuyến OSV" : "CSDL Nội bộ"}</span>
                  </span>
                )}
              </div>

              {intelQueryError && (
                <div className="p-3 rounded bg-red-950/40 border border-red-800/80 text-red-300 text-xs">
                  {intelQueryError}
                </div>
              )}

              {uniqueIntelResults.length === 0 && intelSearched && !intelLoading && (
                <div className="p-8 text-center text-zinc-500 text-xs space-y-2">
                  <p>Không tìm thấy lỗ hổng tương quan cho dịch vụ này.</p>
                  <p className="text-[11px] text-zinc-600">
                    Thử đổi chế độ sang <strong>Đối soát Kép (Dual)</strong> hoặc kiểm tra lại chuỗi phiên bản chính xác.
                  </p>
                </div>
              )}

              {!intelSearched && (
                <div className="p-8 text-center text-zinc-500 text-xs space-y-3">
                  <ShieldCheck className="w-8 h-8 text-cyan-500/40 mx-auto" />
                  <div>
                    <p className="font-semibold text-zinc-300">Tra cứu Tình báo Lỗ hổng Trực tiếp</p>
                    <p className="text-[11px] text-zinc-500 mt-1">
                      Chọn dịch vụ phát hiện bên trên hoặc nhập thông tin phần mềm để đối soát dữ liệu CVE & Exploit thời gian thực.
                    </p>
                  </div>
                </div>
              )}

              {uniqueIntelResults.map((c, idx) => (
                <div
                  key={idx}
                  onClick={() => setSelectedIntelCve(c)}
                  className={`p-3 rounded border transition cursor-pointer flex flex-col space-y-2 ${
                    selectedIntelCve?.cve_id === c.cve_id
                      ? "bg-zinc-900 border-cyan-500/80 shadow-sm"
                      : "bg-[#18181c] border-zinc-800 hover:border-zinc-700"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                      <span className="font-mono text-cyan-400 font-bold text-xs">
                        {c.cve_id}
                      </span>
                      {getSeverityBadge(c.cvss_severity || "HIGH")}
                      {getOriginBadge(c.origin, c.source)}
                      {c.is_cisa_kev && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-950/90 border border-red-500 text-red-300 font-mono animate-pulse">
                          🔥 CISA KEV
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-xs font-bold text-orange-400">
                      CVSS {c.cvss_score?.toFixed(1) || "7.5"}
                    </span>
                  </div>

                  <div className="text-zinc-300 text-xs line-clamp-2 leading-relaxed">
                    {c.description}
                  </div>

                  <div className="flex items-center justify-between pt-1 border-t border-zinc-800/60 text-[10px] text-zinc-500">
                    <span className="truncate max-w-[200px] text-zinc-400 font-mono">
                      {c.source || "Threat Intel"}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleAddToTargetFindings(c);
                      }}
                      className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 hover:text-cyan-200 transition font-medium flex items-center space-x-1"
                    >
                      {addedCveStatus[c.cve_id] === "added" ? (
                        <>
                          <Check className="w-2.5 h-2.5 text-emerald-400" />
                          <span className="text-emerald-400 font-semibold">Đã thêm</span>
                        </>
                      ) : (
                        <>
                          <Plus className="w-2.5 h-2.5" />
                          <span>+ Thêm vào Findings</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Right Column: Detailed Inspector with All Official Links */}
            <div className="w-7/12 overflow-y-auto p-4 bg-[#121214]">
              {selectedIntelCve ? (
                <div className="space-y-4">
                  {/* Top Details & Origin */}
                  <div className="space-y-2 border-b border-zinc-800 pb-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-base font-bold text-cyan-300">
                          {selectedIntelCve.cve_id}
                        </span>
                        {getSeverityBadge(selectedIntelCve.cvss_severity || "HIGH")}
                        {getOriginBadge(selectedIntelCve.origin, selectedIntelCve.source)}
                      </div>
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleAddToTargetFindings(selectedIntelCve)}
                          className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition flex items-center space-x-1.5 shadow-sm"
                        >
                          {addedCveStatus[selectedIntelCve.cve_id] === "added" ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-300" />
                              <span>Đã thêm vào Findings của Mục tiêu</span>
                            </>
                          ) : (
                            <>
                              <Plus className="w-3.5 h-3.5" />
                              <span>+ Thêm vào Findings của Mục tiêu</span>
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    <div className="text-xs text-zinc-400 font-mono">
                      Nguồn dữ liệu xác minh:{" "}
                      <strong className="text-zinc-200">
                        {selectedIntelCve.source || "Authoritative Vulnerability Intel"}
                      </strong>
                    </div>
                  </div>

                  {/* Official Authoritative Links Cards */}
                  <div className="bg-gradient-to-r from-zinc-900 to-[#181824] border border-cyan-950 rounded-lg p-3 space-y-2.5">
                    <div className="text-xs font-bold text-zinc-200 uppercase tracking-wider flex items-center space-x-1.5">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span>Liên kết tra cứu chính thức (Authoritative Links)</span>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      {/* NIST NVD Link */}
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${selectedIntelCve.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 hover:border-cyan-700/80 transition flex items-center justify-between group"
                      >
                        <div className="flex items-center space-x-2">
                          <div className="w-6 h-6 rounded bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-[10px] font-bold">
                            NVD
                          </div>
                          <div className="text-left">
                            <div className="text-xs font-semibold text-zinc-200 group-hover:text-cyan-300">
                              NIST NVD
                            </div>
                            <div className="text-[10px] text-zinc-500">
                              Hồ sơ phân tích chính phủ Mỹ
                            </div>
                          </div>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-cyan-400" />
                      </a>

                      {/* Google OSV.dev Link */}
                      <a
                        href={`https://osv.dev/vulnerability/${selectedIntelCve.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 hover:border-emerald-700/80 transition flex items-center justify-between group"
                      >
                        <div className="flex items-center space-x-2">
                          <div className="w-6 h-6 rounded bg-emerald-950 border border-emerald-800 flex items-center justify-center text-emerald-400 text-[10px] font-bold">
                            OSV
                          </div>
                          <div className="text-left">
                            <div className="text-xs font-semibold text-zinc-200 group-hover:text-emerald-300">
                              Google OSV.dev
                            </div>
                            <div className="text-[10px] text-zinc-500">
                              Open Source Vulnerability API
                            </div>
                          </div>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-emerald-400" />
                      </a>

                      {/* Exploit-DB Link */}
                      <a
                        href={`https://www.exploit-db.com/search?cve=${selectedIntelCve.cve_id.replace("CVE-", "")}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 hover:border-purple-700/80 transition flex items-center justify-between group"
                      >
                        <div className="flex items-center space-x-2">
                          <div className="w-6 h-6 rounded bg-purple-950 border border-purple-800 flex items-center justify-center text-purple-400 text-[10px] font-bold">
                            EDB
                          </div>
                          <div className="text-left">
                            <div className="text-xs font-semibold text-zinc-200 group-hover:text-purple-300">
                              Exploit-DB PoC
                            </div>
                            <div className="text-[10px] text-zinc-500">
                              Khai thác thực tế & Proof of Concept
                            </div>
                          </div>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-purple-400" />
                      </a>

                      {/* MITRE CVE Link */}
                      <a
                        href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedIntelCve.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="p-2 rounded bg-zinc-950/80 hover:bg-zinc-900 border border-zinc-800 hover:border-zinc-700 transition flex items-center justify-between group"
                      >
                        <div className="flex items-center space-x-2">
                          <div className="w-6 h-6 rounded bg-zinc-900 border border-zinc-700 flex items-center justify-center text-zinc-400 text-[10px] font-bold">
                            MIT
                          </div>
                          <div className="text-left">
                            <div className="text-xs font-semibold text-zinc-200 group-hover:text-zinc-100">
                              MITRE CVE
                            </div>
                            <div className="text-[10px] text-zinc-500">
                              Định danh bảo mật quốc tế
                            </div>
                          </div>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-zinc-300" />
                      </a>
                    </div>
                  </div>

                  {/* Vulnerability Metrics */}
                  <div className="grid grid-cols-4 gap-2">
                    <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-center">
                      <div className="text-[10px] uppercase text-zinc-500 font-semibold">CVSS v3.1</div>
                      <div className="text-sm font-bold text-orange-400 font-mono mt-0.5">
                        {selectedIntelCve.cvss_score?.toFixed(1) || "7.5"}
                      </div>
                    </div>
                    <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-center">
                      <div className="text-[10px] uppercase text-zinc-500 font-semibold">CVSS v4.0</div>
                      <div className="text-sm font-bold text-cyan-400 font-mono mt-0.5">
                        {selectedIntelCve.cvss_v4_score?.toFixed(1) || "—"}
                      </div>
                    </div>
                    <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-center">
                      <div className="text-[10px] uppercase text-zinc-500 font-semibold">Xác suất EPSS</div>
                      <div className="text-sm font-bold text-purple-400 font-mono mt-0.5">
                        {selectedIntelCve.epss_score !== undefined
                          ? `${(selectedIntelCve.epss_score * 100).toFixed(1)}%`
                          : "—"}
                      </div>
                    </div>
                    <div className="bg-zinc-900 border border-zinc-800 rounded p-2 text-center">
                      <div className="text-[10px] uppercase text-zinc-500 font-semibold">CISA KEV</div>
                      <div className="text-xs font-bold text-red-400 font-mono mt-0.5">
                        {selectedIntelCve.is_cisa_kev ? "🔥 Đang khai thác" : "Chưa ghi nhận"}
                      </div>
                    </div>
                  </div>

                  {/* Description */}
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                      Mô tả Lỗ hổng
                    </div>
                    <div className="text-xs leading-relaxed text-zinc-200 bg-zinc-900/80 p-3 rounded border border-zinc-800 whitespace-pre-wrap">
                      {selectedIntelCve.description}
                    </div>
                  </div>

                  {/* References with Clickable External Links */}
                  {selectedIntelCve.references && selectedIntelCve.references.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center justify-between">
                        <span>Tài liệu tham chiếu & Advisory ({selectedIntelCve.references.length})</span>
                      </div>
                      <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
                        {selectedIntelCve.references.map((refUrl, rIdx) => (
                          <a
                            key={rIdx}
                            href={refUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1.5 rounded bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono truncate flex items-center space-x-1.5 transition group"
                          >
                            <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-cyan-400 shrink-0" />
                            <span className="truncate">{refUrl}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Quick Safe Read-Only Check Suggestion */}
                  <div className="bg-[#0b1017] border border-cyan-900/50 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-cyan-400 flex items-center space-x-1.5">
                        <Terminal className="w-3.5 h-3.5" />
                        <span>Lệnh kiểm tra thụ động an toàn (Safe Read-Only Probe)</span>
                      </span>
                      <button
                        onClick={() => {
                          const probe = `curl -s -I http://${activeTarget?.host || "target"}/ | grep -i "server:"`;
                          navigator.clipboard.writeText(probe);
                          setCopiedProbe(true);
                          setTimeout(() => setCopiedProbe(false), 2000);
                        }}
                        className="px-2 py-0.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] flex items-center space-x-1"
                      >
                        {copiedProbe ? (
                          <>
                            <Check className="w-2.5 h-2.5 text-emerald-400" />
                            <span className="text-emerald-400">Đã chép</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-2.5 h-2.5" />
                            <span>Sao chép lệnh</span>
                          </>
                        )}
                      </button>
                    </div>
                    <code className="block bg-black/60 p-2 rounded text-[11px] font-mono text-cyan-300">
                      curl -s -I http://{activeTarget?.host || "target"}/ | grep -i "server:"
                    </code>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-zinc-500 text-xs">
                  Chọn một CVE ở cột bên trái để xem đầy đủ các liên kết chính thức (NVD, OSV, Exploit-DB, MITRE) và chi tiết phân tích.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
