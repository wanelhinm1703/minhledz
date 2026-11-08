import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  Shield,
  Server,
  Network,
  Layers,
  Bug,
  AlertTriangle,
  FileCheck,
  RefreshCw,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  ShieldAlert,
  Target,
  Filter,
  CheckCircle2,
  ExternalLink,
  Code2,
  Play,
  Flame,
  GitBranch,
  Skull,
  Zap,
  ShieldCheck,
  ArrowRight,
  TrendingUp,
  Crosshair,
  ChevronRight,
  Sparkles,
  PanelRightClose,
  PanelRightOpen,
  FileDown,
  Download,
  Pause,
  SkipForward,
  RotateCcw,
  ChevronDown,
  ChevronLeft,
  LayoutGrid,
  Terminal,
  Copy,
  Check,
  Search,
  X,
  ListChecks,
  FileText,
  Activity,
  Info,
  Lock,
  Unlock,
  GitFork,
  Split,
} from "lucide-react";

import { useWorkspaceStore } from "../../store/workspaceStore";

export interface GraphNode {
  id: string;
  target_id: string;
  type:
  | "target"
  | "port"
  | "service"
  | "technology"
  | "vulnerability"
  | "finding"
  | "impact"
  | "lateral_movement";
  label: string;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "SAFE";
  properties: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface GraphEdge {
  id: string;
  target_id: string;
  source: string;
  target: string;
  relation: string;
  label?: string;
  properties: Record<string, any>;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  by_type: Record<string, number>;
  by_risk: Record<string, number>;
  critical_path_count: number;
}

export interface AttackPathStep {
  step_number: number;
  phase: string;
  node_id: string;
  title?: string;
  node_label?: string;
  node_type?: string;
  description: string;
  technical_detail?: string | null;
  mitre_tactic?: string;
  mitre_technique?: string;
  annotation?: string | null;
  related_cves?: string[];
}

export interface AttackPath {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss_score?: number;
  cve_id?: string;
  target_id?: string;
  steps?: AttackPathStep[];
  mitigation_steps?: string[];
  remediation_summary?: string;
  attacker_goal?: string;
  is_cisa_kev?: boolean;
  epss_score?: number;
  verification_plan_id?: string;
  is_severed?: boolean;
  severed_by_node?: string | null;
  verification_status?: string;
  explainability?: any;
  related_cves?: string[];
  findings_count?: number;
  annotation?: string;
  service_name?: string;
  port_name?: string;
}

export interface ChainVerificationStep {
  step_number: number;
  phase: string;
  node_id: string;
  node_label: string;
  name: string;
  description: string;
  command: string;
  is_safe_readonly: boolean;
  expected_evidence: string;
  remediation_check?: string;
  break_point_candidate: boolean;
  ai_assessment?: string;
  ai_deduction?: string;
  actual_result?: string;
  evidence_found?: string;
  status?: string;
  timestamp?: string;
}

export interface ChainVerificationPlan {
  chain_id: string;
  target_id: string;
  chain_title: string;
  severity: string;
  attacker_goal: string;
  rationale: string;
  safety_guarantee: string;
  steps: ChainVerificationStep[];
  break_point_recommendation: string;
  recommended_mitigations: string[];
  created_at: string;
}

export interface NodePosition {

  x: number;
  y: number;
}

const RISK_COLORS: Record<
  string,
  { bg: string; border: string; text: string; glow: string; stroke: string }
> = {
  CRITICAL: {
    bg: "rgba(239, 68, 68, 0.18)",
    border: "#ef4444",
    text: "#fca5a5",
    glow: "0 0 15px rgba(239, 68, 68, 0.6)",
    stroke: "#ef4444",
  },
  HIGH: {
    bg: "rgba(249, 115, 22, 0.18)",
    border: "#f97316",
    text: "#fdba74",
    glow: "0 0 12px rgba(249, 115, 22, 0.5)",
    stroke: "#f97316",
  },
  MEDIUM: {
    bg: "rgba(234, 179, 8, 0.18)",
    border: "#eab308",
    text: "#fde047",
    glow: "0 0 10px rgba(234, 179, 8, 0.4)",
    stroke: "#eab308",
  },
  LOW: {
    bg: "rgba(59, 130, 246, 0.18)",
    border: "#3b82f6",
    text: "#93c5fd",
    glow: "0 0 8px rgba(59, 130, 246, 0.3)",
    stroke: "#3b82f6",
  },
  INFO: {
    bg: "rgba(6, 182, 212, 0.15)",
    border: "#06b6d4",
    text: "#67e8f9",
    glow: "0 0 8px rgba(6, 182, 212, 0.3)",
    stroke: "#06b6d4",
  },
  SAFE: {
    bg: "rgba(16, 185, 129, 0.15)",
    border: "#10b981",
    text: "#6ee7b7",
    glow: "0 0 8px rgba(16, 185, 129, 0.3)",
    stroke: "#10b981",
  },
};

const formatEdgeLabel = (label: string): string => {
  const l = (label || "").toLowerCase();
  if (l.includes("open port") || l.includes("cổng mở")) return "CỔNG MỞ";
  if (l.includes("service") || l.includes("dịch vụ")) return "DỊCH VỤ";
  if (l.includes("vulnerable") || l.includes("lỗ hổng")) return "LỖ HỔNG";
  if (l.includes("evidence") || l.includes("bằng chứng")) return "BẰNG CHỨNG";
  if (l.includes("leads to") || l.includes("impact") || l.includes("hệ quả")) return "TÁC ĐỘNG";
  if (l.includes("pivot") || l.includes("leo thang")) return "LEO THANG";
  return label.toUpperCase();
};

const formatNodeType = (type: string): string => {
  switch (type?.toLowerCase()) {
    case "target": return "Mục tiêu (Target)";
    case "port": return "Cổng mạng (Port)";
    case "service": return "Dịch vụ (Service)";
    case "technology": return "Công nghệ / Framework";
    case "vulnerability": return "Lỗ hổng (Vulnerability)";
    case "finding": return "Phát hiện (Finding)";
    case "impact": return "Tác động (Impact)";
    case "lateral_movement": return "Leo thang / Dịch chuyển ngang";
    default: return type ? `${type.toUpperCase()} Entity` : "Thực thể";
  }
};

const getPropertyLabel = (key: string): string => {
  const map: Record<string, string> = {
    finding_id: "Mã phát hiện (Finding ID)",
    title: "Tiêu đề",
    description: "Mô tả kỹ thuật",
    remediation: "Biện pháp khắc phục (Remediation)",
    cvss_score: "Điểm CVSS v3.1",
    cvss_v4_score: "Điểm CVSS v4.0",
    cvss_severity: "Mức độ rủi ro",
    epss_score: "Xác suất khai thác EPSS",
    epss_percentile: "Phân vị EPSS Percentile",
    is_cisa_kev: "Trạng thái CISA KEV",
    affected_asset: "Mục tiêu / Thực thể ảnh hưởng",
    affected_target: "Mục tiêu ảnh hưởng",
    port: "Cổng dịch vụ (Port)",
    service: "Dịch vụ & Giao thức",
    protocol: "Giao thức mạng",
    product: "Phần mềm / Dịch vụ",
    version: "Phiên bản",
    cve_id: "Mã lỗ hổng CVE",
    cwe_id: "Phân loại CWE",
    confidence: "Độ tin cậy xác minh",
    evidence_count: "Số lượng chứng cứ thực nghiệm",
    remediation_effort: "Mức độ phức tạp khắc phục",
    status: "Trạng thái",
    host: "Địa chỉ máy chủ (Host)",
    ip: "Địa chỉ IP",
    os: "Hệ điều hành",
  };
  return map[key] || key.replace(/_/g, " ").toUpperCase();
};

const renderRichTextWithLinks = (text: string): React.ReactNode => {
  if (!text) return null;
  const str = String(text);
  const regex = /(https?:\/\/[^\s<>]+)|(\bCVE-\d{4}-\d{4,7}\b)/gi;
  const parts: React.ReactNode[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(str)) !== null) {
    if (match.index > lastIndex) {
      parts.push(str.slice(lastIndex, match.index));
    }

    const matched = match[0];
    if (matched.startsWith("http://") || matched.startsWith("https://")) {
      let url = matched;
      let trailing = "";
      while (url && /[.,;:!?)]$/.test(url)) {
        if (url.endsWith(")") && (url.match(/\(/g) || []).length >= (url.match(/\)/g) || []).length) {
          break;
        }
        trailing = url.slice(-1) + trailing;
        url = url.slice(0, -1);
      }

      parts.push(
        <a
          key={`url-${match.index}`}
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="text-cyan-400 hover:text-cyan-200 underline font-semibold inline-flex items-center gap-0.5 bg-cyan-950/60 hover:bg-cyan-900/80 px-1.5 py-0.5 rounded border border-cyan-700/70 transition cursor-pointer break-all"
          title={`Chuyển đến nguồn: ${url}`}
        >
          <span>{url}</span>
          <ExternalLink className="w-3 h-3 text-cyan-400 inline shrink-0 ml-0.5" />
        </a>
      );
      if (trailing) {
        parts.push(trailing);
      }
    } else if (/^CVE-\d{4}-\d{4,7}$/i.test(matched)) {
      const cveUpper = matched.toUpperCase();
      parts.push(
        <a
          key={`cve-${match.index}`}
          href={`https://nvd.nist.gov/vuln/detail/${cveUpper}`}
          target="_blank"
          rel="noopener noreferrer"
          onClick={(e) => e.stopPropagation()}
          className="text-amber-300 hover:text-amber-100 font-mono font-bold inline-flex items-center gap-0.5 bg-amber-950/60 hover:bg-amber-900/80 px-1.5 py-0.5 rounded border border-amber-700/80 transition cursor-pointer text-[11px]"
          title={`Xem chi tiết lỗ hổng ${cveUpper} trên NIST NVD`}
        >
          <span>{cveUpper}</span>
          <ExternalLink className="w-2.5 h-2.5 text-amber-400 inline shrink-0" />
        </a>
      );
    }

    lastIndex = regex.lastIndex;
  }

  if (lastIndex < str.length) {
    parts.push(str.slice(lastIndex));
  }

  return parts;
};

export const TopologyViewer: React.FC = () => {
  const { activeTarget, setActiveView, appendTerminalLog } = useWorkspaceStore();

  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [syncing, setSyncing] = useState<boolean>(false);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterRisk, setFilterRisk] = useState<string>("VULNERABLE");
  const [chainPlan, setChainPlan] = useState<ChainVerificationPlan | null>(null);
  const [loadingChainPlan, setLoadingChainPlan] = useState<boolean>(false);
  const [executingChainStep, setExecutingChainStep] = useState<number | null>(null);
  const [chainStepOutputs, setChainStepOutputs] = useState<
    Record<
      number,
      {
        output: string;
        isVuln: boolean;
        isBroken: boolean;
        evidence: string;
        ai_assessment?: string;
        ai_deduction?: string;
        timestamp?: string;
      }
    >
  >({});
  const [copiedStepCmd, setCopiedStepCmd] = useState<number | null>(null);

  // Evidence-Driven Attack Plan & Subtab State
  const [attackPlan, setAttackPlan] = useState<any | null>(null);
  const [loadingAttackPlan, setLoadingAttackPlan] = useState<boolean>(false);
  const [attackChainSubTab, setAttackChainSubTab] = useState<
    "overview" | "plan" | "graph" | "verification"
  >("overview");
  const [verifyFilter, setVerifyFilter] = useState<string>("all");
  const [evidenceFilter, setEvidenceFilter] = useState<string>("all");
  const [findingFilter, setFindingFilter] = useState<string>("all");
  const [expandedEvidenceIdx, setExpandedEvidenceIdx] = useState<number | null>(null);
  const [isSeveringNode, setIsSeveringNode] = useState<string | null>(null);
  const [isRescanning, setIsRescanning] = useState<boolean>(false);


  const selectedNodeReferences = useMemo(() => {
    if (!selectedNode) return [];
    const refs: Array<{ label: string; url: string; badge: string; badgeBg?: string; badgeColor?: string }> = [];
    const seenUrls = new Set<string>();

    const addRef = (label: string, url: string, badge: string, badgeBg?: string, badgeColor?: string) => {
      let cleanUrl = url.trim();
      while (cleanUrl && /[.,;:!?)]$/.test(cleanUrl)) {
        cleanUrl = cleanUrl.slice(0, -1);
      }
      if (cleanUrl && !seenUrls.has(cleanUrl)) {
        seenUrls.add(cleanUrl);
        refs.push({ label, url: cleanUrl, badge, badgeBg, badgeColor });
      }
    };

    // 1. Direct CVE
    const cveId = selectedNode.properties?.cve_id || (selectedNode.label?.startsWith("CVE-") ? selectedNode.label : null);
    if (cveId && /^CVE-\d{4}-\d+/i.test(cveId)) {
      const cveUpper = cveId.toUpperCase();
      addRef(
        `NIST National Vulnerability Database (${cveUpper})`,
        `https://nvd.nist.gov/vuln/detail/${cveUpper}`,
        "NIST NVD",
        "rgba(245, 158, 11, 0.2)",
        "#fbbf24"
      );
      addRef(
        `MITRE CVE Dictionary (${cveUpper})`,
        `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveUpper}`,
        "MITRE",
        "rgba(59, 130, 246, 0.2)",
        "#60a5fa"
      );
    }

    // 2. Scan properties for URLs & additional CVEs
    const props = selectedNode.properties || {};
    for (const [, v] of Object.entries(props)) {
      if (typeof v === "string") {
        const urlMatches = v.match(/https?:\/\/[^\s<>]+/gi);
        if (urlMatches) {
          for (const u of urlMatches) {
            try {
              const parsed = new URL(u);
              const domain = parsed.hostname.replace(/^www\./, "");
              addRef(`Tài liệu tham khảo (${domain})`, u, domain.toUpperCase(), "rgba(6, 182, 212, 0.2)", "#22d3ee");
            } catch {
              addRef("Tài liệu tham khảo", u, "LINK", "rgba(6, 182, 212, 0.2)", "#22d3ee");
            }
          }
        }
        const cveMatches = v.match(/\bCVE-\d{4}-\d{4,7}\b/gi);
        if (cveMatches) {
          for (const c of cveMatches) {
            const cUpper = c.toUpperCase();
            addRef(
              `NIST NVD (${cUpper})`,
              `https://nvd.nist.gov/vuln/detail/${cUpper}`,
              "NVD",
              "rgba(245, 158, 11, 0.2)",
              "#fbbf24"
            );
          }
        }
      } else if (Array.isArray(v)) {
        for (const item of v) {
          if (typeof item === "string" && item.startsWith("http")) {
            try {
              const domain = new URL(item).hostname.replace(/^www\./, "");
              addRef(`Nguồn liên kết (${domain})`, item, domain.toUpperCase());
            } catch {
              addRef("Nguồn liên kết", item, "LINK");
            }
          }
        }
      }
    }

    return refs;
  }, [selectedNode]);

  // Mode: "topology" (full attack surface) vs "attack_path" (DAG chain kill paths)
  const [viewMode, setViewMode] = useState<"topology" | "attack_path">("topology");
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"inspector" | "attack_chain">("inspector");
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(true);
  const [drawerWidth, setDrawerWidth] = useState<number>(() => {
    const saved = localStorage.getItem("topology_drawer_width");
    return saved ? Math.max(380, Math.min(850, parseInt(saved, 10))) : 440;
  });
  const [isWideMode, setIsWideMode] = useState<boolean>(false);
  const [isResizingDrawer, setIsResizingDrawer] = useState<boolean>(false);
  const canvasContainerRef = useRef<HTMLDivElement | null>(null);

  const startResizingDrawer = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsResizingDrawer(true);
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizingDrawer) return;
      const containerRect = canvasContainerRef.current?.getBoundingClientRect();
      if (!containerRect) return;
      const newWidth = containerRect.right - e.clientX;
      if (newWidth >= 360 && newWidth <= Math.min(850, containerRect.width - 220)) {
        setDrawerWidth(newWidth);
        localStorage.setItem("topology_drawer_width", String(newWidth));
      }
    };
    const handleMouseUp = () => {
      setIsResizingDrawer(false);
    };
    if (isResizingDrawer) {
      window.addEventListener("mousemove", handleMouseMove);
      window.addEventListener("mouseup", handleMouseUp);
    }
    return () => {
      window.removeEventListener("mousemove", handleMouseMove);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [isResizingDrawer]);

  // Attack Path Step-by-Step Walkthrough Simulation
  const [walkthroughStep, setWalkthroughStep] = useState<number | null>(null);
  const [isPlayingWalkthrough, setIsPlayingWalkthrough] = useState<boolean>(false);
  const [actionProposedNotice, setActionProposedNotice] = useState<string | null>(null);

  // Canvas Pan & Zoom
  const [scale, setScale] = useState<number>(0.9);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 40, y: 40 });
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const [startPan, setStartPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);

  // Custom Dragging for Nodes
  const [positions, setPositions] = useState<Record<string, NodePosition>>({});
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const dragStartRef = useRef<{ clientX: number; clientY: number } | null>(null);
  const dragOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const isDragMovedRef = useRef<boolean>(false);

  // Filter & Entity Selector Dropdown state
  const [isFilterOpen, setIsFilterOpen] = useState<boolean>(false);
  const [selectedEntityId, setSelectedEntityId] = useState<string | null>(null);
  const [filterTab, setFilterTab] = useState<"vulns" | "impacts" | "pivots" | "risk" | "all">("vulns");
  const [filterSearch, setFilterSearch] = useState<string>("");
  const filterDropdownRef = useRef<HTMLDivElement | null>(null);

  // Attack Path Dropdown state
  const [isPathDropdownOpen, setIsPathDropdownOpen] = useState<boolean>(false);
  const pathDropdownRef = useRef<HTMLDivElement | null>(null);

  // Toolbar drag-to-scroll
  const toolbarRef = useRef<HTMLDivElement | null>(null);
  const isToolbarDraggingRef = useRef<boolean>(false);
  const toolbarStartXRef = useRef<number>(0);
  const toolbarScrollLeftRef = useRef<number>(0);

  const svgRef = useRef<SVGSVGElement | null>(null);

  const targetId = activeTarget?.target_id || "";

  const fetchTopology = async (isSync = false) => {
    if (!targetId) {
      setNodes([]);
      setEdges([]);
      setStats(null);
      setAttackPaths([]);
      setSelectedPathId(null);
      setLoading(false);
      setSyncing(false);
      return;
    }
    if (isSync) setSyncing(true);
    else setLoading(true);

    try {
      const url = isSync
        ? `/api/topology/${encodeURIComponent(targetId)}/sync`
        : `/api/topology/${encodeURIComponent(targetId)}`;
      const res = await fetch(url, { method: isSync ? "POST" : "GET" });
      if (!res.ok) throw new Error("Failed to fetch topology");
      const data = await res.json();

      setNodes(data.nodes || []);
      setEdges(data.edges || []);
      setStats(data.stats || null);
      const paths: AttackPath[] = data.attack_paths || [];
      setAttackPaths(paths);

      if (paths.length > 0 && !selectedPathId) {
        setSelectedPathId(paths[0].id);
      } else if (paths.length === 0) {
        setSelectedPathId(null);
      }

      // Initialize layout positions with crossing minimization
      calculateLayout(data.nodes || [], data.edges || []);
      if (isSync) {
        appendTerminalLog(
          `[*] Attack Surface Topology synced for ${targetId}: ${data.nodes?.length || 0} nodes, ${paths.length} attack path(s) detected.`
        );
      }
    } catch (err: any) {
      appendTerminalLog(`[!] Error loading topology: ${err.message}`);
    } finally {
      setLoading(false);
      setSyncing(false);
    }
  };

  useEffect(() => {
    fetchTopology();
  }, [targetId]);

  const handleExportSvg = () => {
    if (!svgRef.current || !targetId) return;
    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const blob = new Blob([svgData], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${targetId.replace(/[:\/]/g, "-")}_attack_topology.svg`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    appendTerminalLog(`[*] Exported attack surface topology to SVG for ${targetId}`);
  };

  const cleanTargetId = targetId ? targetId.replace(/^target-/, "") : "";

  const handleProposeSafeAction = async (step: AttackPathStep) => {
    try {
      const probeCmd = step.technical_detail || `curl -s -I http://${cleanTargetId}/`;
      const res = await fetch("/api/action/propose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: cleanTargetId,
          name: `Verify ${step.phase}: ${step.node_label || step.title || "Step"}`,
          command: probeCmd,
          description: step.description,
          expected_evidence: "HTTP Response / Service banner match",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setActionProposedNotice(`Action proposed: ${data.action_id} - Awaiting approval`);
        appendTerminalLog(`[+] Proposed safe verification action ${data.action_id}: '${probeCmd}'`);
        setTimeout(() => setActionProposedNotice(null), 5000);
      }
    } catch (e: any) {
      appendTerminalLog(`[!] Failed to propose action: ${e.message}`);
    }
  };

  // Compute Hierarchical Columns Layout with Crossing Minimization (Sugiyama Barycentric Heuristic)
  const calculateLayout = (nodeList: GraphNode[], edgeList?: GraphEdge[]) => {
    if (!nodeList || nodeList.length === 0) return;

    const layerTarget: GraphNode[] = [];
    const layerPorts: GraphNode[] = [];
    const layerServices: GraphNode[] = [];
    const layerVulns: GraphNode[] = [];
    const layerFindings: GraphNode[] = [];
    const layerImpacts: GraphNode[] = [];
    const layerLateral: GraphNode[] = [];

    nodeList.forEach((n) => {
      if (n.type === "target") layerTarget.push(n);
      else if (n.type === "port") layerPorts.push(n);
      else if (n.type === "service" || n.type === "technology") layerServices.push(n);
      else if (n.type === "vulnerability") layerVulns.push(n);
      else if (n.type === "impact") layerImpacts.push(n);
      else if (n.type === "lateral_movement") layerLateral.push(n);
      else layerFindings.push(n);
    });

    // Retain non-empty layers in logical attack chain order
    const rawLayers = [
      layerTarget,
      layerPorts,
      layerServices,
      layerVulns,
      layerFindings,
      layerImpacts,
      layerLateral,
    ];
    const layers = rawLayers.filter((l) => l.length > 0);
    if (layers.length === 0) return;

    const currentEdges = edgeList && edgeList.length > 0 ? edgeList : edges;

    // Adjacency connections
    const adjMap = new Map<string, Set<string>>();
    currentEdges.forEach((e) => {
      if (!adjMap.has(e.source)) adjMap.set(e.source, new Set());
      if (!adjMap.has(e.target)) adjMap.set(e.target, new Set());
      adjMap.get(e.source)!.add(e.target);
      adjMap.get(e.target)!.add(e.source);
    });

    // Map each node id to current layer index and rank within that layer
    const nodeLayerMap = new Map<string, number>();
    const nodeRankMap = new Map<string, number>();

    const updateRanks = () => {
      layers.forEach((layer, lIdx) => {
        layer.forEach((n, rIdx) => {
          nodeLayerMap.set(n.id, lIdx);
          nodeRankMap.set(n.id, rIdx);
        });
      });
    };

    updateRanks();

    // Helper: calculate barycenter (average normalized vertical rank of connected neighbors)
    const getBarycenter = (nodeId: string, currentLayerIdx: number, direction: -1 | 1): number => {
      const neighbors = adjMap.get(nodeId);
      const currentLayer = layers[currentLayerIdx];
      const fallback = (nodeRankMap.get(nodeId) ?? 0) / Math.max(1, currentLayer.length - 1);

      if (!neighbors || neighbors.size === 0) return fallback;

      const targetNeighbors: string[] = [];
      neighbors.forEach((nbId) => {
        const nbLayer = nodeLayerMap.get(nbId);
        if (nbLayer !== undefined) {
          if (direction === -1 && nbLayer < currentLayerIdx) {
            targetNeighbors.push(nbId);
          } else if (direction === 1 && nbLayer > currentLayerIdx) {
            targetNeighbors.push(nbId);
          }
        }
      });

      // If no neighbors found in primary direction, check opposite direction
      if (targetNeighbors.length === 0) {
        neighbors.forEach((nbId) => {
          const nbLayer = nodeLayerMap.get(nbId);
          if (nbLayer !== undefined && nbLayer !== currentLayerIdx) {
            targetNeighbors.push(nbId);
          }
        });
      }

      if (targetNeighbors.length === 0) return fallback;

      let sumNorm = 0;
      targetNeighbors.forEach((nbId) => {
        const nbLayer = nodeLayerMap.get(nbId)!;
        const nbRank = nodeRankMap.get(nbId) ?? 0;
        const layerCount = layers[nbLayer]?.length || 1;
        const norm = layerCount > 1 ? nbRank / (layerCount - 1) : 0.5;
        sumNorm += norm;
      });

      return sumNorm / targetNeighbors.length;
    };

    // Multi-pass Sugiyama barycenter sorting to untangle crossing edges
    for (let iter = 0; iter < 4; iter++) {
      // Forward pass (left to right)
      for (let c = 1; c < layers.length; c++) {
        const currentLayer = layers[c];
        currentLayer.sort((a, b) => {
          const baryA = getBarycenter(a.id, c, -1);
          const baryB = getBarycenter(b.id, c, -1);
          if (Math.abs(baryA - baryB) > 0.0001) {
            return baryA - baryB;
          }
          return (nodeRankMap.get(a.id) ?? 0) - (nodeRankMap.get(b.id) ?? 0);
        });
        currentLayer.forEach((n, rIdx) => nodeRankMap.set(n.id, rIdx));
      }

      // Backward pass (right to left)
      for (let c = layers.length - 2; c >= 0; c--) {
        const currentLayer = layers[c];
        currentLayer.sort((a, b) => {
          const baryA = getBarycenter(a.id, c, 1);
          const baryB = getBarycenter(b.id, c, 1);
          if (Math.abs(baryA - baryB) > 0.0001) {
            return baryA - baryB;
          }
          return (nodeRankMap.get(a.id) ?? 0) - (nodeRankMap.get(b.id) ?? 0);
        });
        currentLayer.forEach((n, rIdx) => nodeRankMap.set(n.id, rIdx));
      }
    }

    updateRanks();

    // Assign positions on SVG canvas
    const newPos: Record<string, NodePosition> = {};
    const colSpacing = 310;
    const startX = 50;
    const maxNodesInAnyLayer = Math.max(...layers.map((l) => l.length), 1);
    const totalHeight = Math.max(maxNodesInAnyLayer * 125, 580);

    layers.forEach((layer, colIndex) => {
      const x = startX + colIndex * colSpacing;
      const count = layer.length;
      const step = totalHeight / (count + 1);

      layer.forEach((n, idx) => {
        newPos[n.id] = {
          x,
          y: Math.round((idx + 1) * step),
        };
      });
    });

    setPositions(newPos);

    // If there is a pending focus request, center on the node immediately using newly computed positions
    if (focusedNodeId && newPos[focusedNodeId] && svgRef.current) {
      const pos = newPos[focusedNodeId];
      const rect = svgRef.current.getBoundingClientRect();
      const targetScale = 0.9;
      setScale(targetScale);
      setPan({
        x: Math.round(rect.width / 2 - (pos.x + 105) * targetScale),
        y: Math.round(rect.height / 2 - (pos.y + 29) * targetScale),
      });
      setFocusedNodeId(null);
    }
  };

  // Helper to focus and center a specific node on canvas and open drawer inspector
  const focusNode = useCallback(
    (nodeId: string, customPositions?: Record<string, NodePosition>) => {
      const targetNode = nodes.find((n) => n.id === nodeId);
      if (!targetNode) return;

      setSelectedNode(targetNode);
      setActiveTab("inspector");
      setIsDrawerOpen(true);

      const activePositions = customPositions || positions;
      const pos = activePositions[nodeId];
      if (pos && svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect();
        const targetScale = 0.9;
        setScale(targetScale);
        const nodeCenterX = pos.x + 105;
        const nodeCenterY = pos.y + 29;
        setPan({
          x: Math.round(rect.width / 2 - nodeCenterX * targetScale),
          y: Math.round(rect.height / 2 - nodeCenterY * targetScale),
        });
      } else {
        setFocusedNodeId(nodeId);
      }
    },
    [nodes, positions]
  );

  // Auto-pan to center focused node when positions are ready
  useEffect(() => {
    if (!focusedNodeId) return;
    const pos = positions[focusedNodeId];
    if (pos && svgRef.current) {
      const rect = svgRef.current.getBoundingClientRect();
      const targetScale = 0.9;
      setScale(targetScale);
      const nodeCenterX = pos.x + 105;
      const nodeCenterY = pos.y + 29;
      setPan({
        x: Math.round(rect.width / 2 - nodeCenterX * targetScale),
        y: Math.round(rect.height / 2 - nodeCenterY * targetScale),
      });
      setFocusedNodeId(null);
    }
  }, [focusedNodeId, positions]);

  // Active Attack Path info
  const activeAttackPath = useMemo(() => {
    if (!attackPaths || attackPaths.length === 0) return null;
    if (selectedPathId) {
      const found = attackPaths.find((p) => p.id === selectedPathId);
      if (found) return found;
    }
    return attackPaths[0] || null;
  }, [attackPaths, selectedPathId]);

  const currentPathIndex = useMemo(() => {
    if (!attackPaths || attackPaths.length === 0) return 0;
    const currentId = activeAttackPath?.id || selectedPathId;
    const idx = attackPaths.findIndex((p) => p.id === currentId);
    return idx >= 0 ? idx : 0;
  }, [attackPaths, activeAttackPath, selectedPathId]);

  const handlePrevPath = () => {
    if (currentPathIndex > 0) {
      const prev = attackPaths[currentPathIndex - 1];
      if (prev) {
        setSelectedPathId(prev.id);
        setActiveTab("attack_chain");
      }
    }
  };

  const handleNextPath = () => {
    if (currentPathIndex < attackPaths.length - 1) {
      const next = attackPaths[currentPathIndex + 1];
      if (next) {
        setSelectedPathId(next.id);
        setActiveTab("attack_chain");
      }
    }
  };

  useEffect(() => {
    let timer: any = null;
    if (
      isPlayingWalkthrough &&
      activeAttackPath &&
      Array.isArray(activeAttackPath.steps) &&
      activeAttackPath.steps.length > 0
    ) {
      timer = setInterval(() => {
        setWalkthroughStep((prev) => {
          const total = activeAttackPath.steps?.length || 1;
          const next = prev === null ? 0 : prev + 1;
          if (next >= total) {
            setIsPlayingWalkthrough(false);
            return total - 1;
          }
          return next;
        });
      }, 2200);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPlayingWalkthrough, activeAttackPath]);

  // Set of node IDs belonging to the active attack path
  const activePathNodeMap = useMemo(() => {
    const map = new Map<string, number>();
    if (activeAttackPath && Array.isArray(activeAttackPath.steps)) {
      activeAttackPath.steps.forEach((s) => {
        if (s?.node_id) {
          map.set(s.node_id, s.step_number);
        }
      });
    }
    return map;
  }, [activeAttackPath]);

  // Load Chain Verification Plan when active attack path changes
  useEffect(() => {
    if (!activeAttackPath || !activeTarget) {
      setChainPlan(null);
      setChainStepOutputs({});
      return;
    }
    const targetKey = targetId || activeTarget.target_id || activeTarget.normalized_value || activeTarget.name;
    setLoadingChainPlan(true);
    setChainStepOutputs({});
    fetch(
      `/api/verification/chain-plan/${encodeURIComponent(targetKey)}/${encodeURIComponent(activeAttackPath.id)}`
    )
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setChainPlan(data);
      })
      .catch((err) => console.error("Failed to load chain verification plan", err))
      .finally(() => setLoadingChainPlan(false));
  }, [activeAttackPath, activeTarget, targetId]);

  const handleExecuteChainStep = async (step: ChainVerificationStep) => {
    if (!activeAttackPath) return;
    setExecutingChainStep(step.step_number);
    appendTerminalLog(`copilot@pentest:~$ ${step.command}`);
    try {
      const res = await fetch("/api/verification/chain-execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chain_id: activeAttackPath.id,
          step_number: step.step_number,
          command: step.command,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setChainStepOutputs((prev) => ({
          ...prev,
          [step.step_number]: {
            output: data.output,
            isVuln: data.is_vulnerable_indicated,
            isBroken: data.is_chain_broken,
            evidence: data.evidence_found,
            ai_assessment: data.ai_assessment,
            ai_deduction: data.ai_deduction,
          },
        }));
        if (data.output) {
          const lines = data.output.split("\n");
          lines.forEach((line: string) => {
            if (line.trim()) appendTerminalLog(line);
          });
        }
        if (data.ai_assessment) {
          appendTerminalLog(`[🔍 ĐÁNH GIÁ KỸ THUẬT] ${data.ai_assessment}`);
        }
        if (data.ai_deduction) {
          appendTerminalLog(`[🎯 TẤN CÔNG] ${data.ai_deduction}`);
        }
        if (data.is_chain_broken) {
          appendTerminalLog(
            `[🛡️ SHIELD] Attack Chain broken at step ${step.step_number}! Service resisted attack path.`
          );
        } else if (data.is_vulnerable_indicated) {
          appendTerminalLog(
            `[🔴 VULNERABLE] Step ${step.step_number} confirmed: ${data.evidence_found || "Vulnerability indicator observed."}`
          );
        }
        appendTerminalLog(`[*] Step ${step.step_number} probe completed (${data.status}).`);
      } else {
        appendTerminalLog(`[!] Probe execution returned HTTP status ${res.status}`);
      }
    } catch (err: any) {
      console.error("Execute chain step failed", err);
      appendTerminalLog(`[!] Probe execution error: ${err?.message || err}`);
    } finally {
      setExecutingChainStep(null);
    }
  };

  const currentTargetKey = useMemo(() => {
    return (
      targetId ||
      activeTarget?.target_id ||
      activeTarget?.normalized_value ||
      activeTarget?.name ||
      activeAttackPath?.target_id ||
      attackPaths[0]?.target_id ||
      (nodes.find((n) => n.type === "target")?.properties?.target_id as string) ||
      nodes.find((n) => n.type === "target")?.label ||
      "192.168.242.129"
    );
  }, [targetId, activeTarget, activeAttackPath, attackPaths, attackPlan, nodes]);

  const loadAttackPlan = useCallback(async (customKey?: string) => {
    const key = customKey || currentTargetKey;
    if (!key) return;
    setLoadingAttackPlan(true);
    try {
      const res = await fetch(`/api/attack-plan/${encodeURIComponent(key)}`);
      if (res.ok) {
        const data = await res.json();
        setAttackPlan(data);
        if (data.attack_paths && data.attack_paths.length > 0) {
          setAttackPaths(data.attack_paths);
          if (!selectedPathId) {
            setSelectedPathId(data.attack_paths[0].id);
          }
        }
      }
    } catch (err) {
      console.error("Failed to load attack plan", err);
    } finally {
      setLoadingAttackPlan(false);
    }
  }, [currentTargetKey, selectedPathId]);

  useEffect(() => {
    if (currentTargetKey) {
      loadAttackPlan(currentTargetKey);
    }
  }, [currentTargetKey, loadAttackPlan]);

  const handleToggleRemediate = async (nodeId: string) => {
    if (!currentTargetKey) return;
    setIsSeveringNode(nodeId);
    try {
      const res = await fetch(`/api/attack-plan/${encodeURIComponent(currentTargetKey)}/remediate-node`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_id: nodeId }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.updated_plan) {
          setAttackPlan(data.updated_plan);
          if (data.updated_plan.attack_paths) {
            setAttackPaths(data.updated_plan.attack_paths);
          }
        }
        appendTerminalLog(
          `[+] Choke Point: đã cập nhật trạng thái cắt đứt cho ${nodeId}. Số đường dẫn bị vô hiệu: ${data.severed_path_ids?.length || 0} (${data.risk_reduction_percent}% rủi ro triệt tiêu)`
        );
      }
    } catch (err) {
      console.error("Failed to toggle remediation", err);
    } finally {
      setIsSeveringNode(null);
    }
  };

  const handleRescanPlan = async () => {
    if (!currentTargetKey) return;
    setIsRescanning(true);
    appendTerminalLog(`[*] Khởi tạo Re-scan và cập nhật Attack Graph cho mục tiêu: ${currentTargetKey}...`);
    try {
      const res = await fetch(`/api/attack-plan/${encodeURIComponent(currentTargetKey)}/rescan`, {
        method: "POST",
      });
      if (res.ok) {
        const plan = await res.json();
        setAttackPlan(plan);
        if (plan.attack_paths) {
          setAttackPaths(plan.attack_paths);
        }
        appendTerminalLog(`[+] Re-scan hoàn tất. Đồ thị tấn công và Decision Points đã được đồng bộ hóa.`);
      }
    } catch (err) {
      console.error("Failed to rescan", err);
      appendTerminalLog(`[-] Lỗi Re-scan: ${err}`);
    } finally {
      setIsRescanning(false);
    }
  };

  const handleVerifyPlanStep = async (step: any) => {
    const targetKey =
      currentTargetKey ||
      targetId ||
      activeAttackPath?.target_id ||
      attackPaths[0]?.target_id ||
      attackPlan?.target_id ||
      "192.168.242.129";

    setExecutingChainStep(step.step_number);
    appendTerminalLog(`copilot@pentest:~$ ${step.command}`);
    try {
      const res = await fetch(`/api/attack-plan/${encodeURIComponent(targetKey)}/verify-step`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          step_number: step.step_number,
          command: step.command,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        const probeRes = data.result || data;
        setChainStepOutputs((prev) => ({
          ...prev,
          [step.step_number]: {
            output: probeRes.output || "(Lệnh probe hoàn tất, không có dữ liệu trả về)",
            isVuln: Boolean(probeRes.is_vulnerable_indicated),
            isBroken: Boolean(probeRes.is_chain_broken),
            evidence: probeRes.evidence_found || "Đã nhận phản hồi từ dịch vụ mục tiêu.",
            timestamp: probeRes.timestamp || new Date().toISOString(),
            ai_assessment: probeRes.ai_assessment || "",
            ai_deduction: probeRes.ai_deduction || "",
          },
        }));
        if (data.updated_plan) {
          setAttackPlan(data.updated_plan);
          if (data.updated_plan.attack_paths) {
            setAttackPaths(data.updated_plan.attack_paths);
          }
        }
        if (probeRes.output) {
          probeRes.output.split("\n").forEach((line: string) => {
            if (line.trim()) appendTerminalLog(line);
          });
        }
        if (probeRes.ai_assessment) {
          appendTerminalLog(`[🔍 ĐÁNH GIÁ KỸ THUẬT] ${probeRes.ai_assessment}`);
        }
        if (probeRes.ai_deduction) {
          appendTerminalLog(`[🎯 HƯỚNG KHAI THÁC] ${probeRes.ai_deduction}`);
        }
        if (probeRes.is_vulnerable_indicated) {
          appendTerminalLog(`[🔴 VERIFIED] Xác nhận với bằng chứng: ${probeRes.evidence_found}`);
        } else if (probeRes.is_chain_broken) {
          appendTerminalLog(`[🛡️ BLOCKED] Chuỗi tấn công bị chặn: ${probeRes.evidence_found}`);
        } else {
          appendTerminalLog(`[✓ PROBE COMPLETE] Hoàn tất probe: ${probeRes.evidence_found || "OK"}`);
        }
      } else {
        const errText = await res.text();
        setChainStepOutputs((prev) => ({
          ...prev,
          [step.step_number]: {
            output: `[LỖI ${res.status}] Máy chủ báo lỗi khi thực thi probe: ${errText}`,
            isVuln: false,
            isBroken: true,
            evidence: "Không thể thu thập phản hồi do lỗi kết nối máy chủ.",
            timestamp: new Date().toISOString(),
          },
        }));
        appendTerminalLog(`[!] Verification failed: ${errText}`);
      }
    } catch (err: any) {
      console.error("Verify probe failed", err);
      setChainStepOutputs((prev) => ({
        ...prev,
        [step.step_number]: {
          output: `[LỖI MẠNG] Không thể kết nối tới mục tiêu: ${err?.message || err}`,
          isVuln: false,
          isBroken: true,
          evidence: "Lỗi kết nối probe mạng.",
          timestamp: new Date().toISOString(),
        },
      }));
      appendTerminalLog(`[!] Verification network error: ${err?.message || err}`);
    } finally {
      setExecutingChainStep(null);
    }
  };

  const handleCopyCommand = (cmd: string, stepNum: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedStepCmd(stepNum);
    setTimeout(() => setCopiedStepCmd(null), 2000);
  };

  // 1. Identify all nodes that represent vulnerabilities, findings, impacts, lateral movements, or directly lead to them.
  // Ports and services that do not have vulnerabilities and do not affect anything are completely excluded.
  const relevantNodeIds = useMemo(() => {
    // Start strictly with Vulnerability and Finding nodes as root core causes
    const coreIds = new Set<string>();
    nodes.forEach((n) => {
      const t = (n.type || "").toLowerCase();
      if (t === "vulnerability" || t === "finding") {
        coreIds.add(n.id);
      }
    });

    if (coreIds.size === 0) {
      // If no vulnerabilities found on target, fallback to all nodes
      return new Set<string>(nodes.map((n) => n.id));
    }

    const keep = new Set<string>(coreIds);

    // Backward BFS from core vulns: traces backward ONLY to Services, Ports, and Target root
    const bwdQueue = Array.from(coreIds);
    while (bwdQueue.length > 0) {
      const curr = bwdQueue.shift()!;
      edges.forEach((e) => {
        if (e.target === curr && !keep.has(e.source)) {
          keep.add(e.source);
          bwdQueue.push(e.source);
        }
      });
    }

    // Forward BFS from core vulns: traces downstream ONLY to Impacts and Lateral Movement pivots
    const fwdQueue = Array.from(coreIds);
    while (fwdQueue.length > 0) {
      const curr = fwdQueue.shift()!;
      edges.forEach((e) => {
        if (e.source === curr && !keep.has(e.target)) {
          keep.add(e.target);
          fwdQueue.push(e.target);
        }
      });
    }

    // Always ensure root Target node is included
    nodes.forEach((n) => {
      if ((n.type || "").toLowerCase() === "target") {
        keep.add(n.id);
      }
    });

    return keep;
  }, [nodes, edges]);

  // Nodes with safe/non-vulnerable/unaffected ports filtered out
  const relevantNodes = useMemo(() => {
    return nodes.filter((n) => relevantNodeIds.has(n.id));
  }, [nodes, relevantNodeIds]);

  // Categorized Entity Lists for Dropdown Selector
  const vulnNodes = useMemo(() => {
    return relevantNodes.filter((n) => (n.type || "").toLowerCase() === "vulnerability");
  }, [relevantNodes]);

  const impactNodes = useMemo(() => {
    return relevantNodes.filter((n) => (n.type || "").toLowerCase() === "impact");
  }, [relevantNodes]);

  const pivotNodes = useMemo(() => {
    return relevantNodes.filter((n) => (n.type || "").toLowerCase() === "lateral_movement");
  }, [relevantNodes]);

  const portNodes = useMemo(() => {
    return relevantNodes.filter((n) => (n.type || "").toLowerCase() === "port");
  }, [relevantNodes]);

  const vulnPortsCount = useMemo(() => {
    return portNodes.length;
  }, [portNodes]);

  // Filtered Items inside the Dropdown List
  const filteredListItems = useMemo(() => {
    const q = filterSearch.trim().toLowerCase();
    if (filterTab === "vulns") {
      return vulnNodes.filter(
        (n) =>
          !q ||
          n.label.toLowerCase().includes(q) ||
          (n.properties?.cve_id && String(n.properties.cve_id).toLowerCase().includes(q)) ||
          (n.properties?.description && String(n.properties.description).toLowerCase().includes(q))
      );
    }
    if (filterTab === "impacts") {
      return impactNodes.filter(
        (n) =>
          !q ||
          n.label.toLowerCase().includes(q) ||
          (n.properties?.description && String(n.properties.description).toLowerCase().includes(q))
      );
    }
    if (filterTab === "pivots") {
      return pivotNodes.filter(
        (n) =>
          !q ||
          n.label.toLowerCase().includes(q) ||
          (n.properties?.description && String(n.properties.description).toLowerCase().includes(q))
      );
    }
    // "all": return all relevant entities
    return relevantNodes.filter(
      (n) =>
        !q ||
        n.label.toLowerCase().includes(q) ||
        n.id.toLowerCase().includes(q) ||
        (n.properties?.cve_id && String(n.properties.cve_id).toLowerCase().includes(q))
    );
  }, [filterTab, filterSearch, vulnNodes, impactNodes, pivotNodes, relevantNodes]);

  // Filtered Nodes and Edges
  const filteredNodes = useMemo(() => {
    // 1. If a specific entity is selected (e.g. specific CVE, Impact, or Pivot)
    if (selectedEntityId) {
      const targetNode = relevantNodes.find((n) => n.id === selectedEntityId);
      if (!targetNode) return relevantNodes;

      const keepIds = new Set<string>([selectedEntityId]);
      const queue: string[] = [selectedEntityId];

      // Backward BFS: Trace all paths back to root (Target)
      while (queue.length > 0) {
        const curr = queue.shift()!;
        edges.forEach((e) => {
          if (e.target === curr && !keepIds.has(e.source)) {
            keepIds.add(e.source);
            queue.push(e.source);
          }
        });
      }

      // Forward BFS: Trace downstream consequences (Impact, Lateral Movement)
      const fwdQueue: string[] = [selectedEntityId];
      while (fwdQueue.length > 0) {
        const curr = fwdQueue.shift()!;
        edges.forEach((e) => {
          if (e.source === curr && !keepIds.has(e.target)) {
            keepIds.add(e.target);
            fwdQueue.push(e.target);
          }
        });
      }

      // Always ensure target nodes are included
      relevantNodes.forEach((n) => {
        if ((n.type || "").toLowerCase() === "target") keepIds.add(n.id);
      });

      return relevantNodes.filter((n) => keepIds.has(n.id));
    }

    // 2. Otherwise use category filter (excluding safe/unaffected ports)
    if (filterRisk === "ALL") return relevantNodes;

    if (filterRisk === "VULNERABLE") {
      const vNodes = relevantNodes.filter(
        (n) =>
          n.risk_level === "CRITICAL" ||
          n.risk_level === "HIGH" ||
          n.risk_level === "MEDIUM" ||
          (n.type || "").toLowerCase() === "vulnerability"
      );
      if (vNodes.length === 0) return relevantNodes;

      const keepIds = new Set<string>();
      const queue: string[] = [];
      vNodes.forEach((n) => {
        keepIds.add(n.id);
        queue.push(n.id);
      });

      // Backward BFS: Keep ports & services that expose these vulnerabilities
      while (queue.length > 0) {
        const curr = queue.shift()!;
        edges.forEach((e) => {
          if (e.target === curr && !keepIds.has(e.source)) {
            keepIds.add(e.source);
            queue.push(e.source);
          }
        });
      }

      // Forward BFS: include all downstream consequences (impacts, lateral movements, evidence findings)
      const fwdQueue: string[] = Array.from(keepIds);
      while (fwdQueue.length > 0) {
        const curr = fwdQueue.shift()!;
        edges.forEach((e) => {
          if (e.source === curr && !keepIds.has(e.target)) {
            keepIds.add(e.target);
            fwdQueue.push(e.target);
          }
        });
      }

      relevantNodes.forEach((n) => {
        if ((n.type || "").toLowerCase() === "target") keepIds.add(n.id);
      });

      return relevantNodes.filter((n) => keepIds.has(n.id));
    }

    if (filterRisk === "IMPACT") {
      const impNodes = relevantNodes.filter(
        (n) => (n.type || "").toLowerCase() === "impact"
      );
      if (impNodes.length === 0) return relevantNodes;

      const keepIds = new Set<string>();
      const queue: string[] = [];
      impNodes.forEach((n) => {
        keepIds.add(n.id);
        queue.push(n.id);
      });

      // Backward BFS: Trace all paths back to root (target)
      while (queue.length > 0) {
        const curr = queue.shift()!;
        edges.forEach((e) => {
          if (e.target === curr && !keepIds.has(e.source)) {
            keepIds.add(e.source);
            queue.push(e.source);
          }
        });
      }

      // Forward 1 hop: include connected lateral movement nodes
      impNodes.forEach((n) => {
        edges.forEach((e) => {
          if (e.source === n.id) {
            keepIds.add(e.target);
          }
        });
      });

      relevantNodes.forEach((n) => {
        if ((n.type || "").toLowerCase() === "target") keepIds.add(n.id);
      });

      return relevantNodes.filter((n) => keepIds.has(n.id));
    }

    if (filterRisk === "PIVOT" || filterRisk === "LATERAL_MOVEMENT") {
      const pNodes = relevantNodes.filter(
        (n) => (n.type || "").toLowerCase() === "lateral_movement"
      );
      if (pNodes.length === 0) return relevantNodes;

      const keepIds = new Set<string>();
      const queue: string[] = [];
      pNodes.forEach((n) => {
        keepIds.add(n.id);
        queue.push(n.id);
      });

      // Backward BFS: Trace all paths back to root (target)
      while (queue.length > 0) {
        const curr = queue.shift()!;
        edges.forEach((e) => {
          if (e.target === curr && !keepIds.has(e.source)) {
            keepIds.add(e.source);
            queue.push(e.source);
          }
        });
      }

      relevantNodes.forEach((n) => {
        if ((n.type || "").toLowerCase() === "target") keepIds.add(n.id);
      });

      return relevantNodes.filter((n) => keepIds.has(n.id));
    }

    return relevantNodes.filter((n) => n.risk_level === filterRisk);
  }, [relevantNodes, edges, filterRisk, selectedEntityId]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  const filteredEdges = useMemo(() => {
    return edges.filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));
  }, [edges, filteredNodeIds]);

  // Automatically recompute layout when filter, selected entity or loaded nodes change so nodes are packed compactly without voids
  useEffect(() => {
    if (filteredNodes.length > 0) {
      calculateLayout(filteredNodes, filteredEdges);
    }
  }, [filterRisk, selectedEntityId, filteredNodes, filteredEdges]);

  // Close dropdowns on outside click
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        filterDropdownRef.current &&
        !filterDropdownRef.current.contains(e.target as Node)
      ) {
        setIsFilterOpen(false);
      }
      if (
        pathDropdownRef.current &&
        !pathDropdownRef.current.contains(e.target as Node)
      ) {
        setIsPathDropdownOpen(false);
      }
    };
    if (isFilterOpen || isPathDropdownOpen) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [isFilterOpen, isPathDropdownOpen]);

  // Window-level smooth pan & node dragging
  useEffect(() => {
    const handleWindowMouseMove = (e: MouseEvent) => {
      if (isPanning) {
        setPan({ x: e.clientX - startPan.x, y: e.clientY - startPan.y });
      } else if (draggingNodeId && svgRef.current) {
        if (dragStartRef.current) {
          const dist = Math.hypot(
            e.clientX - dragStartRef.current.clientX,
            e.clientY - dragStartRef.current.clientY
          );
          if (dist > 3) {
            isDragMovedRef.current = true;
          }
        }
        const svgRect = svgRef.current.getBoundingClientRect();
        const mouseX = (e.clientX - svgRect.left - pan.x) / scale;
        const mouseY = (e.clientY - svgRect.top - pan.y) / scale;
        setPositions((prev) => ({
          ...prev,
          [draggingNodeId]: {
            x: Math.round(mouseX - dragOffsetRef.current.x),
            y: Math.round(mouseY - dragOffsetRef.current.y),
          },
        }));
      }
    };

    const handleWindowMouseUp = () => {
      if (isPanning) {
        setIsPanning(false);
      }
      if (draggingNodeId) {
        const nodeId = draggingNodeId;
        const didMove = isDragMovedRef.current;
        setDraggingNodeId(null);
        dragStartRef.current = null;

        // If it was a click (no significant drag), select node & open inspector
        if (!didMove) {
          const found = nodes.find((n) => n.id === nodeId);
          if (found) {
            setSelectedNode(found);
            setActiveTab("inspector");
            setIsDrawerOpen(true);
          }
        }
      }
    };

    if (isPanning || draggingNodeId) {
      window.addEventListener("mousemove", handleWindowMouseMove);
      window.addEventListener("mouseup", handleWindowMouseUp);
      return () => {
        window.removeEventListener("mousemove", handleWindowMouseMove);
        window.removeEventListener("mouseup", handleWindowMouseUp);
      };
    }
  }, [isPanning, draggingNodeId, pan, scale, startPan, nodes]);

  // Canvas pan handler
  const handleMouseDownCanvas = (e: React.MouseEvent) => {
    const target = e.target as HTMLElement;
    if (
      target.tagName === "svg" ||
      target.id === "bg-grid" ||
      target.getAttribute("id") === "bg-grid"
    ) {
      setIsPanning(true);
      setStartPan({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  // Node drag handler
  const handleNodeMouseDown = (e: React.MouseEvent, node: GraphNode) => {
    e.stopPropagation();
    e.preventDefault();
    dragStartRef.current = { clientX: e.clientX, clientY: e.clientY };
    isDragMovedRef.current = false;
    const pos = positions[node.id] || { x: 100, y: 100 };
    const svgRect = svgRef.current?.getBoundingClientRect();
    if (svgRect) {
      const mouseX = (e.clientX - svgRect.left - pan.x) / scale;
      const mouseY = (e.clientY - svgRect.top - pan.y) / scale;
      dragOffsetRef.current = { x: mouseX - pos.x, y: mouseY - pos.y };
      setDraggingNodeId(node.id);
    }
  };

  // Toolbar drag-to-scroll handlers
  const handleToolbarMouseDown = (e: React.MouseEvent) => {
    if (
      (e.target as HTMLElement).closest("button") ||
      (e.target as HTMLElement).closest("a")
    )
      return;
    if (!toolbarRef.current) return;
    isToolbarDraggingRef.current = true;
    toolbarStartXRef.current = e.pageX - toolbarRef.current.offsetLeft;
    toolbarScrollLeftRef.current = toolbarRef.current.scrollLeft;
  };

  const handleToolbarMouseMove = (e: React.MouseEvent) => {
    if (!isToolbarDraggingRef.current || !toolbarRef.current) return;
    e.preventDefault();
    const x = e.pageX - toolbarRef.current.offsetLeft;
    const walk = (x - toolbarStartXRef.current) * 1.5;
    toolbarRef.current.scrollLeft = toolbarScrollLeftRef.current - walk;
  };

  const handleToolbarMouseUp = () => {
    isToolbarDraggingRef.current = false;
  };

  const renderNodes = useMemo(() => {
    if (!draggingNodeId) return filteredNodes;
    return [...filteredNodes].sort((a, b) => {
      if (a.id === draggingNodeId) return 1;
      if (b.id === draggingNodeId) return -1;
      return 0;
    });
  }, [filteredNodes, draggingNodeId]);

  const resetView = () => {
    setScale(0.9);
    setPan({ x: 40, y: 40 });
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "target":
        return <Server className="w-4 h-4 text-emerald-400" />;
      case "port":
        return <Network className="w-4 h-4 text-cyan-400" />;
      case "service":
        return <Layers className="w-4 h-4 text-indigo-400" />;
      case "technology":
        return <Code2 className="w-4 h-4 text-sky-400" />;
      case "vulnerability":
        return <Bug className="w-4 h-4 text-red-400" />;
      case "finding":
        return <FileCheck className="w-4 h-4 text-amber-400" />;
      case "impact":
        return <Flame className="w-4 h-4 text-orange-400" />;
      case "lateral_movement":
        return <Skull className="w-4 h-4 text-rose-400" />;
      default:
        return <Shield className="w-4 h-4 text-zinc-400" />;
    }
  };

  return (
    <div className="flex-1 flex flex-col h-full bg-[#121214] text-zinc-200 select-none overflow-hidden">
      {/* Top Controls & Stats Bar */}
      <div
        ref={toolbarRef}
        onMouseDown={handleToolbarMouseDown}
        onMouseMove={handleToolbarMouseMove}
        onMouseUp={handleToolbarMouseUp}
        onMouseLeave={handleToolbarMouseUp}
        className="h-13 border-b border-zinc-800 bg-[#161619] px-3 flex items-center justify-between z-30 gap-2 min-w-0 select-none cursor-default relative overflow-visible"
      >
        <div className="flex items-center space-x-2 flex-shrink-0 min-w-0">
          {/* Mode Switcher */}
          <div className="flex items-center bg-zinc-900 border border-zinc-700/80 rounded-md p-0.5 flex-shrink-0">
            <button
              onClick={() => setViewMode("topology")}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-semibold whitespace-nowrap flex-shrink-0 transition ${viewMode === "topology"
                  ? "bg-cyan-900/60 text-cyan-300 border border-cyan-700"
                  : "text-zinc-400 hover:text-zinc-200"
                }`}
              title="Full network topology and attack surface view"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Full Topology</span>
            </button>
            <button
              onClick={() => {
                setViewMode("attack_path");
                setActiveTab("attack_chain");
                setIsDrawerOpen(true);
              }}
              className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-semibold whitespace-nowrap flex-shrink-0 transition ${viewMode === "attack_path"
                  ? "bg-rose-950/80 text-rose-300 border border-rose-700"
                  : "text-zinc-400 hover:text-zinc-200"
                }`}
              title="Multi-stage attack path chains view"
            >
              <Crosshair className="w-3.5 h-3.5 text-rose-400" />
              <span>Attack Paths ({attackPaths.length})</span>
              {attackPaths.length > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping ml-0.5 inline-block" />
              )}
            </button>
          </div>

          <span className="text-[11px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700 whitespace-nowrap flex-shrink-0">
            Target: <strong className={targetId ? "text-emerald-400 font-mono" : "text-zinc-500 font-normal"}>{cleanTargetId || "Chưa chọn"}</strong>
          </span>


          {/* Unified Filter & Entity Selector Bar */}
          {viewMode === "topology" && (
            <div ref={filterDropdownRef} className="relative flex-shrink-0">
              <div className="flex items-center bg-zinc-900 border border-zinc-700/80 rounded-lg p-0.5 shadow-sm text-xs">
                {/* Selector Trigger Button */}
                <button
                  onClick={() => setIsFilterOpen((v) => !v)}
                  className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md transition cursor-pointer ${selectedEntityId
                      ? "bg-amber-950/70 border border-amber-600/80 text-amber-300 font-bold"
                      : filterRisk !== "VULNERABLE"
                        ? "bg-cyan-950/70 border border-cyan-600/80 text-cyan-300 font-bold"
                        : "hover:bg-zinc-800 text-zinc-300"
                    }`}
                  title="Danh sách đối tượng và bộ lọc phân loại"
                >
                  <Filter className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="text-zinc-400 text-[11px]">Lọc:</span>
                  <span className="font-semibold text-zinc-200 max-w-[150px] truncate">
                    {selectedEntityId
                      ? (relevantNodes.find((n) => n.id === selectedEntityId)?.label || "Entity")
                      : filterRisk === "VULNERABLE"
                        ? `Lỗ hổng & Cổng ảnh hưởng (${portNodes.length})`
                        : filterRisk === "ALL"
                          ? `Toàn bộ (${relevantNodes.length})`
                          : filterRisk === "IMPACT"
                            ? `Hậu quả (${impactNodes.length})`
                            : filterRisk === "PIVOT"
                              ? `Pivots (${pivotNodes.length})`
                              : filterRisk === "CRITICAL"
                                ? `Critical (${relevantNodes.filter((n) => n.risk_level === "CRITICAL").length})`
                                : `High (${relevantNodes.filter((n) => n.risk_level === "HIGH").length})`}
                  </span>
                  <ChevronDown
                    className={`w-3 h-3 text-zinc-400 transition-transform duration-150 shrink-0 ${isFilterOpen ? "rotate-180" : ""
                      }`}
                  />
                </button>

                {/* Reset button if an entity or non-default filter is active */}
                {(selectedEntityId || filterRisk !== "VULNERABLE") && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedEntityId(null);
                      setFilterRisk("VULNERABLE");
                      resetView();
                    }}
                    className="px-1.5 py-1 text-zinc-400 hover:text-rose-400 hover:bg-zinc-800 rounded transition cursor-pointer"
                    title="Khôi phục mặc định: Chỉ hiện cổng có lỗ hổng"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                )}

                <div className="h-4 w-[1px] bg-zinc-700/60 mx-1" />

                {/* Vulns Quick Tab Button */}
                <button
                  onClick={() => {
                    setFilterTab("vulns");
                    setIsFilterOpen(true);
                  }}
                  className={`flex items-center space-x-1 px-2 py-1 rounded transition cursor-pointer ${filterTab === "vulns" && isFilterOpen
                      ? "bg-red-950/70 text-red-300 font-semibold"
                      : "text-zinc-400 hover:text-red-300 hover:bg-zinc-800/60"
                    }`}
                  title={`Nhấn để mở danh sách ${vulnNodes.length} lỗ hổng bảo mật`}
                >
                  <span className="text-[11px]">Vulns:</span>
                  <span className="font-bold text-red-400">{vulnNodes.length}</span>
                </button>

                {/* Impacts Quick Tab Button */}
                {impactNodes.length > 0 && (
                  <button
                    onClick={() => {
                      setFilterTab("impacts");
                      setIsFilterOpen(true);
                    }}
                    className={`flex items-center space-x-1 px-2 py-1 rounded transition cursor-pointer ${filterTab === "impacts" && isFilterOpen
                        ? "bg-orange-950/70 text-orange-300 font-semibold"
                        : "text-zinc-400 hover:text-orange-300 hover:bg-zinc-800/60"
                      }`}
                    title={`Nhấn để mở danh sách ${impactNodes.length} hậu quả dữ liệu`}
                  >
                    <span className="text-[11px]">Impacts:</span>
                    <span className="font-bold text-orange-400">{impactNodes.length}</span>
                  </button>
                )}

                {/* Pivots Quick Tab Button */}
                {pivotNodes.length > 0 && (
                  <button
                    onClick={() => {
                      setFilterTab("pivots");
                      setIsFilterOpen(true);
                    }}
                    className={`flex items-center space-x-1 px-2 py-1 rounded transition cursor-pointer ${filterTab === "pivots" && isFilterOpen
                        ? "bg-purple-950/70 text-purple-300 font-semibold"
                        : "text-zinc-400 hover:text-purple-300 hover:bg-zinc-800/60"
                      }`}
                    title={`Nhấn để mở danh sách ${pivotNodes.length} di chuyển ngang / pivots`}
                  >
                    <span className="text-[11px]">Pivots:</span>
                    <span className="font-bold text-purple-400">{pivotNodes.length}</span>
                  </button>
                )}
              </div>

              {/* The Dropdown List Modal */}
              {isFilterOpen && (
                <div className="absolute left-0 mt-2 w-96 bg-[#161619] border border-zinc-700/90 rounded-xl shadow-2xl shadow-black/95 z-50 animate-in fade-in zoom-in-95 duration-100 flex flex-col overflow-hidden">
                  {/* Dropdown Header Tabs */}
                  <div className="flex items-center border-b border-zinc-800 bg-[#121214] p-1 gap-1 text-[11px]">
                    <button
                      onClick={() => setFilterTab("vulns")}
                      className={`flex-1 py-1.5 px-2 rounded font-semibold transition text-center cursor-pointer ${filterTab === "vulns"
                          ? "bg-red-950/70 text-red-300 border border-red-800/70"
                          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                        }`}
                    >
                      Lỗ hổng ({vulnNodes.length})
                    </button>
                    <button
                      onClick={() => setFilterTab("impacts")}
                      className={`flex-1 py-1.5 px-2 rounded font-semibold transition text-center cursor-pointer ${filterTab === "impacts"
                          ? "bg-orange-950/70 text-orange-300 border border-orange-800/70"
                          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                        }`}
                    >
                      Hậu quả ({impactNodes.length})
                    </button>
                    <button
                      onClick={() => setFilterTab("pivots")}
                      className={`flex-1 py-1.5 px-2 rounded font-semibold transition text-center cursor-pointer ${filterTab === "pivots"
                          ? "bg-purple-950/70 text-purple-300 border border-purple-800/70"
                          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                        }`}
                    >
                      Pivots ({pivotNodes.length})
                    </button>
                    <button
                      onClick={() => setFilterTab("all")}
                      className={`flex-1 py-1.5 px-2 rounded font-semibold transition text-center cursor-pointer ${filterTab === "all"
                          ? "bg-cyan-950/70 text-cyan-300 border border-cyan-800/70"
                          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                        }`}
                    >
                      Tất cả ({relevantNodes.length})
                    </button>
                  </div>

                  {/* Search Input Box */}
                  <div className="p-2 border-b border-zinc-800 bg-[#141417]">
                    <div className="relative flex items-center">
                      <Search className="w-3.5 h-3.5 text-zinc-400 absolute left-2.5 pointer-events-none" />
                      <input
                        type="text"
                        value={filterSearch}
                        onChange={(e) => setFilterSearch(e.target.value)}
                        placeholder={
                          filterTab === "vulns"
                            ? "Tìm theo CVE, tên lỗ hổng..."
                            : filterTab === "impacts"
                              ? "Tìm theo tên hậu quả, rò rỉ..."
                              : filterTab === "pivots"
                                ? "Tìm theo bước di chuyển ngang..."
                                : "Tìm kiếm mọi đối tượng trong sơ đồ..."
                        }
                        className="w-full pl-8 pr-7 py-1.5 bg-zinc-900 border border-zinc-700/70 rounded-md text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 transition"
                        autoFocus
                      />
                      {filterSearch && (
                        <button
                          onClick={() => setFilterSearch("")}
                          className="absolute right-2 text-zinc-400 hover:text-zinc-200 cursor-pointer"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Group Action Button: View All / Filter Type */}
                  <div className="px-2.5 py-1.5 bg-zinc-900/60 border-b border-zinc-800/60 flex items-center justify-between">
                    <button
                      onClick={() => {
                        setSelectedEntityId(null);
                        if (filterTab === "vulns") {
                          setFilterRisk("VULNERABLE");
                          const vulnNode = relevantNodes.find((n) => (n.type || "").toLowerCase() === "vulnerability");
                          if (vulnNode) focusNode(vulnNode.id);
                        } else if (filterTab === "impacts") {
                          setFilterRisk("IMPACT");
                          const impactNode = relevantNodes.find((n) => (n.type || "").toLowerCase() === "impact");
                          if (impactNode) focusNode(impactNode.id);
                        } else if (filterTab === "pivots") {
                          setFilterRisk("PIVOT");
                          const pivotNode = relevantNodes.find((n) => (n.type || "").toLowerCase() === "lateral_movement");
                          if (pivotNode) focusNode(pivotNode.id);
                        } else {
                          setFilterRisk("ALL");
                          resetView();
                        }
                        setIsFilterOpen(false);
                      }}
                      className="w-full text-left flex items-center justify-between text-xs py-1 px-2 rounded bg-zinc-800/70 hover:bg-zinc-700/80 text-cyan-300 font-medium transition cursor-pointer"
                    >
                      <span className="flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                        {filterTab === "vulns"
                          ? `Chỉ hiện các cổng có lỗ hổng & ảnh hưởng (${portNodes.length} cổng, ${vulnNodes.length} CVE)`
                          : filterTab === "impacts"
                            ? `Lọc & xem tất cả ${impactNodes.length} hậu quả dữ liệu`
                            : filterTab === "pivots"
                              ? `Lọc & xem tất cả ${pivotNodes.length} pivots di chuyển ngang`
                              : `Hiển thị toàn bộ sơ đồ tấn công (${relevantNodes.length} nodes, ${portNodes.length} cổng)`}
                      </span>
                      <ChevronRight className="w-3.5 h-3.5 text-zinc-400" />
                    </button>
                  </div>

                  {/* Scrollable Entity List */}
                  <div className="max-h-72 overflow-y-auto divide-y divide-zinc-800/50 custom-scrollbar p-1">
                    {filteredListItems.length === 0 ? (
                      <div className="text-center py-6 text-zinc-500 text-xs">
                        Không tìm thấy đối tượng nào phù hợp với "{filterSearch}"
                      </div>
                    ) : (
                      filteredListItems.map((item) => {
                        const isCurrent = selectedEntityId === item.id;
                        const cvss = item.properties?.cvss_score;
                        const hasKev = item.properties?.is_cisa_kev || item.properties?.in_cisa_kev;
                        const epss = item.properties?.epss_score;
                        const riskColor = RISK_COLORS[item.risk_level] || RISK_COLORS.INFO;

                        return (
                          <button
                            key={item.id}
                            onClick={() => {
                              setSelectedEntityId(item.id);
                              setFilterRisk("ALL");
                              setSelectedNode(item);
                              focusNode(item.id);
                              setIsFilterOpen(false);
                            }}
                            className={`w-full text-left p-2 rounded-md flex flex-col gap-1 transition cursor-pointer ${isCurrent
                                ? "bg-cyan-950/60 border border-cyan-500/60 shadow-inner"
                                : "hover:bg-zinc-800/60"
                              }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <div className="flex items-center gap-1.5 min-w-0">
                                {item.type === "vulnerability" ? (
                                  <Bug className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                ) : item.type === "impact" ? (
                                  <Skull className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                                ) : item.type === "lateral_movement" ? (
                                  <GitBranch className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                                ) : item.type === "target" ? (
                                  <Server className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                ) : (
                                  <Shield className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                )}
                                <span className="font-semibold text-xs text-zinc-200 truncate">
                                  {item.label}
                                </span>
                              </div>
                              <span
                                className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider shrink-0"
                                style={{
                                  backgroundColor: riskColor.bg,
                                  color: riskColor.text,
                                  border: `1px solid ${riskColor.border}`,
                                }}
                              >
                                {item.risk_level}
                              </span>
                            </div>

                            {/* Extra Metadata: CVSS, KEV, EPSS, Description/Service */}
                            <div className="flex items-center gap-1.5 flex-wrap text-[11px] text-zinc-400">
                              {cvss !== undefined && (
                                <span className="px-1.5 py-0.2 rounded bg-red-950/60 text-red-300 font-mono text-[10px] border border-red-800/60">
                                  CVSS {cvss}
                                </span>
                              )}
                              {hasKev && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-300 font-mono font-bold text-[10px] border border-rose-700 animate-pulse">
                                  KEV
                                </span>
                              )}
                              {epss !== undefined && (
                                <span className="px-1.5 py-0.2 rounded bg-purple-950/60 text-purple-300 font-mono text-[10px] border border-purple-800/60">
                                  EPSS {(Number(epss) * 100).toFixed(1)}%
                                </span>
                              )}
                              {(item.properties?.description || item.properties?.service) && (
                                <span className="text-zinc-400 text-[10px] truncate max-w-[200px]">
                                  {String(item.properties.description || item.properties.service)}
                                </span>
                              )}
                            </div>
                          </button>
                        );
                      })
                    )}
                  </div>

                  {/* Dropdown Footer: Selected Entity Status & Reset */}
                  {selectedEntityId && (
                    <div className="p-2 border-t border-zinc-800 bg-[#121214] flex items-center justify-between">
                      <span className="text-[11px] text-zinc-400">
                        Đang chọn:{" "}
                        <strong className="text-cyan-300">
                          {nodes.find((n) => n.id === selectedEntityId)?.label || selectedEntityId}
                        </strong>
                      </span>
                      <button
                        onClick={() => {
                          setSelectedEntityId(null);
                          setFilterRisk("ALL");
                          resetView();
                          setIsFilterOpen(false);
                        }}
                        className="text-[11px] text-rose-400 hover:text-rose-300 underline font-medium cursor-pointer"
                      >
                        Hủy chọn / Xem tất cả
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Quick Alert Button for Attack Paths */}
          {attackPaths.length > 0 && (
            <button
              onClick={() => {
                setViewMode("attack_path");
                setActiveTab("attack_chain");
                setIsDrawerOpen(true);
              }}
              className="flex items-center space-x-1 px-2 py-1 bg-red-950/60 hover:bg-red-900/80 border border-red-800 rounded text-red-300 animate-pulse whitespace-nowrap transition cursor-pointer"
              title="Click to view attack path chains"
            >
              <AlertTriangle className="w-3.5 h-3.5" />
              <span className="font-bold">{attackPaths.length} Paths</span>
            </button>
          )}
        </div>

        {/* Action Controls */}
        <div className="flex items-center space-x-1.5 flex-shrink-0">
          <button
            onClick={() => calculateLayout(filteredNodes, filteredEdges)}
            className="flex items-center space-x-1 px-2 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 rounded text-xs transition font-medium whitespace-nowrap"
            title="Tự động sắp xếp vị trí & gỡ các đường bắt chéo (Sugiyama Auto Layout / Untangle)"
          >
            <LayoutGrid className="w-3.5 h-3.5 text-cyan-400" />
            <span>Layout</span>
          </button>

          <button
            onClick={() => fetchTopology(true)}
            disabled={syncing}
            className="flex items-center space-x-1 px-2.5 py-1 bg-cyan-900/40 hover:bg-cyan-800/60 border border-cyan-700 text-cyan-300 rounded text-xs transition font-medium disabled:opacity-50 whitespace-nowrap"
            title="Rescan artifacts and rebuild topology"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncing ? "animate-spin" : ""}`} />
            <span>{syncing ? "Syncing..." : "Sync"}</span>
          </button>

          <button
            onClick={handleExportSvg}
            className="flex items-center space-x-1 px-2 py-1 bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 rounded text-xs transition font-medium whitespace-nowrap"
            title="Xuất đồ thị bề mặt tấn công sang định dạng SVG vector"
          >
            <Download className="w-3.5 h-3.5 text-zinc-400" />
            <span>SVG</span>
          </button>

          <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded">
            <button
              onClick={() => setScale((s) => Math.min(s + 0.15, 2.5))}
              className="p-1 text-zinc-400 hover:text-zinc-200"
              title="Phóng to (Zoom In)"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setScale((s) => Math.max(s - 0.15, 0.4))}
              className="p-1 text-zinc-400 hover:text-zinc-200"
              title="Thu nhỏ (Zoom Out)"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={resetView}
              className="p-1 text-zinc-400 hover:text-zinc-200 border-l border-zinc-800"
              title="Căn giữa màn hình (Reset View)"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
          </div>

          <button
            onClick={() => setIsDrawerOpen((v) => !v)}
            className="p-1 bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded"
            title={isDrawerOpen ? "Thu nhỏ ngăn chi tiết" : "Mở rộng ngăn chi tiết"}
          >
            {isDrawerOpen ? (
              <PanelRightClose className="w-3.5 h-3.5" />
            ) : (
              <PanelRightOpen className="w-3.5 h-3.5 text-cyan-400" />
            )}
          </button>
        </div>
      </div>

      {/* Attack Path Selector Strip (Compact Dropdown + Player) */}
      {viewMode === "attack_path" && attackPaths.length > 0 && (
        <div className="bg-[#18181c] border-b border-zinc-800 px-3 py-1.5 flex items-center justify-between z-10 gap-3 text-xs flex-shrink-0 select-none">
          <div className="flex items-center space-x-2 flex-shrink-0 min-w-0">
            {/* Attack Path Dropdown ("Nhấn vào để chọn") */}
            <div ref={pathDropdownRef} className="relative flex-shrink-0">
              <button
                onClick={() => setIsPathDropdownOpen((v) => !v)}
                className="flex items-center space-x-2 px-3 py-1 rounded-md bg-rose-950/70 hover:bg-rose-900/90 border border-rose-600/80 text-rose-100 text-xs font-semibold shadow-md shadow-rose-950/40 transition"
                title={activeAttackPath?.annotation ? `${activeAttackPath.title}\nChú thích: ${activeAttackPath.annotation}` : activeAttackPath?.title || "Click to select attack path"}
              >
                <Flame className="w-3.5 h-3.5 text-rose-400 flex-shrink-0" />
                <span className="text-zinc-400 font-normal text-[11px]">Path:</span>
                <span className="w-4 h-4 rounded-full bg-rose-900 border border-rose-500 flex items-center justify-center text-[10px] font-mono font-bold text-rose-200 flex-shrink-0">
                  {currentPathIndex + 1}
                </span>
                <span className="max-w-[260px] truncate font-bold text-rose-200">
                  {activeAttackPath?.title ? activeAttackPath.title.replace("Khai thác ", "Xác minh ") : "Chọn Attack Path"}
                </span>
                {activeAttackPath?.findings_count && activeAttackPath.findings_count > 1 && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-cyan-950/90 text-cyan-300 border border-cyan-700/80 font-mono">
                    {activeAttackPath.findings_count} CVEs
                  </span>
                )}
                {activeAttackPath?.is_cisa_kev && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-red-900 text-red-200 border border-red-500 font-mono">
                    🔥 KEV
                  </span>
                )}
                {activeAttackPath?.epss_score !== undefined && activeAttackPath.epss_score !== null && (
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-900 text-purple-200 border border-purple-500 font-mono">
                    EPSS: {(activeAttackPath.epss_score * 100).toFixed(0)}%
                  </span>
                )}
                <ChevronDown
                  className={`w-3.5 h-3.5 text-rose-300 transition-transform ${isPathDropdownOpen ? "rotate-180" : ""
                    }`}
                />
              </button>

              {isPathDropdownOpen && (
                <div
                  onWheel={(e) => e.stopPropagation()}
                  className="absolute left-0 mt-1.5 w-[420px] max-h-[380px] overflow-y-auto overscroll-contain scrollbar-thin scrollbar-thumb-zinc-700 scrollbar-track-zinc-900 bg-[#14161c] border border-rose-900/80 rounded-lg shadow-2xl shadow-black/95 p-1.5 z-50 animate-in fade-in zoom-in-95 duration-100 space-y-1"
                >
                  <div className="px-2.5 py-1 text-[10px] font-bold text-zinc-400 uppercase tracking-wider border-b border-zinc-800 flex items-center justify-between">
                    <span>Đường dẫn tấn công ({attackPaths.length})</span>
                    <span className="text-zinc-500 font-mono text-[10px]">Select to inspect</span>
                  </div>
                  {attackPaths.map((p, idx) => {
                    const isSelected = p.id === (activeAttackPath?.id || selectedPathId);
                    const cleanTitle = p.title.replace("Khai thác ", "Xác minh ");
                    return (
                      <button
                        key={p.id}
                        onClick={() => {
                          setSelectedPathId(p.id);
                          setIsPathDropdownOpen(false);
                          setActiveTab("attack_chain");
                          setIsDrawerOpen(true);
                        }}
                        className={`w-full flex items-start space-x-2.5 p-2 rounded-md text-left transition ${isSelected
                            ? "bg-rose-950/90 border border-rose-600/80 text-rose-100"
                            : "hover:bg-zinc-800/80 text-zinc-300 border border-transparent"
                          }`}
                      >
                        <span
                          className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-mono font-bold flex-shrink-0 mt-0.5 ${isSelected
                              ? "bg-rose-600 text-white"
                              : "bg-zinc-800 text-zinc-400 border border-zinc-700"
                            }`}
                        >
                          {idx + 1}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-1.5">
                            <span className="font-semibold text-xs truncate">{cleanTitle}</span>
                            {p.severity && (
                              <span className="px-1 text-[9px] font-mono font-bold rounded bg-black/40 text-rose-300 shrink-0">
                                {p.severity}
                              </span>
                            )}
                            {p.findings_count && p.findings_count > 1 && (
                              <span className="px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800/80 shrink-0">
                                {p.findings_count} CVEs
                              </span>
                            )}
                            {p.is_severed && (
                              <span className="px-1.5 py-0.2 rounded text-[8.5px] font-mono font-bold bg-zinc-900 text-zinc-400 border border-zinc-700 shrink-0">
                                Đã cắt
                              </span>
                            )}
                          </div>
                          <div className="flex items-center space-x-2 mt-0.5 text-[10px] text-zinc-400">
                            <span>{p.steps?.length || 0} steps</span>
                            {p.is_cisa_kev && (
                              <span className="text-red-400 font-bold">🔥 KEV</span>
                            )}
                            {p.epss_score !== undefined && p.epss_score !== null && (
                              <span>EPSS: {(p.epss_score * 100).toFixed(0)}%</span>
                            )}
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Quick Prev / Next Path Arrows */}
            <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded p-0.5 flex-shrink-0">
              <button
                onClick={handlePrevPath}
                disabled={currentPathIndex <= 0}
                className="p-1 rounded text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition"
                title="Previous Path"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <span className="px-1.5 text-[10px] font-mono font-semibold text-zinc-400">
                {currentPathIndex + 1}/{attackPaths.length}
              </span>
              <button
                onClick={handleNextPath}
                disabled={currentPathIndex >= attackPaths.length - 1}
                className="p-1 rounded text-zinc-400 hover:text-zinc-200 disabled:opacity-30 transition"
                title="Next Path"
              >
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Walkthrough Simulation Player Controls */}
          {activeAttackPath && Array.isArray(activeAttackPath.steps) && activeAttackPath.steps.length > 0 && (
            <div className="flex items-center space-x-1.5 flex-shrink-0">
              <button
                onClick={() => {
                  if (isPlayingWalkthrough) {
                    setIsPlayingWalkthrough(false);
                  } else {
                    if (walkthroughStep === null || walkthroughStep >= (activeAttackPath.steps?.length || 1) - 1) {
                      setWalkthroughStep(0);
                    }
                    setIsPlayingWalkthrough(true);
                  }
                }}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-semibold whitespace-nowrap transition ${isPlayingWalkthrough
                    ? "bg-amber-900/60 text-amber-200 border border-amber-600"
                    : "bg-rose-900/60 text-rose-200 border border-rose-600 hover:bg-rose-800/80"
                  }`}
                title={isPlayingWalkthrough ? "Pause simulation" : "Run multi-stage attack simulation"}
              >
                {isPlayingWalkthrough ? (
                  <>
                    <Pause className="w-3.5 h-3.5 text-amber-300" />
                    <span>Pause</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 text-rose-300" />
                    <span>Simulate Path</span>
                  </>
                )}
              </button>

              <button
                onClick={() => {
                  setWalkthroughStep((prev) => {
                    const total = activeAttackPath.steps?.length || 1;
                    if (prev === null) return 0;
                    return Math.min(prev + 1, total - 1);
                  });
                }}
                disabled={walkthroughStep !== null && walkthroughStep >= (activeAttackPath.steps?.length || 1) - 1}
                className="p-1 rounded bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-300 disabled:opacity-40"
                title="Next Step"
              >
                <SkipForward className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={() => {
                  setIsPlayingWalkthrough(false);
                  setWalkthroughStep(null);
                }}
                className="p-1 rounded bg-zinc-900 border border-zinc-800 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200"
                title="Reset simulation"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>

              {walkthroughStep !== null && activeAttackPath.steps && (
                <span className="px-2 py-0.5 rounded bg-zinc-900 border border-rose-900/60 text-[10px] font-mono text-rose-300 font-bold whitespace-nowrap">
                  Step {walkthroughStep + 1}/{activeAttackPath.steps.length}: {activeAttackPath.steps[walkthroughStep]?.phase}
                </span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Main Canvas & Inspector View */}
      <div ref={canvasContainerRef} className="flex-1 flex relative overflow-hidden">
        {/* SVG Canvas */}
        <div
          className="flex-1 min-w-0 h-full relative cursor-grab active:cursor-grabbing bg-[#0d0d10]"
          onMouseDown={handleMouseDownCanvas}
        >
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-black/60 z-20">
              <div className="flex items-center space-x-3 text-cyan-400">
                <RefreshCw className="w-6 h-6 animate-spin" />
                <span className="text-sm font-semibold">
                  Đang tạo bề mặt tấn công & đồ thị tuyến đường...
                </span>
              </div>
            </div>
          )}

          {/* Empty state when no target is selected */}
          {!loading && !targetId && (
            <div className="absolute inset-0 flex flex-col items-center justify-center z-10 p-6 pointer-events-none">
              <div className="max-w-md w-full bg-[#121216]/95 border border-zinc-800 rounded-2xl p-8 text-center shadow-2xl backdrop-blur-md pointer-events-auto">
                <div className="w-16 h-16 rounded-2xl bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center mx-auto mb-4 text-cyan-400 shadow-inner">
                  <Network className="w-8 h-8" />
                </div>
                <h3 className="text-base font-bold text-zinc-100 mb-2">
                  Chưa chọn mục tiêu phân tích
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed mb-5">
                  Attack Graph chưa hiển thị vì chưa có mục tiêu nào được chọn. Vui lòng thêm hoặc chọn một mục tiêu trong Workspace Explorer bên trái để bắt đầu mô hình hóa đồ thị tấn công.
                </p>
                <div className="inline-flex items-center space-x-2 text-xs font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 px-3.5 py-2 rounded-lg">
                  <span>Workspace Explorer → + Thêm mục tiêu</span>
                </div>
              </div>
            </div>
          )}

          {/* Empty state when target is selected but has no scan nodes */}
          {!loading && targetId && nodes.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center z-10 p-6 pointer-events-none">
              <div className="max-w-md w-full bg-[#121216]/95 border border-zinc-800 rounded-2xl p-8 text-center shadow-2xl backdrop-blur-md pointer-events-auto">
                <div className="w-16 h-16 rounded-2xl bg-amber-950/40 border border-amber-500/30 flex items-center justify-center mx-auto mb-4 text-amber-400 shadow-inner">
                  <ShieldAlert className="w-8 h-8" />
                </div>
                <h3 className="text-base font-bold text-zinc-100 mb-2">
                  Chưa có dữ liệu đồ thị tấn công
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed mb-5">
                  Mục tiêu <strong className="text-zinc-200 font-mono">{cleanTargetId}</strong> chưa có dữ liệu quét cổng hoặc phát hiện dịch vụ nào. Hãy chạy quét cổng (Nmap, RustScan, Naabu) hoặc Recon để Copilot xây dựng sơ đồ Attack Graph.
                </p>
                <button
                  onClick={() => fetchTopology(true)}
                  disabled={syncing}
                  className="inline-flex items-center space-x-2 text-xs font-medium text-cyan-300 bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700/70 px-4 py-2 rounded-lg transition shadow-md"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${syncing ? "animate-spin" : ""}`} />
                  <span>Đồng bộ dữ liệu quét</span>
                </button>
              </div>
            </div>
          )}

          <svg
            ref={svgRef}
            className="w-full h-full"
            id="bg-grid"
            style={{
              backgroundImage: "radial-gradient(#27272a 1px, transparent 1px)",
              backgroundSize: "24px 24px",
            }}
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#71717a" />
              </marker>
              <marker
                id="arrow-risk"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444" />
              </marker>
              <marker
                id="arrow-attack-path"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
              </marker>
              <marker
                id="arrow-pivot"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#a855f7" />
              </marker>
              <style>{`
                text, tspan {
                  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                @keyframes attackPulseDash {
                  from { stroke-dashoffset: 24; }
                  to { stroke-dashoffset: 0; }
                }
                .attack-edge-pulse {
                  animation: attackPulseDash 1s linear infinite;
                }
                @keyframes attackNodePulse {
                  0% { r: 18; opacity: 0.9; }
                  100% { r: 42; opacity: 0; }
                }
                .attack-node-halo {
                  animation: attackNodePulse 1.4s cubic-bezier(0, 0, 0.2, 1) infinite;
                }
              `}</style>
            </defs>

            <g transform={`translate(${pan.x}, ${pan.y}) scale(${scale})`}>
              {/* Edges */}
              {filteredEdges.map((e) => {
                const srcPos = positions[e.source];
                const dstPos = positions[e.target];
                if (!srcPos || !dstPos) return null;

                const isPathMode = viewMode === "attack_path";
                const isEdgeInPath =
                  isPathMode &&
                  activePathNodeMap.has(e.source) &&
                  activePathNodeMap.has(e.target);

                const isHighRisk =
                  e.relation === "VULNERABLE_TO" ||
                  e.relation === "LEADS_TO" ||
                  e.relation === "ENABLES_PIVOT" ||
                  (e.properties?.severity &&
                    ["CRITICAL", "HIGH"].includes(e.properties.severity));

                const isPivot = e.relation === "ENABLES_PIVOT";

                // Multiple edge distribution offsets to prevent bundle overlapping, sorted by target/source Y to prevent pin crossings
                const outEdges = filteredEdges
                  .filter((x) => x.source === e.source)
                  .sort((a, b) => (positions[a.target]?.y ?? 0) - (positions[b.target]?.y ?? 0));
                const outIdx = outEdges.findIndex((x) => x.id === e.id);
                const srcOffsetY = outEdges.length > 1 ? (outIdx - (outEdges.length - 1) / 2) * 8 : 0;

                const inEdges = filteredEdges
                  .filter((x) => x.target === e.target)
                  .sort((a, b) => (positions[a.source]?.y ?? 0) - (positions[b.source]?.y ?? 0));
                const inIdx = inEdges.findIndex((x) => x.id === e.id);
                const dstOffsetY = inEdges.length > 1 ? (inIdx - (inEdges.length - 1) / 2) * 8 : 0;

                const startX = srcPos.x + 210;
                const startY = srcPos.y + 29 + srcOffsetY;
                const endX = dstPos.x;
                const endY = dstPos.y + 29 + dstOffsetY;

                // Smooth Bezier Curve with adaptive control points
                const dx = endX - startX;
                const curvature = Math.max(Math.abs(dx) * 0.45, 40);
                const c1x = dx >= 0 ? startX + curvature : startX - curvature;
                const c2x = dx >= 0 ? endX - curvature : endX + curvature;
                const pathD = `M ${startX} ${startY} C ${c1x} ${startY}, ${c2x} ${endY}, ${endX} ${endY}`;

                // Midpoint calculation for label placement
                const midX = (startX + endX) / 2;
                const midY = (startY + endY) / 2;

                // Edge visual styling
                let stroke = isHighRisk ? "#ef4444" : "#475569";
                let strokeWidth = isHighRisk ? 2.2 : 1.5;
                let marker = isHighRisk ? "url(#arrow-risk)" : "url(#arrow)";
                let opacity = 1;

                if (isPivot) {
                  stroke = "#a855f7";
                  marker = "url(#arrow-pivot)";
                }

                if (isPathMode) {
                  if (isEdgeInPath) {
                    stroke = "#f43f5e";
                    strokeWidth = 3.2;
                    marker = "url(#arrow-attack-path)";
                    opacity = 1;
                  } else {
                    opacity = 0.12;
                    stroke = "#334155";
                    strokeWidth = 1;
                  }
                }

                const displayTxt = e.label ? formatEdgeLabel(e.label) : "";
                const pillWidth = Math.max(displayTxt.length * 7.5 + 18, 64);

                return (
                  <g key={e.id} opacity={opacity}>
                    <path
                      d={pathD}
                      fill="none"
                      stroke={stroke}
                      strokeWidth={strokeWidth}
                      strokeDasharray={
                        isEdgeInPath
                          ? "10, 5"
                          : e.relation === "HAS_EVIDENCE" || e.relation === "LEADS_TO"
                            ? "4,4"
                            : undefined
                      }
                      markerEnd={marker}
                      className={
                        isEdgeInPath
                          ? "attack-edge-pulse"
                          : isHighRisk
                            ? "animate-pulse"
                            : ""
                      }
                    />
                    {e.label && (!isPathMode || isEdgeInPath) && (
                      <g transform={`translate(${midX}, ${midY})`} className="pointer-events-none">
                        <rect
                          x={-pillWidth / 2}
                          y={-11}
                          width={pillWidth}
                          height={22}
                          rx={5}
                          fill={isEdgeInPath ? "#1e1022" : isHighRisk ? "#240a0a" : "#0a0f1d"}
                          stroke={isEdgeInPath ? "#f43f5e" : isHighRisk ? "#ef4444" : "#3b4252"}
                          strokeWidth={isEdgeInPath ? 1.8 : 1.2}
                          filter="drop-shadow(0 2px 4px rgba(0,0,0,0.6))"
                        />
                        <text
                          x={0}
                          y={4}
                          fill={isEdgeInPath ? "#ffe4e6" : isHighRisk ? "#fca5a5" : "#e2e8f0"}
                          fontSize="9.5"
                          fontWeight="700"
                          textAnchor="middle"
                          className="font-mono tracking-wider select-none"
                        >
                          {displayTxt}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}

              {/* Active Step Halo in Walkthrough Player */}
              {walkthroughStep !== null &&
                activeAttackPath?.steps &&
                activeAttackPath.steps[walkthroughStep] &&
                (() => {
                  const stepNodeId = activeAttackPath.steps[walkthroughStep]?.node_id;
                  const nodePos = positions[stepNodeId];
                  if (!nodePos) return null;
                  return (
                    <g transform={`translate(${nodePos.x + 105}, ${nodePos.y + 29})`}>
                      <circle
                        r="38"
                        fill="none"
                        stroke="#f43f5e"
                        strokeWidth="2.5"
                        className="attack-node-halo"
                      />
                      <circle
                        r="24"
                        fill="rgba(244, 63, 94, 0.25)"
                        stroke="#f43f5e"
                        strokeWidth="1.5"
                      />
                    </g>
                  );
                })()}

              {/* Nodes (dragged node rendered last so it stays on top) */}
              {renderNodes.map((n) => {
                const pos = positions[n.id] || { x: 100, y: 100 };
                const riskStyle = RISK_COLORS[n.risk_level] || RISK_COLORS.INFO;
                const isSelected = selectedNode?.id === n.id;
                const isDragging = draggingNodeId === n.id;

                const isPathMode = viewMode === "attack_path";
                const stepNumber = activePathNodeMap.get(n.id);
                const isInActivePath = stepNumber !== undefined;

                // Dimming non-path nodes in attack_path mode
                const nodeOpacity = isPathMode ? (isInActivePath ? 1 : 0.2) : 1;

                const hasKev = n.properties?.is_cisa_kev || n.properties?.in_cisa_kev;
                const epss = n.properties?.epss_score;
                const cvssV4 = n.properties?.cvss_v4_score;

                return (
                  <g
                    key={n.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    opacity={nodeOpacity}
                    onMouseDown={(e) => handleNodeMouseDown(e, n)}
                    className={`${isDragging ? "cursor-grabbing" : "cursor-grab"} group select-none`}
                    style={{
                      filter: isDragging
                        ? "drop-shadow(0 0 16px rgba(34, 211, 238, 0.95))"
                        : isSelected
                          ? "drop-shadow(0 0 10px rgba(34, 211, 238, 0.6))"
                          : undefined,
                    }}
                  >
                    {/* Pulsing Selection Halo to visually emphasize focused node */}
                    {isSelected && (
                      <g transform="translate(105, 29)" className="pointer-events-none">
                        <circle
                          r="48"
                          fill="none"
                          stroke={
                            n.type === "impact"
                              ? "#f97316"
                              : n.type === "lateral_movement"
                                ? "#a855f7"
                                : n.type === "vulnerability"
                                  ? "#ef4444"
                                  : "#22d3ee"
                          }
                          strokeWidth="2.5"
                          className="attack-node-halo"
                        />
                        <circle
                          r="32"
                          fill={
                            n.type === "impact"
                              ? "rgba(249, 115, 22, 0.2)"
                              : n.type === "lateral_movement"
                                ? "rgba(168, 85, 247, 0.2)"
                                : n.type === "vulnerability"
                                  ? "rgba(239, 68, 68, 0.2)"
                                  : "rgba(34, 211, 238, 0.2)"
                          }
                          stroke={
                            n.type === "impact"
                              ? "#f97316"
                              : n.type === "lateral_movement"
                                ? "#a855f7"
                                : n.type === "vulnerability"
                                  ? "#ef4444"
                                  : "#22d3ee"
                          }
                          strokeWidth="1.5"
                        />
                      </g>
                    )}

                    {/* Attack Path Step Badge (Floating above node) */}
                    {isPathMode && isInActivePath && (
                      <g transform="translate(0, -16)">
                        <rect
                          width="74"
                          height="16"
                          rx="4"
                          fill="#f43f5e"
                          className="animate-pulse"
                        />
                        <text
                          x="37"
                          y="11"
                          fill="#ffffff"
                          fontSize="9"
                          fontWeight="bold"
                          textAnchor="middle"
                          className="font-mono"
                        >
                          STEP {stepNumber}
                        </text>
                      </g>
                    )}

                    {/* Node Box */}
                    <rect
                      width="210"
                      height="58"
                      rx="8"
                      fill="#18181b"
                      stroke={
                        isDragging
                          ? "#22d3ee"
                          : isInActivePath && isPathMode
                            ? "#f43f5e"
                            : isSelected
                              ? "#22d3ee"
                              : n.type === "impact"
                                ? "#f97316"
                                : n.type === "lateral_movement"
                                  ? "#a855f7"
                                  : riskStyle.border
                      }
                      strokeWidth={
                        isDragging
                          ? 2.5
                          : isInActivePath && isPathMode
                            ? 2.5
                            : isSelected
                              ? 2.5
                              : 1.5
                      }
                      style={{
                        filter:
                          isDragging
                            ? "drop-shadow(0 0 12px rgba(34, 211, 238, 0.8))"
                            : isInActivePath && isPathMode
                              ? "drop-shadow(0 0 12px rgba(244, 63, 94, 0.8))"
                              : isSelected
                                ? "drop-shadow(0 0 10px rgba(34, 211, 238, 0.8))"
                                : `drop-shadow(${riskStyle.glow})`,
                      }}
                    />

                    {/* Top Status Bar indicator */}
                    <rect
                      x="0"
                      y="0"
                      width="210"
                      height="4"
                      rx="2"
                      fill={
                        isInActivePath && isPathMode
                          ? "#f43f5e"
                          : n.type === "impact"
                            ? "#f97316"
                            : n.type === "lateral_movement"
                              ? "#a855f7"
                              : riskStyle.border
                      }
                    />

                    {/* Content inside foreignObject for HTML styling */}
                    <foreignObject width="210" height="58" className="pointer-events-none">
                      <div className="w-full h-full flex flex-col justify-center px-3 py-1 text-xs">
                        <div className="flex items-center space-x-2">
                          <div className="p-1 rounded bg-zinc-900 border border-zinc-700/80 flex-shrink-0">
                            {getNodeIcon(n.type)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="font-semibold truncate text-zinc-100 text-[12px] leading-tight">
                              {n.label}
                            </div>
                            <div className="flex items-center space-x-1.5 mt-0.5">
                              <span className="text-[10px] uppercase font-bold text-zinc-400">
                                {n.type === "lateral_movement"
                                  ? "pivot"
                                  : n.type}
                              </span>
                              <span
                                className="text-[9px] px-1 py-0.2 rounded font-mono font-bold"
                                style={{
                                  color: riskStyle.border,
                                  backgroundColor: riskStyle.bg,
                                }}
                              >
                                {n.risk_level}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Threat Intel Badges for Vulnerability Nodes */}
                        {n.type === "vulnerability" && (hasKev || epss !== undefined || cvssV4) && (
                          <div className="flex items-center space-x-1 mt-1">
                            {hasKev && (
                              <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-red-950 text-red-300 border border-red-600 font-mono">
                                🔥 KEV
                              </span>
                            )}
                            {epss !== undefined && epss !== null && (
                              <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-purple-950 text-purple-300 border border-purple-600 font-mono">
                                EPSS: {(epss * 100).toFixed(0)}%
                              </span>
                            )}
                            {cvssV4 && (
                              <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-600 font-mono">
                                v4: {cvssV4}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </foreignObject>
                  </g>
                );
              })}
            </g>
          </svg>
        </div>

        {/* Inspector & Attack Chain Side Drawer */}
        {isDrawerOpen && (
          <div
            style={{ width: isWideMode ? 620 : drawerWidth }}
            className="relative flex-shrink-0 border-l border-[#1e293b] bg-[#0c101c] flex flex-col h-full overflow-hidden z-20 shadow-2xl transition-[width] duration-150 ease-out"
          >
            {/* Left drag handle for resizing */}
            <div
              onMouseDown={startResizingDrawer}
              className="absolute left-0 top-0 bottom-0 w-1.5 cursor-col-resize hover:bg-cyan-500/60 transition-colors z-30 group"
              title="Kéo để điều chỉnh độ rộng ngăn phân tích"
            >
              <div className="w-0.5 h-8 bg-zinc-600 group-hover:bg-cyan-400 rounded-full mx-auto my-auto relative top-1/2 -translate-y-1/2" />
            </div>

            {/* Drawer Tab Headers & Window Controls */}
            <div className="flex items-center justify-between border-b border-[#1e293b] bg-[#0e1320] text-xs px-1 select-none flex-shrink-0">
              <div className="flex-1 flex">
                <button
                  onClick={() => setActiveTab("attack_chain")}
                  className={`flex-1 py-2.5 font-semibold text-center flex items-center justify-center space-x-1.5 border-b-2 transition ${activeTab === "attack_chain"
                      ? "border-rose-500 text-rose-300 bg-[#161a29]"
                      : "border-transparent text-zinc-400 hover:text-zinc-200"
                    }`}
                >
                  <Crosshair className="w-3.5 h-3.5 text-rose-400" />
                  <span>Attack Chain</span>
                  {attackPaths.length > 0 && (
                    <span className="px-1.5 py-0.2 text-[10px] rounded-full bg-rose-950 text-rose-300 border border-rose-800 font-mono ml-1">
                      {attackPaths.length}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => setActiveTab("inspector")}
                  className={`flex-1 py-2.5 font-semibold text-center flex items-center justify-center space-x-1.5 border-b-2 transition ${activeTab === "inspector"
                      ? "border-cyan-500 text-cyan-300 bg-[#161a29]"
                      : "border-transparent text-zinc-400 hover:text-zinc-200"
                    }`}
                >
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Node Details</span>
                </button>
              </div>

              <div className="flex items-center space-x-1 pr-1.5">
                <button
                  onClick={() => setIsWideMode((v) => !v)}
                  className="p-1.5 rounded-md hover:bg-[#1c253d] text-zinc-400 hover:text-cyan-300 transition"
                  title={isWideMode ? "Thu gọn về kích thước chuẩn" : "Mở rộng tối đa (Wide Mode)"}
                >
                  {isWideMode ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
                </button>
                <button
                  onClick={() => setIsDrawerOpen(false)}
                  className="p-1.5 rounded-md hover:bg-[#1c253d] text-zinc-500 hover:text-zinc-200 transition"
                  title="Đóng ngăn chi tiết"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Sub-navigation for Attack Chain: 4 Core Sections */}
            {activeTab === "attack_chain" && (
              <div className="bg-[#0b0f19] border-b border-[#1e293b] px-3 py-1.5 flex items-center space-x-1.5 select-none flex-shrink-0">
                {[
                  { id: "overview", label: "Overview", icon: Target, count: attackPaths.length },
                  { id: "plan", label: "Attack Plan", icon: GitBranch, count: 6 },
                  { id: "graph", label: "Attack Graph", icon: Network },
                  { id: "verification", label: "Evidence & Verify", icon: ShieldCheck, count: (attackPlan?.verification_steps || chainPlan?.steps || []).length },
                ].map((tab) => {
                  const isCur = attackChainSubTab === tab.id;
                  const IconComp = tab.icon;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setAttackChainSubTab(tab.id as any)}
                      className={`flex-1 flex items-center justify-center space-x-1.5 px-2 py-1.5 rounded-md text-[11px] font-medium whitespace-nowrap transition border ${isCur
                          ? "bg-[#162035] border-cyan-500/80 text-cyan-200 shadow-sm shadow-cyan-950 font-bold"
                          : "bg-[#0d121e] border-[#1e293b] text-zinc-400 hover:text-zinc-200 hover:bg-[#131929]"
                        }`}
                    >
                      <IconComp className={`w-3.5 h-3.5 ${isCur ? "text-cyan-400" : "text-zinc-500"}`} />
                      <span>{tab.label}</span>
                      {tab.count !== undefined && tab.count !== null && (
                        <span className={`px-1.5 py-0.2 text-[9px] rounded font-mono ${isCur ? "bg-cyan-950 text-cyan-300 border border-cyan-800" : "bg-zinc-800 text-zinc-400"
                          }`}>
                          {tab.count}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}

            {/* Quick Attack Chain Selector Bar */}
            {activeTab === "attack_chain" && attackPaths.length > 0 && (
              <div className="bg-[#0e1320]/90 border-b border-[#1e293b] px-3 py-1.5 flex flex-col space-y-1 select-none flex-shrink-0">
                <div className="flex items-center justify-between text-[10.5px]">
                  <span className="font-bold text-zinc-300 flex items-center space-x-1.5">
                    <Zap className="w-3.5 h-3.5 text-rose-400" />
                    <span>Đường dẫn tấn công ({currentPathIndex + 1}/{attackPaths.length})</span>
                  </span>
                  <div className="flex items-center space-x-1">
                    <button
                      onClick={handlePrevPath}
                      disabled={currentPathIndex <= 0}
                      className="p-1 rounded bg-[#121829] hover:bg-[#1c253d] disabled:opacity-30 text-zinc-400 hover:text-cyan-300 border border-[#1e293b] transition"
                      title="Chuỗi trước"
                    >
                      <ChevronLeft className="w-3 h-3" />
                    </button>
                    <button
                      onClick={handleNextPath}
                      disabled={currentPathIndex >= attackPaths.length - 1}
                      className="p-1 rounded bg-[#121829] hover:bg-[#1c253d] disabled:opacity-30 text-zinc-400 hover:text-cyan-300 border border-[#1e293b] transition"
                      title="Chuỗi kế tiếp"
                    >
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Horizontal Pills for each Chain */}
                <div className="flex items-center space-x-1.5 overflow-x-auto pb-0.5 scrollbar-thin">
                  {attackPaths.map((p, idx) => {
                    const isCur = p.id === (activeAttackPath?.id || selectedPathId);
                    const cleanTitle = p.title.replace("Khai thác ", "Xác minh ");
                    let shortName = p.service_name
                      ? `${p.service_name}${p.port_name ? ` (${p.port_name})` : ""}`
                      : cleanTitle.includes("➔")
                        ? cleanTitle.split("➔")[0].replace("Xác minh ", "").trim()
                        : cleanTitle.replace("Xác minh ", "");
                    if (shortName.length > 24) shortName = shortName.slice(0, 22) + "…";

                    return (
                      <button
                        key={p.id}
                        onClick={() => setSelectedPathId(p.id)}
                        title={p.annotation ? `${p.title}\nChú thích: ${p.annotation}` : p.title}
                        className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-[10px] font-medium whitespace-nowrap transition border ${p.is_severed
                            ? "bg-zinc-900/60 border-zinc-800 text-zinc-500 line-through opacity-70"
                            : isCur
                              ? "bg-gradient-to-r from-rose-950 to-rose-900 border-rose-500 text-rose-100 shadow-sm shadow-rose-950 font-bold"
                              : "bg-[#121829] border-[#1e293b] text-zinc-400 hover:text-zinc-200 hover:bg-[#182033]"
                          }`}
                      >
                        <span className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-[8.5px] font-mono ${p.is_severed
                            ? "bg-zinc-800 text-zinc-500"
                            : isCur
                              ? "bg-rose-600 text-white"
                              : "bg-zinc-800 text-zinc-400"
                          }`}>
                          {idx + 1}
                        </span>
                        <span className="truncate max-w-[140px]">{shortName}</span>
                        {p.findings_count && p.findings_count > 1 && (
                          <span className="px-1 py-0.2 rounded text-[8px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                            {p.findings_count} CVEs
                          </span>
                        )}
                        {p.is_severed && <span className="text-[9px] text-emerald-400 not-sr-only">🛡️ Đã cắt</span>}
                        {p.verification_status === "VERIFIED" && !p.is_severed && (
                          <span className="text-[9px] text-emerald-400">✓</span>
                        )}
                        {p.is_cisa_kev && !p.is_severed && <span className="text-[9px]">🔥</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* TAB 1: ATTACK CHAIN CONTAINER */}
            {activeTab === "attack_chain" && (
              <div className="flex-1 overflow-y-auto p-3.5 space-y-3.5 bg-[#0a0d14]">
                {/* 1. OVERVIEW SUBTAB */}
                {attackChainSubTab === "overview" && (
                  <div className="space-y-3.5">
                    {/* 1. Target & State Hero Bar */}
                    <div className="p-3 rounded-xl bg-gradient-to-r from-[#11192e] to-[#0c1220] border border-cyan-900/70 shadow-md space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono text-cyan-400 font-bold uppercase tracking-wide flex items-center space-x-1.5">
                          <Target className="w-4 h-4 text-cyan-400" />
                          <span>MỤC TIÊU: <strong className="text-zinc-100 font-mono">{cleanTargetId || "192.168.100.153"}</strong></span>
                        </span>
                        <span className={`font-mono font-bold px-2 py-0.5 rounded text-[9.5px] border ${attackPlan?.state === "SEVERED"
                            ? "bg-emerald-950/80 border-emerald-600 text-emerald-300"
                            : attackPlan?.state === "VERIFIED"
                              ? "bg-rose-950/80 border-rose-600 text-rose-300"
                              : "bg-cyan-950/80 border-cyan-700 text-cyan-300"
                          }`}>
                          TRẠNG THÁI: {attackPlan?.state || "ACTIVE"}
                        </span>
                      </div>
                      {attackPlan?.objective && (
                        <p className="text-[11px] text-zinc-300 leading-snug">
                          <span className="text-zinc-400 font-semibold">Mục tiêu kiểm thử: </span>{attackPlan.objective}
                        </p>
                      )}
                    </div>

                    {/* 2. Pipeline Funnel (Không coi 39 Findings = 39 Chains) */}
                    <div className="p-3 rounded-xl bg-[#0c1220] border border-[#1e293b] space-y-2">
                      <div className="text-[10.5px] font-bold text-zinc-400 uppercase tracking-wider flex items-center justify-between">
                        <span className="flex items-center space-x-1.5">
                          <Layers className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Quy Trình Tương Quan (Correlation Funnel)</span>
                        </span>
                        <span className="text-[9.5px] font-mono text-zinc-500">Evidence-Driven</span>
                      </div>

                      {/* Funnel Flow Badges */}
                      <div className="grid grid-cols-5 gap-1.5 text-center">
                        {/* Step 1: Findings */}
                        <div className="p-2 rounded-lg bg-[#111626] border border-cyan-900/50">
                          <div className="text-[10px] text-zinc-400 font-medium">Findings</div>
                          <div className="text-sm font-bold font-mono text-cyan-300 mt-0.5">{attackPlan?.findings?.length || 0}</div>
                          <div className="text-[8px] text-zinc-500 uppercase mt-0.5">Phát hiện</div>
                        </div>

                        {/* Step 2: Correlation Paths */}
                        <div className="p-2 rounded-lg bg-[#12162a] border border-purple-900/50">
                          <div className="text-[10px] text-zinc-400 font-medium">Paths</div>
                          <div className="text-sm font-bold font-mono text-purple-300 mt-0.5">{attackPaths.length}</div>
                          <div className="text-[8px] text-zinc-500 uppercase mt-0.5">Chuỗi DAG</div>
                        </div>

                        {/* Step 3: Need Verification */}
                        <div className="p-2 rounded-lg bg-[#181822] border border-amber-900/50">
                          <div className="text-[10px] text-zinc-400 font-medium">Cần Verify</div>
                          <div className="text-sm font-bold font-mono text-amber-300 mt-0.5">
                            {attackPaths.filter((p) => !p.is_severed && p.verification_status !== "VERIFIED").length}
                          </div>
                          <div className="text-[8px] text-zinc-500 uppercase mt-0.5">Chờ xác minh</div>
                        </div>

                        {/* Step 4: Verified */}
                        <div className="p-2 rounded-lg bg-[#101e1c] border border-emerald-900/50">
                          <div className="text-[10px] text-zinc-400 font-medium">Verified</div>
                          <div className="text-sm font-bold font-mono text-emerald-300 mt-0.5">
                            {attackPaths.filter((p) => p.verification_status === "VERIFIED").length}
                          </div>
                          <div className="text-[8px] text-zinc-500 uppercase mt-0.5">Đã xác minh</div>
                        </div>

                        {/* Step 5: Blocked / Severed */}
                        <div className="p-2 rounded-lg bg-[#181216] border border-rose-900/50">
                          <div className="text-[10px] text-zinc-400 font-medium">Blocked</div>
                          <div className="text-sm font-bold font-mono text-rose-300 mt-0.5">
                            {attackPaths.filter((p) => p.is_severed).length}
                          </div>
                          <div className="text-[8px] text-zinc-500 uppercase mt-0.5">Đã cắt đứt</div>
                        </div>
                      </div>
                    </div>

                    {/* 3. Remediation Summary (Tích hợp gọn gàng, không danh sách dài) */}
                    <div className="p-3 rounded-xl bg-[#0c1420] border border-emerald-900/60 flex items-center justify-between gap-2 shadow-sm">
                      <div className="space-y-1">
                        <div className="text-[10.5px] font-bold text-emerald-400 flex items-center space-x-1.5">
                          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Tổng Hợp Khắc Phục (Remediation)</span>
                        </div>
                        <div className="flex items-center space-x-3 text-[11px] text-zinc-300 font-mono">
                          <span>Affected: <strong className="text-zinc-100">{attackPaths.length}</strong></span>
                          <span>•</span>
                          <span>Active: <strong className="text-rose-400">{attackPaths.filter((p) => !p.is_severed).length}</strong></span>
                          <span>•</span>
                          <span>Blocked: <strong className="text-emerald-400">{attackPaths.filter((p) => p.is_severed).length}</strong></span>
                        </div>
                      </div>
                      <button
                        onClick={handleRescanPlan}
                        disabled={isRescanning}
                        className="px-2.5 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-[10.5px] font-semibold transition flex items-center space-x-1 shrink-0 shadow"
                        title="Quét lại và cập nhật lại Attack Graph"
                      >
                        <RefreshCw className={`w-3 h-3 ${isRescanning ? "animate-spin" : ""}`} />
                        <span>{isRescanning ? "Đang quét..." : "Re-Scan"}</span>
                      </button>
                    </div>

                    {/* 4. Active Attack Path Card */}
                    {activeAttackPath && (
                      <div className="p-3.5 rounded-xl bg-[#0f1526] border border-[#1e293b] space-y-3 shadow-md">
                        {/* Title & Badges */}
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-mono text-zinc-400 uppercase tracking-wide flex items-center space-x-1.5">
                              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
                              <span>PATH #{currentPathIndex + 1} • {activeAttackPath.id.split(":").pop()}</span>
                            </span>
                            <div className="flex items-center space-x-1">
                              {activeAttackPath.is_severed && (
                                <span className="font-mono font-bold px-1.5 py-0.2 rounded text-[8.5px] bg-emerald-950 border border-emerald-600 text-emerald-300">
                                  🛡️ ĐÃ CẮT ĐỨT
                                </span>
                              )}
                              <span
                                className="font-mono font-bold px-2 py-0.5 rounded text-[10px]"
                                style={{
                                  backgroundColor: RISK_COLORS[activeAttackPath.severity]?.bg || RISK_COLORS.HIGH.bg,
                                  color: RISK_COLORS[activeAttackPath.severity]?.border || RISK_COLORS.HIGH.border,
                                }}
                              >
                                {activeAttackPath.severity}
                              </span>
                            </div>
                          </div>

                          <h3 className={`font-bold text-sm leading-snug ${activeAttackPath.is_severed ? "line-through text-zinc-500" : "text-zinc-100"}`}>
                            {activeAttackPath.title.replace("Khai thác ", "Xác minh ")}
                          </h3>
                        </div>

                        {/* CVE Chips if multiple */}
                        {activeAttackPath.related_cves && activeAttackPath.related_cves.length > 1 && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                            <span className="text-[10px] text-zinc-400 font-mono">CVEs:</span>
                            {activeAttackPath.related_cves.map((cve) => (
                              <span
                                key={cve}
                                className="px-1.5 py-0.2 rounded text-[9.5px] font-mono bg-[#090e18] border border-cyan-800/60 text-cyan-300"
                              >
                                {cve}
                              </span>
                            ))}
                          </div>
                        )}

                        {/* Status, CVSS & Confidence Badges */}
                        <div className="grid grid-cols-3 gap-2 text-center text-xs">
                          <div className="p-2 rounded bg-[#0a0d16] border border-zinc-800">
                            <div className="text-[9.5px] text-zinc-500">CVSS (Nghiêm trọng)</div>
                            <div className="font-mono font-bold text-rose-400 mt-0.5 text-sm">
                              {activeAttackPath.cvss_score ? activeAttackPath.cvss_score.toFixed(1) : "N/A"}
                            </div>
                            <div className="text-[8px] text-zinc-500">Không = Exploited</div>
                          </div>
                          <div className="p-2 rounded bg-[#0a0d16] border border-zinc-800">
                            <div className="text-[9.5px] text-zinc-500">Trạng thái</div>
                            <div className="font-mono font-bold text-cyan-300 mt-0.5 text-[11px] truncate">
                              {activeAttackPath.verification_status || "Chờ xác minh"}
                            </div>
                            <div className="text-[8px] text-zinc-500">{activeAttackPath.is_severed ? "Blocked" : "Active"}</div>
                          </div>
                          <div className="p-2 rounded bg-[#0a0d16] border border-zinc-800">
                            <div className="text-[9.5px] text-zinc-500">Độ tin cậy</div>
                            <div className="font-mono font-bold text-emerald-400 mt-0.5 text-sm">
                              {Math.round(((activeAttackPath as any).confidence_score || 0.85) * 100)}%
                            </div>
                            <div className="text-[8px] text-zinc-500">Evidence-based</div>
                          </div>
                        </div>

                        {/* Explainability: Why this path exists? (Không dài dòng, gạch đầu dòng ngắn) */}
                        <div className="p-2.5 rounded-lg bg-[#0b101c] border border-blue-900/50 space-y-1.5 text-xs">
                          <div className="font-bold text-blue-300 text-[10.5px] flex items-center space-x-1.5">
                            <Info className="w-3.5 h-3.5 text-blue-400" />
                            <span>Tại sao đường dẫn này tồn tại? (Explainability)</span>
                          </div>
                          <div className="space-y-1 text-[10.5px] text-zinc-300">
                            <div className="flex items-start space-x-1.5">
                              <span className="text-cyan-400 font-bold shrink-0">🎯 Khả thi:</span>
                              <span className="text-zinc-300">
                                {activeAttackPath.explainability?.why_viable || "Cổng mạng mở và banner dịch vụ khớp với dải phiên bản bị ảnh hưởng."}
                              </span>
                            </div>
                            <div className="flex items-start space-x-1.5">
                              <span className="text-amber-400 font-bold shrink-0">🔑 Tiền đề:</span>
                              <span className="text-zinc-300">
                                {activeAttackPath.explainability?.requires_prior_step || "Cần xác thực phản hồi từ dịch vụ trước khi kích hoạt payload."}
                              </span>
                            </div>
                            <div className="flex items-start space-x-1.5">
                              <span className="text-rose-400 font-bold shrink-0">⚡ Điều kiện gãy:</span>
                              <span className="text-zinc-300">
                                {activeAttackPath.explainability?.what_would_break_it || "Đóng cổng, cấu hình WAF chặn path traversal hoặc cập nhật bản vá."}
                              </span>
                            </div>
                          </div>
                        </div>

                        {/* Evidence Summary & Next Action */}
                        <div className="p-2.5 rounded-lg bg-[#0d121f] border border-[#1e293b] space-y-1.5 text-xs">
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-zinc-400 font-semibold">Tóm tắt Bằng chứng:</span>
                            <span className="font-mono text-cyan-400">
                              {activeAttackPath.cve_id || "Nmap & Banner Scan"}
                            </span>
                          </div>
                          <div className="text-[10.5px] text-zinc-300 truncate">
                            {activeAttackPath.attacker_goal ? `Mục tiêu: ${activeAttackPath.attacker_goal}` : "Phát hiện qua quét trinh sát tự động."}
                          </div>
                          <div className="pt-1.5 border-t border-zinc-800 flex items-center justify-between text-[10px]">
                            <span className="text-amber-300 font-medium">Bước tiếp theo:</span>
                            <button
                              onClick={() => setAttackChainSubTab("verification")}
                              className="text-cyan-400 hover:text-cyan-300 font-semibold hover:underline flex items-center space-x-1"
                            >
                              <span>Xem bằng chứng & Chạy Probe</span>
                              <ArrowRight className="w-3 h-3" />
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. ATTACK PLAN SUBTAB (AI Lập Kế Hoạch & Timeline 6 Bước & Choke Point) */}
                {attackChainSubTab === "plan" && (
                  <div className="space-y-3.5">
                    {/* Header */}
                    <div className="p-3 rounded-xl bg-[#0e1628] border border-cyan-800/70 space-y-1">
                      <div className="text-xs font-bold text-cyan-300 flex items-center space-x-1.5">
                        <GitBranch className="w-4 h-4 text-cyan-400" />
                        <span>Kế Hoạch Kiểm Thử (Attack Plan Timeline)</span>
                      </div>
                      <p className="text-[11px] text-zinc-300 leading-relaxed">
                        Quy trình kiểm thử 6 bước tuần tự. Nếu một bước chưa đủ bằng chứng (Insufficient Evidence) thì bước phụ thuộc sẽ tự động bị KHÓA (BLOCKED).
                      </p>
                    </div>

                    {/* 6-Stage Timeline */}
                    <div className="space-y-2 relative before:absolute before:left-4 before:top-4 before:bottom-4 before:w-0.5 before:bg-zinc-800">
                      {[
                        {
                          stepNum: 1,
                          name: "Target Validation",
                          status: "PASSED",
                          icon: "✓",
                          color: "text-emerald-400 border-emerald-500 bg-emerald-950",
                          badge: "bg-emerald-950 text-emerald-300 border-emerald-700",
                          reason: `Mục tiêu ${cleanTargetId || "Target"} phản hồi kết nối và đang trực tuyến.`,
                          evidence: `ICMP Ping / TCP SynACK từ nmap (${cleanTargetId || "Host"})`,
                          nextAction: "Quét và phân giải cổng dịch vụ.",
                        },
                        {
                          stepNum: 2,
                          name: "Service Validation",
                          status: "PASSED",
                          icon: "✓",
                          color: "text-emerald-400 border-emerald-500 bg-emerald-950",
                          badge: "bg-emerald-950 text-emerald-300 border-emerald-700",
                          reason: `Dịch vụ đang mở tại cổng ${activeAttackPath?.steps?.find((s) => s.node_type === "port")?.node_label || "80/tcp"}.`,
                          evidence: "Nmap -sV / HTTPx structured result",
                          nextAction: "Thu thập banner để xác định số phiên bản chính xác.",
                        },
                        {
                          stepNum: 3,
                          name: "Version Validation",
                          status: activeAttackPath?.cve_id ? "PASSED" : "NEEDS_EVIDENCE",
                          icon: activeAttackPath?.cve_id ? "✓" : "⚠",
                          color: activeAttackPath?.cve_id ? "text-emerald-400 border-emerald-500 bg-emerald-950" : "text-amber-400 border-amber-500 bg-amber-950",
                          badge: activeAttackPath?.cve_id ? "bg-emerald-950 text-emerald-300 border-emerald-700" : "bg-amber-950 text-amber-300 border-amber-700",
                          reason: activeAttackPath?.cve_id ? "Phiên bản được xác định rõ từ banner dịch vụ." : "Thiếu banner phiên bản chính xác (Insufficient Evidence).",
                          evidence: activeAttackPath?.cve_id ? "Server: Apache 2.4.49 / HTTP Response" : "Chỉ phát hiện tên dịch vụ, thiếu version cụ thể",
                          nextAction: activeAttackPath?.cve_id ? "Đối chiếu phiên bản với cơ sở dữ liệu CVE/CPE." : "Chạy service-enum để thu thập version.",
                        },
                        {
                          stepNum: 4,
                          name: "Applicability Check",
                          status: !activeAttackPath?.cve_id ? "BLOCKED" : "APPLICABLE",
                          icon: !activeAttackPath?.cve_id ? "✕" : "✓",
                          color: !activeAttackPath?.cve_id ? "text-rose-400 border-rose-500 bg-rose-950" : "text-blue-400 border-blue-500 bg-blue-950",
                          badge: !activeAttackPath?.cve_id ? "bg-rose-950 text-rose-300 border-rose-700" : "bg-blue-950 text-blue-300 border-blue-700",
                          reason: !activeAttackPath?.cve_id
                            ? "BỊ CHẶN: Không thể đối soát Applicability khi thiếu bằng chứng phiên bản."
                            : `Phiên bản khớp với dải sản phẩm bị ảnh hưởng của ${activeAttackPath.cve_id || "CVE"}.`,
                          evidence: !activeAttackPath?.cve_id ? "Thiếu dữ liệu phiên bản" : "CPE Match: dải 2.4.49 - 2.4.50",
                          nextAction: !activeAttackPath?.cve_id ? "Dừng chuỗi cho đến khi có bằng chứng phiên bản." : "Lập kế hoạch Safe Read-Only Verification Probe.",
                        },
                        {
                          stepNum: 5,
                          name: "Verification",
                          status: !activeAttackPath?.cve_id
                            ? "BLOCKED"
                            : activeAttackPath.verification_status === "VERIFIED"
                              ? "VERIFIED"
                              : "NEEDS_VERIFICATION",
                          icon: !activeAttackPath?.cve_id ? "✕" : activeAttackPath.verification_status === "VERIFIED" ? "✓" : "○",
                          color: !activeAttackPath?.cve_id
                            ? "text-rose-400 border-rose-500 bg-rose-950"
                            : activeAttackPath.verification_status === "VERIFIED"
                              ? "text-emerald-400 border-emerald-500 bg-emerald-950"
                              : "text-amber-400 border-amber-500 bg-amber-950",
                          badge: !activeAttackPath?.cve_id
                            ? "bg-rose-950 text-rose-300 border-rose-700"
                            : activeAttackPath.verification_status === "VERIFIED"
                              ? "bg-emerald-950 text-emerald-300 border-emerald-700"
                              : "bg-amber-950 text-amber-300 border-amber-700",
                          reason: !activeAttackPath?.cve_id
                            ? "BỊ CHẶN: Không thực thi probe khi Applicability chưa thỏa mãn."
                            : activeAttackPath.verification_status === "VERIFIED"
                              ? "Probe an toàn đã xác nhận phản hồi đúng theo kỳ vọng."
                              : "Cần gửi safe probe read-only để xác nhận trước khi kết luận.",
                          evidence: activeAttackPath.verification_status === "VERIFIED"
                            ? "curl probe status 200 & khớp evidence payload"
                            : "Lệnh probe: curl read-only (chưa chạy)",
                          nextAction: activeAttackPath.verification_status === "VERIFIED"
                            ? "Chuyển sang đánh giá tác động thực tế."
                            : "Nhấn 'Xác minh' trong tab Evidence & Verify.",
                        },
                        {
                          stepNum: 6,
                          name: "Impact Assessment",
                          status: activeAttackPath?.verification_status === "VERIFIED" ? "EVALUATED" : "PENDING",
                          icon: activeAttackPath?.verification_status === "VERIFIED" ? "✓" : "○",
                          color: activeAttackPath?.verification_status === "VERIFIED"
                            ? "text-purple-400 border-purple-500 bg-purple-950"
                            : "text-zinc-500 border-zinc-700 bg-zinc-900",
                          badge: activeAttackPath?.verification_status === "VERIFIED"
                            ? "bg-purple-950 text-purple-300 border-purple-700"
                            : "bg-zinc-900 text-zinc-500 border-zinc-800",
                          reason: activeAttackPath?.verification_status === "VERIFIED"
                            ? `Xác nhận nguy cơ: ${activeAttackPath.attacker_goal || "Arbitrary File Read / Potential RCE"}.`
                            : "Chờ kết quả xác minh trước khi đánh giá tác động cuối cùng.",
                          evidence: activeAttackPath?.verification_status === "VERIFIED" ? "Chuỗi tấn công có tính khả thi cao" : "Chưa đủ dữ liệu thực nghiệm",
                          nextAction: activeAttackPath?.verification_status === "VERIFIED"
                            ? "Triển khai khắc phục Choke Point phòng thủ."
                            : "Chờ hoàn tất Verification.",
                        },
                      ].map((item) => (
                        <div
                          key={item.stepNum}
                          className="relative pl-9 pr-3 py-2.5 rounded-xl bg-[#0f1526] border border-[#1e293b] text-xs space-y-1.5 transition hover:border-[#2d3b55]"
                        >
                          {/* Dot / Step Icon */}
                          <div className={`absolute left-2 top-3 w-4 h-4 rounded-full border flex items-center justify-center text-[9px] font-mono font-bold shadow-sm ${item.color}`}>
                            {item.icon}
                          </div>

                          <div className="flex items-center justify-between">
                            <span className="font-bold text-zinc-100 flex items-center space-x-1.5">
                              <span>{item.stepNum}. {item.name}</span>
                            </span>
                            <span className={`text-[8.5px] font-mono px-1.5 py-0.2 rounded font-bold border ${item.badge}`}>
                              {item.status}
                            </span>
                          </div>

                          <div className="text-[10.5px] text-zinc-300">
                            <strong className="text-zinc-400">Lý do: </strong>{item.reason}
                          </div>

                          <div className="text-[10px] text-zinc-400 bg-[#0a0d16] p-1.5 rounded border border-zinc-800/80">
                            <span className="text-cyan-400 font-semibold">Bằng chứng: </span>
                            <span className="font-mono text-zinc-300">{item.evidence}</span>
                          </div>

                          <div className="text-[10px] flex items-center space-x-1 pt-0.5 text-amber-300">
                            <span className="font-semibold">Hành động: </span>
                            <span className="text-zinc-300">{item.nextAction}</span>
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Integrated Choke Point Section */}
                    <div className="pt-2 border-t border-[#1e293b] space-y-2.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-amber-300 flex items-center space-x-1.5">
                          <ShieldAlert className="w-4 h-4 text-amber-400" />
                          <span>Điểm Nghẽn Huyết Mạch (Choke Point)</span>
                        </span>
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-700 font-mono">
                          Graph Bottleneck
                        </span>
                      </div>

                      {(attackPlan?.choke_points || []).length === 0 ? (
                        <div className="p-3 rounded-xl bg-[#0c1220] border border-zinc-800 text-xs text-zinc-500 italic text-center">
                          Chưa có điểm nghẽn nào được phát hiện trên đồ thị.
                        </div>
                      ) : (
                        (attackPlan?.choke_points || []).map((cp: any) => {
                          const isSevering = isSeveringNode === cp.node_id;
                          return (
                            <div
                              key={cp.node_id}
                              className={`p-3 rounded-xl border space-y-2 text-xs transition ${cp.is_severed
                                  ? "bg-emerald-950/20 border-emerald-600/70"
                                  : "bg-[#0e1526] border-[#1e293b]"
                                }`}
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-zinc-100 flex items-center space-x-1.5">
                                  <span className={`w-2 h-2 rounded-full ${cp.is_severed ? "bg-emerald-400" : "bg-amber-400"}`} />
                                  <span>{cp.node_label}</span>
                                </span>
                                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-700 font-bold">
                                  Cắt đứt {cp.affected_paths_count} chuỗi ({Math.round((cp.severance_ratio || 0.5) * 100)}%)
                                </span>
                              </div>

                              <p className="text-[10.5px] text-zinc-300 leading-relaxed">
                                <strong className="text-zinc-400">Lý do: </strong>{cp.reason}
                              </p>

                              <div className="p-1.5 rounded bg-[#0a0d16] border border-[#1e293b] text-[10px] text-zinc-400">
                                <strong className="text-emerald-400">Khắc phục: </strong>
                                {cp.recommended_remediation}
                              </div>

                              <div className="pt-1 flex items-center justify-between">
                                <span className="text-[9.5px] font-mono text-zinc-500">Node: {cp.node_id.split(":").slice(0, 3).join(":")}</span>
                                <button
                                  onClick={() => handleToggleRemediate(cp.node_id)}
                                  disabled={executingChainStep !== null}
                                  className={`px-2.5 py-1 rounded text-[10.5px] font-semibold transition flex items-center space-x-1 ${cp.is_severed
                                      ? "bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-600"
                                      : "bg-emerald-700 hover:bg-emerald-600 text-white shadow-sm"
                                    }`}
                                >
                                  {isSevering ? (
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                  ) : cp.is_severed ? (
                                    <RotateCcw className="w-3 h-3 text-zinc-400" />
                                  ) : (
                                    <ShieldCheck className="w-3 h-3 text-emerald-300" />
                                  )}
                                  <span>{cp.is_severed ? "Khôi phục chuỗi" : "Khắc phục (Cắt chuỗi)"}</span>
                                </button>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                )}

                {/* 3. ATTACK GRAPH SUBTAB (Multi-Hop DAG Sequence & Multi-Finding per Service) */}
                {attackChainSubTab === "graph" && (
                  <div className="space-y-3.5">
                    {/* Header */}
                    <div className="p-3 rounded-xl bg-[#0e1628] border border-cyan-800/70 space-y-1">
                      <div className="text-xs font-bold text-cyan-300 flex items-center space-x-1.5">
                        <Network className="w-4 h-4 text-cyan-400" />
                        <span>Biểu Diễn Quan Hệ Đồ Thị (Attack Graph)</span>
                      </div>
                      <p className="text-[11px] text-zinc-300 leading-relaxed">
                        Target ➔ Port ➔ Service ➔ Finding ➔ Verification ➔ Impact. Một Service có thể chứa nhiều Finding, một Finding có thể tham gia nhiều Attack Path.
                      </p>
                    </div>

                    {/* 1. Multi-Hop Sequence for Active Path */}
                    {activeAttackPath && (
                      <div className="p-3 rounded-xl bg-[#0d121f] border border-[#1e293b] space-y-2">
                        <div className="flex items-center justify-between text-xs pb-1 border-b border-[#1e293b]">
                          <span className="font-bold text-zinc-200 flex items-center space-x-1.5">
                            <GitBranch className="w-3.5 h-3.5 text-rose-400" />
                            <span>Luồng Multi-Hop (Chuỗi #{currentPathIndex + 1})</span>
                          </span>
                          <button
                            onClick={() => {
                              if (activeAttackPath.steps && activeAttackPath.steps[0]) {
                                focusNode(activeAttackPath.steps[0].node_id);
                              }
                            }}
                            className="text-[10px] font-semibold text-cyan-400 hover:underline flex items-center space-x-1"
                          >
                            <Crosshair className="w-3 h-3" />
                            <span>Focus chuỗi</span>
                          </button>
                        </div>

                        {/* Interactive Steps List */}
                        <div className="space-y-1.5">
                          {(activeAttackPath.steps || []).map((step, idx) => {
                            const isSelected = selectedNode?.id === step.node_id;
                            return (
                              <div
                                key={idx}
                                onClick={() => focusNode(step.node_id)}
                                className={`p-2 rounded-lg border text-xs cursor-pointer transition flex items-center justify-between ${isSelected
                                    ? "bg-cyan-950/40 border-cyan-500 shadow-sm"
                                    : "bg-[#111626] border-[#1e293b] hover:border-zinc-700"
                                  }`}
                              >
                                <div className="flex items-center space-x-2 truncate">
                                  <span className="w-4 h-4 rounded-full bg-zinc-800 text-zinc-300 border border-zinc-700 flex items-center justify-center text-[9px] font-mono shrink-0">
                                    {idx + 1}
                                  </span>
                                  <span className="font-semibold text-zinc-200 truncate">{step.node_label || step.title}</span>
                                </div>
                                <div className="flex items-center space-x-1.5 shrink-0">
                                  <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/50 text-zinc-400 border border-zinc-800">
                                    {step.phase || step.node_type}
                                  </span>
                                  <ChevronRight className="w-3 h-3 text-zinc-500" />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* 2. Selected Node Details Inline Card */}
                    {selectedNode && (
                      <div className="p-3 rounded-xl bg-[#0c1424] border border-blue-600/60 space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-blue-300 flex items-center space-x-1.5">
                            <Info className="w-3.5 h-3.5 text-blue-400" />
                            <span>Chi Tiết Node: {selectedNode.label}</span>
                          </span>
                          <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-blue-950 text-blue-300 border border-blue-700 font-bold">
                            {selectedNode.type}
                          </span>
                        </div>

                        <div className="text-[10.5px] text-zinc-300 font-mono">
                          ID: <span className="text-zinc-400">{selectedNode.id}</span>
                        </div>

                        {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                          <div className="grid grid-cols-2 gap-1 text-[10px] font-mono pt-1 border-t border-zinc-800">
                            {Object.entries(selectedNode.properties).slice(0, 6).map(([k, v]) => (
                              <div key={k} className="truncate text-zinc-400">
                                <span className="text-zinc-500">{k}: </span>
                                <span className="text-zinc-200">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 3. Service & Multi-Finding Relationship Tree */}
                    <div className="p-3 rounded-xl bg-[#0d121f] border border-[#1e293b] space-y-3">
                      <div className="text-xs font-bold text-cyan-300 pb-1.5 border-b border-[#1e293b] flex items-center space-x-1.5">
                        <Server className="w-4 h-4 text-amber-400" />
                        <span>Dịch Vụ & Lỗ Hổng Trực Thuộc (Multi-Finding Mapping)</span>
                      </div>

                      <div className="space-y-3">
                        {relevantNodes.filter((n) => n.type === "service").length === 0 ? (
                          <div className="text-xs text-zinc-500 italic py-2">
                            Không phát hiện dịch vụ nào có lỗ hổng bảo mật.
                          </div>
                        ) : (
                          relevantNodes
                            .filter((n) => n.type === "service")
                            .map((svcNode) => {
                              const portNum = svcNode.properties?.port;
                              const relatedFindings = (attackPlan?.findings || []).filter(
                                (f: any) =>
                                  f.affected_asset &&
                                  (f.affected_asset.includes(`:${portNum}`) ||
                                    f.affected_asset.includes(String(portNum)) ||
                                    f.title.toLowerCase().includes(svcNode.label.toLowerCase()))
                              );

                              return (
                                <div key={svcNode.id} className="p-2.5 rounded-lg bg-[#101626] border border-[#1e293b] space-y-2 text-xs">
                                  {/* Service Header */}
                                  <div
                                    onClick={() => focusNode(svcNode.id)}
                                    className="flex items-center justify-between cursor-pointer hover:text-cyan-300"
                                  >
                                    <span className="font-bold text-amber-300 flex items-center space-x-1.5">
                                      <Server className="w-3.5 h-3.5 text-amber-400" />
                                      <span>Dịch vụ: {svcNode.label} {portNum ? `(Cổng ${portNum})` : ""}</span>
                                    </span>
                                    <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-black/60 text-zinc-400 border border-zinc-800">
                                      {relatedFindings.length} Findings
                                    </span>
                                  </div>

                                  {/* Findings Cards Under This Service */}
                                  <div className="space-y-1.5 pl-3 border-l-2 border-amber-900/50">
                                    {relatedFindings.map((f: any) => {
                                      // Determine which attack paths this finding participates in
                                      const participatingPaths = attackPaths
                                        .map((p, pIdx) => ({
                                          pathNum: pIdx + 1,
                                          hasFinding: p.steps?.some((st) => st.node_label?.includes(f.cve_id || f.title) || st.title?.includes(f.cve_id || f.title)),
                                        }))
                                        .filter((item) => item.hasFinding)
                                        .map((item) => `#${item.pathNum}`);

                                      return (
                                        <div key={f.id} className="p-2 rounded bg-[#0b0f19] border border-[#1e293b] space-y-1 text-xs">
                                          <div className="flex items-center justify-between">
                                            <span className="font-semibold text-rose-300 text-[11px] truncate max-w-[180px]">
                                              {f.cve_id || f.title}
                                            </span>
                                            <span className={`text-[8.5px] font-mono px-1.5 py-0.2 rounded font-bold border ${f.status === "VERIFIED"
                                                ? "bg-emerald-950 text-emerald-300 border-emerald-600"
                                                : f.status === "APPLICABLE"
                                                  ? "bg-blue-950 text-blue-300 border-blue-600"
                                                  : "bg-amber-950 text-amber-300 border-amber-600"
                                              }`}>
                                              {f.status}
                                            </span>
                                          </div>

                                          {participatingPaths.length > 0 && (
                                            <div className="text-[9.5px] text-purple-300 flex items-center space-x-1">
                                              <GitBranch className="w-3 h-3 text-purple-400 shrink-0" />
                                              <span>Thuộc Attack Path: {participatingPaths.join(", ")}</span>
                                            </div>
                                          )}

                                          <div className="flex items-center justify-between pt-1 border-t border-zinc-800/60 text-[9.5px] text-zinc-400">
                                            <span>CVSS: <strong className="text-rose-400">{f.cvss_score || "N/A"}</strong></span>
                                            <span>Confidence: <strong className="text-cyan-400">{Math.round((f.confidence_score || 0.8) * 100)}%</strong></span>
                                          </div>
                                        </div>
                                      );
                                    })}
                                    {relatedFindings.length === 0 && (
                                      <div className="text-[10px] text-zinc-500 italic py-1">Không có lỗ hổng liên quan</div>
                                    )}
                                  </div>
                                </div>
                              );
                            })
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* 4. EVIDENCE & VERIFICATION SUBTAB (Combined & Traceable Probes) */}
                {attackChainSubTab === "verification" && (
                  <div className="space-y-3.5">
                    {/* Header */}
                    <div className="p-3 rounded-xl bg-[#0c1424] border border-cyan-900/70 space-y-1">
                      <div className="text-xs font-bold text-cyan-400 flex items-center space-x-1.5">
                        <ShieldCheck className="w-4 h-4 text-cyan-400" />
                        <span>Bằng Chứng & Kế Hoạch Xác Minh (Evidence & Verification)</span>
                      </div>
                      <p className="text-[11px] text-zinc-300 leading-relaxed">
                        100% Safe Read-Only Probes. Kiểm chứng tính đúng đắn trước khi kết luận có thể khai thác. Thiếu bằng chứng sẽ hiển thị rõ INSUFFICIENT EVIDENCE.
                      </p>
                    </div>

                    {/* Filter Pills */}
                    <div className="flex items-center space-x-1 overflow-x-auto pb-0.5 scrollbar-thin select-none">
                      {[
                        { id: "all", label: "Tất cả" },
                        { id: "needs_verify", label: "Cần xác minh" },
                        { id: "verified", label: "Đã xác minh" },
                        { id: "insufficient", label: "Chưa đủ bằng chứng" },
                      ].map((flt) => (
                        <button
                          key={flt.id}
                          onClick={() => setVerifyFilter(flt.id)}
                          className={`px-2.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap border transition ${verifyFilter === flt.id
                              ? "bg-cyan-950 border-cyan-500 text-cyan-200 font-bold"
                              : "bg-[#0e1320] border-[#1e293b] text-zinc-400 hover:text-zinc-200"
                            }`}
                        >
                          {flt.label}
                        </button>
                      ))}
                    </div>

                    {/* Combined Verification Probes List */}
                    <div className="space-y-3">
                      {(attackPlan?.verification_steps || chainPlan?.steps || [])
                        .filter((step: any) => {
                          const outputInfo = chainStepOutputs[step.step_number] || (step.actual_result ? {
                            output: step.actual_result,
                            isVuln: step.status === "VERIFIED" || step.next_decision === "CONTINUE_PATH" || (step.confidence === "HIGH" && step.status === "SUCCESS"),
                            isBroken: step.status === "BLOCKED" || step.next_decision === "BLOCK_PATH",
                            evidence: step.evidence_found,
                            timestamp: step.timestamp,
                            ai_assessment: step.ai_assessment,
                            ai_deduction: step.ai_deduction,
                          } : null);
                          if (verifyFilter === "verified") return outputInfo?.isVuln || step.status === "VERIFIED";
                          if (verifyFilter === "needs_verify") return !outputInfo && step.status !== "VERIFIED";
                          if (verifyFilter === "insufficient") return !step.expected_result && !step.command;
                          return true;
                        })
                        .map((step: any) => {
                          const outputInfo = chainStepOutputs[step.step_number] || (step.actual_result ? {
                            output: step.actual_result,
                            isVuln: step.status === "VERIFIED" || step.next_decision === "CONTINUE_PATH" || (step.confidence === "HIGH" && step.status === "SUCCESS"),
                            isBroken: step.status === "BLOCKED" || step.next_decision === "BLOCK_PATH",
                            evidence: step.evidence_found,
                            timestamp: step.timestamp,
                            ai_assessment: step.ai_assessment,
                            ai_deduction: step.ai_deduction,
                          } : null);
                          const isExecuting = executingChainStep === step.step_number;
                          const isCopied = copiedStepCmd === step.step_number;
                          const hasEvidence = Boolean(step.evidence_ref || outputInfo?.evidence || step.expected_result);

                          return (
                            <div
                              key={step.step_number}
                              className={`p-3.5 rounded-xl border space-y-2.5 text-xs transition-all ${isExecuting
                                  ? "bg-[#0b1324] border-cyan-500 shadow-md shadow-cyan-950/40"
                                  : outputInfo?.isVuln || step.status === "VERIFIED"
                                    ? "bg-[#0c1824] border-emerald-900/60"
                                    : outputInfo?.isBroken
                                      ? "bg-[#11131a] border-zinc-800"
                                      : "bg-[#0f1628] border-[#1e293b]"
                                }`}
                            >
                              {/* Header: Tool, Step, Status */}
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-blue-400 text-[11px] flex items-center space-x-1.5">
                                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                                  <span>Bước {step.step_number}: {step.phase || "Safe Probe"}</span>
                                </span>
                                {isExecuting ? (
                                  <span className="text-[8.5px] font-mono px-2 py-0.5 rounded font-bold border bg-cyan-950 text-cyan-300 border-cyan-500 flex items-center space-x-1 animate-pulse">
                                    <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                                    <span>ĐANG CHẠY</span>
                                  </span>
                                ) : (
                                  <span
                                    className={`text-[8.5px] font-mono px-2 py-0.5 rounded font-bold border ${outputInfo?.isVuln || step.status === "VERIFIED"
                                        ? "bg-emerald-950 text-emerald-300 border-emerald-600 shadow-sm shadow-emerald-950"
                                        : outputInfo?.isBroken
                                          ? "bg-zinc-800 text-zinc-400 border-zinc-700"
                                          : "bg-amber-950 text-amber-300 border-amber-600"
                                      }`}
                                  >
                                    {outputInfo?.isVuln || step.status === "VERIFIED"
                                      ? "VERIFIED"
                                      : outputInfo?.isBroken
                                        ? "BLOCKED"
                                        : "NEEDS_VERIFICATION"}
                                  </span>
                                )}
                              </div>

                              <div className="font-semibold text-zinc-100 text-[12px]">{step.node_label || step.name}</div>

                              {step.purpose && (
                                <div className="text-[10.5px] text-zinc-300 leading-relaxed">
                                  <strong className="text-cyan-400">Mục đích: </strong>{step.purpose}
                                </div>
                              )}

                              {/* Command Bar with Copy & Run */}
                              {step.command && (
                                <div className="flex items-center justify-between bg-black/70 p-2 rounded-lg border border-zinc-800 gap-2">
                                  <div className="flex items-center space-x-1.5 overflow-hidden flex-1 min-w-0">
                                    <span className="text-zinc-500 font-mono text-[10px] select-none">$</span>
                                    <code className="text-[10px] font-mono text-cyan-300 truncate" title={step.command}>
                                      {step.command}
                                    </code>
                                  </div>
                                  <div className="flex items-center space-x-1 shrink-0">
                                    <button
                                      onClick={() => handleCopyCommand(step.command, step.step_number)}
                                      className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition"
                                      title="Copy lệnh"
                                    >
                                      {isCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                    </button>
                                    <button
                                      onClick={() => handleVerifyPlanStep(step)}
                                      disabled={isExecuting}
                                      className="flex items-center space-x-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-[10.5px] font-semibold transition shadow-sm"
                                    >
                                      {isExecuting ? (
                                        <RefreshCw className="w-3 h-3 animate-spin" />
                                      ) : (
                                        <Play className="w-3 h-3 fill-current" />
                                      )}
                                      <span>{isExecuting ? "Đang chạy..." : "Xác minh"}</span>
                                    </button>
                                  </div>
                                </div>
                              )}

                              {/* Expected Result */}
                              <div className="text-[10.5px] text-zinc-400">
                                <strong className="text-zinc-300">Kỳ vọng: </strong>
                                <span>{step.expected_result || step.expected_evidence || "Phản hồi mã trạng thái và banner khớp thông số dịch vụ"}</span>
                              </div>

                              {/* Dynamic Execution Feedback / Active Probe */}
                              {isExecuting && (
                                <div className="p-3 rounded-lg bg-[#070e1e] border border-cyan-500/60 space-y-1.5 animate-pulse">
                                  <div className="flex items-center space-x-2 text-[11px] text-cyan-300 font-mono font-semibold">
                                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                                    <span>Đang thực thi probe an toàn trên máy chủ mục tiêu...</span>
                                  </div>
                                  <div className="text-[9.5px] font-mono text-zinc-400 pl-5.5">
                                    $ {step.command}
                                  </div>
                                </div>
                              )}

                              {/* Execution Actual Result Console Output */}
                              {outputInfo && !isExecuting && (
                                <div className="p-3 rounded-lg bg-[#070b15] border border-zinc-700/80 space-y-2">
                                  <div className="flex items-center justify-between text-[10.5px] font-semibold pb-1.5 border-b border-zinc-800">
                                    <span className="text-zinc-300 flex items-center space-x-1.5">
                                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                                      <span className="font-bold text-cyan-200">KẾT QUẢ THỰC TẾ (PROBE OUTPUT):</span>
                                    </span>
                                    {outputInfo.isBroken ? (
                                      <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-600 text-zinc-300 font-bold text-[9px] flex items-center space-x-1">
                                        <ShieldAlert className="w-2.5 h-2.5 text-zinc-400" />
                                        <span>ĐÃ PHÒNG VỆ / AN TOÀN</span>
                                      </span>
                                    ) : outputInfo.isVuln ? (
                                      <span className="px-2 py-0.5 rounded bg-rose-950 border border-rose-600 text-rose-300 font-bold text-[9px] flex items-center space-x-1">
                                        <CheckCircle2 className="w-2.5 h-2.5 text-rose-400" />
                                        <span>XÁC NHẬN LỖ HỔNG</span>
                                      </span>
                                    ) : (
                                      <span className="px-2 py-0.5 rounded bg-blue-950 border border-blue-600 text-blue-300 font-bold text-[9px] flex items-center space-x-1">
                                        <Info className="w-2.5 h-2.5 text-blue-400" />
                                        <span>HOÀN TẤT THĂM DÒ</span>
                                      </span>
                                    )}
                                  </div>

                                  <div className="bg-black/90 p-2.5 rounded border border-zinc-800/90">
                                    <pre className="text-[10px] font-mono text-emerald-400 max-h-40 overflow-y-auto whitespace-pre-wrap leading-relaxed select-text scrollbar-thin">
                                      {outputInfo.output}
                                    </pre>
                                  </div>

                                  {outputInfo.evidence && (
                                    <div className="p-2 rounded bg-cyan-950/40 border border-cyan-800/60 text-[10px] text-cyan-200 flex items-start space-x-2">
                                      <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                                      <div>
                                        <strong className="text-cyan-300">Bằng chứng trích xuất: </strong>
                                        <span>{outputInfo.evidence}</span>
                                      </div>
                                    </div>
                                  )}

                                  {/* Technical Assessment */}
                                  {(outputInfo.ai_assessment || step.ai_assessment) && (
                                    <div className="p-2.5 rounded-lg bg-[#081220] border border-cyan-800/70 space-y-1.5 shadow-sm">
                                      <div className="flex items-center justify-between text-[10.5px]">
                                        <span className="font-bold text-cyan-300 flex items-center space-x-1.5">
                                          <Activity className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                                          <span>ĐÁNH GIÁ KỸ THUẬT:</span>
                                        </span>
                                        <span className="text-[8.5px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-700 text-cyan-300">
                                          TECHNICAL AUDIT
                                        </span>
                                      </div>
                                      <div className="text-[11px] text-zinc-200 leading-relaxed font-sans pl-2.5 border-l-2 border-cyan-500/60">
                                        {outputInfo.ai_assessment || step.ai_assessment}
                                      </div>
                                    </div>
                                  )}

                                  {/* Attack Chain Deduction */}
                                  {(outputInfo.ai_deduction || step.ai_deduction) && (
                                    <div className="p-2.5 rounded-lg bg-[#140e26] border border-purple-800/70 space-y-1.5 shadow-sm">
                                      <div className="flex items-center justify-between text-[10.5px]">
                                        <span className="font-bold text-purple-300 flex items-center space-x-1.5">
                                          <Crosshair className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                                          <span>HƯỚNG KHAI THÁC:</span>
                                        </span>
                                        <span className="text-[8.5px] font-mono font-bold px-1.5 py-0.2 rounded bg-purple-950 border border-purple-700 text-purple-300">
                                          ATTACK CHAIN IMPACT
                                        </span>
                                      </div>
                                      <div className="text-[11px] text-zinc-200 leading-relaxed font-sans pl-2.5 border-l-2 border-purple-500/60">
                                        {outputInfo.ai_deduction || step.ai_deduction}
                                      </div>
                                    </div>
                                  )}

                                  {outputInfo.timestamp && (
                                    <div className="text-[9px] font-mono text-zinc-500 text-right">
                                      Thời điểm xác minh: {new Date(outputInfo.timestamp).toLocaleTimeString()}
                                    </div>
                                  )}
                                </div>
                              )}

                              {/* Evidence Block or INSUFFICIENT EVIDENCE Banner (only if unverified and no output) */}
                              {!outputInfo && !isExecuting && !hasEvidence ? (
                                <div className="p-2.5 rounded-lg bg-amber-950/40 border border-amber-700/60 text-amber-300 text-[10.5px] flex items-center space-x-1.5">
                                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                                  <span className="font-bold font-mono">INSUFFICIENT EVIDENCE:</span>
                                  <span>Chưa có bằng chứng thực địa từ công cụ. Nhấn nút "Xác minh" ở trên để gửi probe thu thập.</span>
                                </div>
                              ) : null}

                              {/* Confidence Score & Next Decision */}
                              <div className="pt-1.5 border-t border-zinc-800/80 flex items-center justify-between text-[10px] text-zinc-400">
                                <span>Độ tin cậy: <strong className="text-emerald-400">{Math.round((step.confidence_score || 0.85) * 100)}%</strong></span>
                                <span className="text-zinc-500 font-mono">100% Read-Only</span>
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tab 2: Individual Node Inspector */}
            {activeTab === "inspector" && (
              <div className="flex-1 overflow-y-auto p-4 flex flex-col space-y-4">
                {selectedNode ? (
                  <>
                    <div className="flex items-center space-x-2 pb-2 border-b border-zinc-800">
                      <div className="p-1.5 rounded bg-zinc-900 border border-zinc-700">
                        {getNodeIcon(selectedNode.type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="font-bold text-sm text-zinc-100 truncate">
                          {selectedNode.label}
                        </h3>
                        <span className="text-[10px] text-zinc-500 uppercase tracking-wider">
                          {formatNodeType(selectedNode.type)}
                        </span>
                      </div>
                    </div>

                    {/* Entity Label & Risk */}
                    <div className="p-3 rounded bg-zinc-900/80 border border-zinc-800">
                      <div className="text-xs text-zinc-400">Đánh giá mức độ rủi ro:</div>
                      <div className="flex items-center justify-between mt-1">
                        <span
                          className="font-mono font-bold px-2 py-0.5 rounded text-xs"
                          style={{
                            backgroundColor: RISK_COLORS[selectedNode.risk_level]?.bg,
                            color: RISK_COLORS[selectedNode.risk_level]?.border,
                          }}
                        >
                          {selectedNode.risk_level}
                        </span>
                        {selectedNode.properties?.cvss_score && (
                          <span className="text-xs font-mono text-zinc-300">
                            CVSS: <strong>{selectedNode.properties.cvss_score}</strong>
                          </span>
                        )}
                      </div>

                      {/* Threat Intel if CVE node */}
                      {selectedNode.type === "vulnerability" && (
                        <div className="mt-3 pt-2 border-t border-zinc-800 space-y-1.5">
                          <div className="text-[10px] font-bold text-zinc-400 uppercase">
                            Tình báo mối đe dọa trực tiếp (Live Threat Intel)
                          </div>

                          {selectedNode.properties?.is_cisa_kev ? (
                            <div className="flex items-center space-x-1.5 px-2 py-1 rounded bg-red-950/80 border border-red-700 text-red-300 text-xs font-semibold">
                              <Flame className="w-3.5 h-3.5 text-red-400" />
                              <span>CISA KEV: Đang bị khai thác thực tế</span>
                            </div>
                          ) : (
                            <div className="text-[11px] text-zinc-500">
                              CISA KEV: Chưa ghi nhận mã khai thác đại trà
                            </div>
                          )}

                          {selectedNode.properties?.epss_score !== undefined && (
                            <div className="text-xs text-purple-300 flex items-center justify-between">
                              <span>Xác suất bị khai thác (EPSS):</span>
                              <span className="font-mono font-bold">
                                {(selectedNode.properties.epss_score * 100).toFixed(1)}%
                              </span>
                            </div>
                          )}

                          {selectedNode.properties?.cvss_v4_score && (
                            <div className="text-xs text-cyan-300 flex items-center justify-between">
                              <span>Điểm số CVSS v4.0:</span>
                              <span className="font-mono font-bold">
                                {selectedNode.properties.cvss_v4_score}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    {/* Direct Reference Links Card */}
                    {selectedNodeReferences.length > 0 && (
                      <div className="p-3 rounded bg-cyan-950/30 border border-cyan-800/70 space-y-2">
                        <div className="text-[11px] font-bold text-cyan-300 uppercase tracking-wider flex items-center justify-between">
                          <div className="flex items-center space-x-1.5">
                            <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Nguồn tham khảo (Nhấn để đọc nguồn)</span>
                          </div>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-300 border border-cyan-700/50">
                            {selectedNodeReferences.length} liên kết
                          </span>
                        </div>
                        <div className="flex flex-col space-y-1.5">
                          {selectedNodeReferences.map((ref, idx) => (
                            <a
                              key={idx}
                              href={ref.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center justify-between p-2 rounded bg-zinc-900/90 hover:bg-zinc-800 border border-cyan-800/50 hover:border-cyan-600 text-cyan-200 text-xs transition group shadow-xs"
                              title={`Chuyển đến nguồn: ${ref.url}`}
                            >
                              <div className="flex items-center space-x-2 min-w-0">
                                <span
                                  className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold uppercase shrink-0"
                                  style={{
                                    backgroundColor: ref.badgeBg || "rgba(6, 182, 212, 0.2)",
                                    color: ref.badgeColor || "#22d3ee",
                                  }}
                                >
                                  {ref.badge}
                                </span>
                                <span className="font-medium text-zinc-200 group-hover:text-cyan-300 truncate text-[11px]">
                                  {ref.label}
                                </span>
                              </div>
                              <ExternalLink className="w-3.5 h-3.5 text-zinc-500 group-hover:text-cyan-400 shrink-0 ml-1.5 transition-transform group-hover:translate-x-0.5" />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Properties List */}
                    <div className="space-y-2 flex-1">
                      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                        Thuộc tính & Metadata thực thể
                      </h4>
                      <div className="space-y-2 text-xs">
                        {Object.entries(selectedNode.properties || {}).map(([key, val]) => {
                          if (
                            key === "evidence_chain" ||
                            key === "patch_recommendation" ||
                            typeof val === "object"
                          )
                            return null;
                          return (
                            <div
                              key={key}
                              className="p-2 rounded bg-zinc-900/50 border border-zinc-800/80 flex flex-col"
                            >
                              <span className="text-[10px] text-zinc-500 uppercase">{getPropertyLabel(key)}</span>
                              <div className="font-mono text-zinc-200 mt-0.5 break-words leading-relaxed text-xs">
                                {renderRichTextWithLinks(String(val))}
                              </div>
                            </div>
                          );
                        })}

                        {selectedNode.properties?.patch_recommendation && (
                          <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-800/60 text-xs">
                            <span className="text-[10px] text-emerald-400 uppercase font-semibold">
                              Khuyến nghị khắc phục:
                            </span>
                            <div className="text-zinc-300 mt-1 leading-relaxed">
                              {renderRichTextWithLinks(selectedNode.properties.patch_recommendation)}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="pt-3 border-t border-zinc-800 space-y-2">
                      {selectedNodeReferences.length > 0 && (
                        <a
                          href={selectedNodeReferences[0].url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-700 text-cyan-200 rounded text-xs font-semibold transition shadow-sm"
                        >
                          <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Chuyển đến nguồn ({selectedNodeReferences[0].badge}) ↗</span>
                        </a>
                      )}

                      {selectedNode.type === "vulnerability" && (
                        <button
                          onClick={() => {
                            const cve = selectedNode.properties?.cve_id || selectedNode.label;
                            appendTerminalLog(`[*] Safe verification initiated for: ${cve}`);
                            appendTerminalLog(`$ @copilot verify ${cve}`);
                            setActiveView("findings");
                          }}
                          className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-red-950/40 hover:bg-red-900/60 border border-red-800 text-red-300 rounded text-xs font-semibold transition"
                        >
                          <Play className="w-3.5 h-3.5" />
                          <span>Kế hoạch kiểm chứng an toàn</span>
                        </button>
                      )}

                      <button
                        onClick={() => {
                          setActiveView("findings");
                        }}
                        className="w-full flex items-center justify-center space-x-2 px-3 py-2 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-300 rounded text-xs font-medium transition"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-zinc-400" />
                        <span>Xem chi tiết trong Danh mục Lỗ hổng (Findings)</span>
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="p-8 text-center text-zinc-500 text-xs">
                    {!targetId
                      ? "Chưa chọn mục tiêu nào."
                      : "Chọn một Node trên đồ thị hoặc một bước trong Attack Chain để xem chi tiết."}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
