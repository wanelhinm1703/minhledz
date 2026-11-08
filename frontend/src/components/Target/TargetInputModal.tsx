import React, { useState } from "react";
import {
  X,
  Search,
  CheckCircle,
  AlertTriangle,
  Play,
  ShieldAlert,
  Sliders,
  Check,
  Plus,
  Globe,
  Radio,
  ShieldCheck,
  Server,
  RotateCcw,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

interface SystemTool {
  id: string;
  name: string;
  category: "network" | "web" | "vulnerability" | "service_enum";
  categoryLabel: string;
  purpose: string;
}

const ALL_SYSTEM_TOOLS: SystemTool[] = [
  // Network Scanning
  { id: "naabu", name: "Naabu", category: "network", categoryLabel: "Network", purpose: "Fast Port Discovery" },
  { id: "nmap", name: "Nmap", category: "network", categoryLabel: "Network", purpose: "Service & Version Fingerprinting" },
  { id: "rustscan", name: "RustScan", category: "network", categoryLabel: "Network", purpose: "Adaptive Fast Port Scanner" },
  { id: "masscan", name: "Masscan", category: "network", categoryLabel: "Network", purpose: "High-Speed SYN Port Scanner" },
  { id: "testssl", name: "TestSSL", category: "network", categoryLabel: "Network", purpose: "SSL/TLS Cipher & Vuln Audit" },
  { id: "theharvester", name: "theHarvester", category: "network", categoryLabel: "Network", purpose: "OSINT Subdomain Recon" },
  // Web Enumeration
  { id: "httpx", name: "HTTPx", category: "web", categoryLabel: "Web", purpose: "HTTP Probe, Title & Tech Probing" },
  { id: "whatweb", name: "WhatWeb", category: "web", categoryLabel: "Web", purpose: "CMS & Framework Fingerprinting" },
  { id: "nikto", name: "Nikto", category: "web", categoryLabel: "Web", purpose: "Web Server Misconfiguration Scanner" },
  { id: "gobuster", name: "Gobuster", category: "web", categoryLabel: "Web", purpose: "URI & Directory Bruteforcing" },
  { id: "ffuf", name: "FFUF", category: "web", categoryLabel: "Web", purpose: "High-Performance Web Fuzzing" },
  { id: "katana", name: "Katana", category: "web", categoryLabel: "Web", purpose: "Web Crawler & Endpoint Extraction" },
  // Vulnerability
  { id: "nuclei", name: "Nuclei", category: "vulnerability", categoryLabel: "Vulnerability", purpose: "Template CVE & Exposure Audit" },
  { id: "nmap-nse", name: "Nmap NSE", category: "vulnerability", categoryLabel: "Vulnerability", purpose: "Vulnerability & Auth Scripts" },
  { id: "searchsploit", name: "SearchSploit", category: "vulnerability", categoryLabel: "Vulnerability", purpose: "Exploit-DB Offline Query" },
  // Service Enum
  { id: "enum4linux", name: "enum4linux", category: "service_enum", categoryLabel: "Services", purpose: "SMB & Windows Share Enumeration" },
  { id: "smbclient", name: "smbclient", category: "service_enum", categoryLabel: "Services", purpose: "Samba Share & Null Session Probe" },
  { id: "snmpwalk", name: "snmpwalk", category: "service_enum", categoryLabel: "Services", purpose: "SNMP System Info & OID Walking" },
  { id: "ldapsearch", name: "ldapsearch", category: "service_enum", categoryLabel: "Services", purpose: "LDAP / Active Directory Query" },
  { id: "database", name: "Database", category: "service_enum", categoryLabel: "Services", purpose: "MySQL, Postgres Banner Discovery" },
];

export const TargetInputModal: React.FC = () => {
  const {
    isTargetModalOpen,
    setTargetModalOpen,
    fetchInitialData,
    appendTerminalLog,
  } = useWorkspaceStore();
  const [inputVal, setInputVal] = useState("");
  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState<any>(null);
  const [selectedTools, setSelectedTools] = useState<string[]>([
    "naabu",
    "nmap",
  ]);
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  if (!isTargetModalOpen) return null;

  const handleDetect = async () => {
    if (!inputVal.trim()) return;
    setDetecting(true);
    setError(null);
    setDetection(null);

    try {
      const res = await fetch("/api/targets/detect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: inputVal.trim() }),
      });
      if (!res.ok) {
        let errMsg = `Lỗi máy chủ (${res.status})`;
        try {
          const errData = await res.json();
          errMsg = errData.detail || errMsg;
        } catch {
          if (res.status === 502 || res.status === 504 || res.status === 500) {
            errMsg =
              "Không thể kết nối đến Backend Server (cổng 8000). Hãy đảm bảo bạn đã mở terminal chạy lệnh: python run.py dev";
          }
        }
        throw new Error(errMsg);
      }
      const data = await res.json();
      setDetection(data);
      if (data.recommended_tools && data.recommended_tools.length > 0) {
        setSelectedTools(data.recommended_tools);
      }
    } catch (err: any) {
      if (
        err.name === "TypeError" ||
        err.message.includes("JSON") ||
        err.message.includes("fetch")
      ) {
        setError(
          "Không thể kết nối đến Backend Server (cổng 8000). Hãy đảm bảo bạn đã mở terminal chạy lệnh: python run.py dev",
        );
      } else {
        setError(err.message);
      }
    } finally {
      setDetecting(false);
    }
  };

  const toggleTool = (toolId: string) => {
    const tid = toolId.toLowerCase();
    if (selectedTools.includes(tid)) {
      if (selectedTools.length <= 1) return; // Giữ ít nhất 1 tool
      setSelectedTools(selectedTools.filter((t) => t !== tid));
    } else {
      setSelectedTools([...selectedTools, tid]);
    }
  };

  const applyPreset = (preset: "default" | "network" | "web" | "services" | "all") => {
    if (preset === "default") {
      if (detection?.recommended_tools?.length) {
        setSelectedTools(detection.recommended_tools);
      } else {
        setSelectedTools(["naabu", "nmap"]);
      }
    } else if (preset === "network") {
      setSelectedTools(["naabu", "nmap", "rustscan", "masscan", "testssl", "theharvester"]);
    } else if (preset === "web") {
      setSelectedTools(["httpx", "whatweb", "nikto", "gobuster", "ffuf", "katana"]);
    } else if (preset === "services") {
      setSelectedTools(["enum4linux", "smbclient", "snmpwalk", "ldapsearch", "database"]);
    } else if (preset === "all") {
      setSelectedTools(ALL_SYSTEM_TOOLS.map((t) => t.id));
    }
  };

  const handleScan = async () => {
    if (!detection || !detection.scope.allowed) return;
    setScanning(true);
    appendTerminalLog(`[*] Initiating Recon Pipeline for: ${inputVal}`);
    if (selectedTools.length) {
      appendTerminalLog(`[*] Selected Tools (${selectedTools.length}): ${selectedTools.join(", ").toUpperCase()}`);
    }

    try {
      const res = await fetch("/api/recon/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: inputVal.trim(),
          tools: selectedTools.length ? selectedTools : undefined,
        }),
      });
      if (!res.ok) {
        let errMsg = `Lỗi máy chủ (${res.status})`;
        try {
          const errData = await res.json();
          errMsg = errData.detail || errMsg;
        } catch {
          if (res.status === 502 || res.status === 504 || res.status === 500) {
            errMsg =
              "Không thể kết nối đến Backend Server (cổng 8000). Hãy đảm bảo Backend đang chạy.";
          }
        }
        throw new Error(errMsg);
      }
      const data = await res.json();
      appendTerminalLog(
        `[+] Recon completed! Tools: ${data.manifest.tools_executed.join(", ")}`,
      );
      await fetchInitialData();
      setTargetModalOpen(false);
    } catch (err: any) {
      const msg = err.message.includes("JSON")
        ? "Không thể kết nối tới Backend (cổng 8000)"
        : err.message;
      appendTerminalLog(`[!] Error running scan: ${msg}`);
      setError(msg);
    } finally {
      setScanning(false);
    }
  };

  const filteredTools =
    activeCategory === "all"
      ? ALL_SYSTEM_TOOLS
      : ALL_SYSTEM_TOOLS.filter((t) => t.category === activeCategory);

  const getCategoryColor = (cat: string, isSelected: boolean) => {
    if (!isSelected) return "border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200";
    switch (cat) {
      case "network":
        return "border-cyan-500 bg-cyan-950/80 text-cyan-200 shadow-sm shadow-cyan-950";
      case "web":
        return "border-emerald-500 bg-emerald-950/80 text-emerald-200 shadow-sm shadow-emerald-950";
      case "vulnerability":
        return "border-amber-500 bg-amber-950/80 text-amber-200 shadow-sm shadow-amber-950";
      case "service_enum":
        return "border-purple-500 bg-purple-950/80 text-purple-200 shadow-sm shadow-purple-950";
      default:
        return "border-cyan-500 bg-cyan-950/80 text-cyan-200";
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-50 p-4">
      <div className="bg-[#0e1320] border border-[#1e293b] rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl shadow-black/80 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-3.5 bg-[#0c101c] border-b border-[#1e293b] flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-6 h-6 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
              <Sliders className="w-3.5 h-3.5" />
            </div>
            <h3 className="text-sm font-semibold text-zinc-100 tracking-wide">
              Dynamic Target Ingestion & Toolset Selection
            </h3>
          </div>
          <button
            onClick={() => setTargetModalOpen(false)}
            className="text-zinc-400 hover:text-zinc-200 p-1.5 rounded-lg hover:bg-[#151c2e] transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5 space-y-4 text-xs overflow-y-auto flex-1 bg-[#0e1320]">
          {/* Input Box */}
          <div>
            <label className="block text-zinc-300 mb-1.5 font-medium">
              Target Input (IP, URL, CIDR, Domain, Host:Port):
            </label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={inputVal}
                onChange={(e) => setInputVal(e.target.value)}
                placeholder="192.168.1.1, https://target.domain..."
                className="flex-1 bg-[#121829] border border-[#1e293b] rounded-xl px-3.5 py-2 text-zinc-100 focus:outline-none focus:border-cyan-500 font-mono text-xs shadow-inner"
              />
              <button
                onClick={handleDetect}
                disabled={detecting}
                className="bg-gradient-to-r from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500 text-white px-4 py-2 rounded-xl flex items-center space-x-1.5 font-medium transition shadow-sm shadow-cyan-950/50"
              >
                <Search className="w-3.5 h-3.5" />
                <span>{detecting ? "Detecting..." : "Detect"}</span>
              </button>
            </div>
          </div>

          {error && (
            <div className="bg-red-950/50 border border-red-800 text-red-300 p-3 rounded-lg flex items-start space-x-2">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Target Metadata if Detected */}
          {detection && (
            <div className="bg-zinc-900/90 border border-zinc-800 p-3.5 rounded-lg space-y-2 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div className="flex items-center space-x-2">
                  <span className="text-zinc-400">Target Type:</span>
                  <span className="text-cyan-400 font-bold uppercase font-mono">
                    {detection.target_type}
                  </span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-zinc-400">Normalized:</span>
                  <span className="text-zinc-200 font-mono truncate">
                    {detection.normalized_value}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-1 border-t border-zinc-800/80">
                <span className="text-zinc-400">Scope Authorization:</span>
                {detection.scope.allowed ? (
                  <span className="flex items-center space-x-1 text-emerald-400 font-medium">
                    <CheckCircle className="w-3.5 h-3.5" />
                    <span>Authorized ({detection.scope.matched_rule || "Allowed"})</span>
                  </span>
                ) : (
                  <span className="flex items-center space-x-1 text-red-400 font-medium">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>BLOCKED (Out of Scope)</span>
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Tool Selection Section */}
          <div className="border border-zinc-800 rounded-lg p-3.5 bg-zinc-900/40 space-y-3">
            {/* Header + Presets */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-2.5">
              <div className="flex items-center space-x-2">
                <span className="text-zinc-200 font-semibold text-xs">
                  Available Toolset
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-800">
                  {selectedTools.length} / {ALL_SYSTEM_TOOLS.length} selected
                </span>
              </div>

              {/* Presets buttons */}
              <div className="flex flex-wrap items-center gap-1">
                <button
                  type="button"
                  onClick={() => applyPreset("default")}
                  className="px-2 py-1 rounded text-[11px] bg-zinc-800 hover:bg-zinc-700 text-zinc-200 transition border border-zinc-700 font-medium"
                  title="Naabu + Nmap"
                >
                  ⚡ Default
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("network")}
                  className="px-2 py-1 rounded text-[11px] bg-zinc-800 hover:bg-cyan-950 hover:border-cyan-700 text-cyan-300 transition border border-zinc-700 font-medium"
                  title="Naabu, Nmap, RustScan, Masscan, TestSSL, theHarvester"
                >
                  🌐 Network (6)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("web")}
                  className="px-2 py-1 rounded text-[11px] bg-zinc-800 hover:bg-emerald-950 hover:border-emerald-700 text-emerald-300 transition border border-zinc-700 font-medium"
                  title="HTTPx, WhatWeb, Nikto, Gobuster, FFUF, Katana"
                >
                  🕸️ Web (6)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("services")}
                  className="px-2 py-1 rounded text-[11px] bg-zinc-800 hover:bg-purple-950 hover:border-purple-700 text-purple-300 transition border border-zinc-700 font-medium"
                  title="enum4linux, smbclient, snmpwalk, ldapsearch, database"
                >
                  🔍 Services (5)
                </button>
                <button
                  type="button"
                  onClick={() => applyPreset("all")}
                  className="px-2 py-1 rounded text-[11px] bg-zinc-800 hover:bg-indigo-950 hover:border-indigo-700 text-indigo-300 transition border border-zinc-700 font-bold"
                  title="Toàn bộ 20 công cụ của dự án"
                >
                  🚀 Select All (20)
                </button>
              </div>
            </div>

            {/* Category Filter Tabs */}
            <div className="flex items-center space-x-1 text-[11px]">
              <button
                type="button"
                onClick={() => setActiveCategory("all")}
                className={`px-2.5 py-1 rounded transition font-medium ${
                  activeCategory === "all"
                    ? "bg-zinc-700 text-white font-bold"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                }`}
              >
                All ({ALL_SYSTEM_TOOLS.length})
              </button>
              <button
                type="button"
                onClick={() => setActiveCategory("network")}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition font-medium ${
                  activeCategory === "network"
                    ? "bg-cyan-900/60 text-cyan-300 border border-cyan-700"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                }`}
              >
                <Radio className="w-3 h-3" />
                <span>Network (6)</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveCategory("web")}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition font-medium ${
                  activeCategory === "web"
                    ? "bg-emerald-900/60 text-emerald-300 border border-emerald-700"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                }`}
              >
                <Globe className="w-3 h-3" />
                <span>Web (6)</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveCategory("vulnerability")}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition font-medium ${
                  activeCategory === "vulnerability"
                    ? "bg-amber-900/60 text-amber-300 border border-amber-700"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                }`}
              >
                <ShieldCheck className="w-3 h-3" />
                <span>Vuln (3)</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveCategory("service_enum")}
                className={`flex items-center space-x-1 px-2.5 py-1 rounded transition font-medium ${
                  activeCategory === "service_enum"
                    ? "bg-purple-900/60 text-purple-300 border border-purple-700"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                }`}
              >
                <Server className="w-3 h-3" />
                <span>Services (5)</span>
              </button>
            </div>

            {/* Grid of Tools */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-56 overflow-y-auto pr-1">
              {filteredTools.map((tool) => {
                const isSelected = selectedTools.includes(tool.id);
                return (
                  <button
                    key={tool.id}
                    type="button"
                    onClick={() => toggleTool(tool.id)}
                    className={`flex items-start justify-between p-2 rounded-lg border text-left transition group ${getCategoryColor(
                      tool.category,
                      isSelected,
                    )}`}
                  >
                    <div className="flex-1 min-w-0 pr-2">
                      <div className="flex items-center space-x-1.5">
                        <span className="font-mono font-bold text-xs uppercase tracking-wide">
                          {tool.name}
                        </span>
                        <span className="text-[9px] px-1.5 py-0.2 rounded bg-black/40 text-zinc-400 border border-white/5 uppercase">
                          {tool.categoryLabel}
                        </span>
                      </div>
                      <p className="text-[10px] text-zinc-400 mt-0.5 truncate group-hover:text-zinc-300">
                        {tool.purpose}
                      </p>
                    </div>

                    <div
                      className={`w-5 h-5 rounded flex items-center justify-center flex-shrink-0 mt-0.5 border ${
                        isSelected
                          ? "bg-cyan-500 border-cyan-400 text-black font-bold"
                          : "border-zinc-700 bg-zinc-800 text-zinc-500 group-hover:border-zinc-500 group-hover:text-zinc-300"
                      }`}
                    >
                      {isSelected ? (
                        <Check className="w-3.5 h-3.5 stroke-[3]" />
                      ) : (
                        <Plus className="w-3.5 h-3.5 stroke-[2]" />
                      )}
                    </div>
                  </button>
                );
              })}
            </div>

            <p className="text-[10px] text-zinc-500 italic pt-1 border-t border-zinc-800/80">
              💡 Mẹo: Bạn có thể chọn bất kỳ công cụ nào. Nếu quét IP thô, ban đầu Nmap/Naabu sẽ dò cổng;
              khi phát hiện cổng mở (Web, SMB, v.v.), hệ thống sẽ tự động liên kết các công cụ phân tích sâu đã chọn.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 bg-[#0c101c] border-t border-[#1e293b] flex items-center justify-between text-xs">
          <button
            onClick={() => setTargetModalOpen(false)}
            className="px-4 py-2 rounded-lg hover:bg-[#151c2e] text-zinc-400 hover:text-zinc-200 transition font-medium"
          >
            Hủy bỏ (Cancel)
          </button>

          <button
            onClick={handleScan}
            disabled={!detection || !detection.scope.allowed || scanning}
            className={`flex items-center space-x-2 px-5 py-2.5 rounded-xl font-semibold transition shadow-md ${
              detection && detection.scope.allowed && !scanning
                ? "bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white shadow-emerald-950/60"
                : "bg-[#121829] text-zinc-500 cursor-not-allowed border border-[#1e293b]"
            }`}
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>
              {scanning
                ? "Đang thực thi Quét..."
                : `Xác nhận & Khởi chạy Quét (${selectedTools.length} công cụ)`}
            </span>
          </button>
        </div>
      </div>
    </div>
  );
};
