import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Send,
  Sparkles,
  ShieldAlert,
  ChevronRight,
  Layers,
  RotateCcw,
  User,
  Bot,
  Copy,
  Check,
  Loader2,
  PanelRightClose,
  Paperclip,
  FileText,
  FileCode,
  Image as ImageIcon,
  X,
  Maximize2,
  Download,
} from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";
import { MarkdownRenderer } from "./MarkdownRenderer";

interface ChatPanelProps {
  onClose?: () => void;
}

interface SourceItem {
  id?: number | string;
  source: string;
  title: string;
  url?: string;
  snippet?: string;
  score?: number;
}

export interface ChatAttachment {
  id: string;
  name: string;
  size: number;
  type: string;
  data: string;
  content?: string;
  url?: string;
}

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  attachments?: ChatAttachment[];
  sources?: SourceItem[];
  confidence?: number;
  nextSteps?: string[];
  isStreaming?: boolean;
}

interface ProviderInfo {
  id: string;
  name: string;
  active: boolean;
  ready: boolean;
}

export const ChatPanel: React.FC<ChatPanelProps> = ({ onClose }) => {
  const {
    activeTarget,
    openTabs,
    activeTabId,
    selectedProvider,
    setSelectedProvider,
  } = useWorkspaceStore();
  const activeTab = openTabs.find((t) => t.id === activeTabId);
  const activeFile = activeTab?.path;
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMsg, setInputMsg] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [conversationId, setConversationId] = useState<string>("conv_global");
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [activeProvider, setActiveProvider] = useState<string>("offline");
  const [copiedMsgId, setCopiedMsgId] = useState<string | null>(null);

  // Attachment states
  const [attachments, setAttachments] = useState<ChatAttachment[]>([]);
  const [isUploading, setIsUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [previewImage, setPreviewImage] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleCopyMessage = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedMsgId(id);
      setTimeout(() => setCopiedMsgId(null), 2000);
    } catch (err) {
      console.error("Failed to copy", err);
    }
  };

  // Upload helper for files and screenshots
  const uploadFile = async (file: File): Promise<ChatAttachment | null> => {
    const formData = new FormData();
    formData.append("file", file);
    try {
      const res = await fetch("/api/chat/upload", {
        method: "POST",
        body: formData,
      });
      if (res.ok) {
        const data: ChatAttachment = await res.json();
        return data;
      }
    } catch (err) {
      console.error("Upload error:", err);
    }

    // Client-side fallback if server upload endpoint is temporarily unavailable
    return new Promise((resolve) => {
      const reader = new FileReader();
      const isImg = file.type.startsWith("image/");
      if (isImg) {
        reader.onload = () => {
          resolve({
            id: `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            name: file.name,
            size: file.size,
            type: file.type || "image/png",
            data: reader.result as string,
          });
        };
        reader.onerror = () => resolve(null);
        reader.readAsDataURL(file);
      } else {
        reader.onload = () => {
          resolve({
            id: `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            name: file.name,
            size: file.size,
            type: file.type || "text/plain",
            data: "",
            content: reader.result as string,
          });
        };
        reader.onerror = () => resolve(null);
        reader.readAsText(file);
      }
    });
  };

  const handleAddFiles = async (newFiles: FileList | File[]) => {
    const fileList = Array.from(newFiles);
    if (fileList.length === 0) return;
    setIsUploading(true);
    try {
      const uploaded = await Promise.all(fileList.map((f) => uploadFile(f)));
      const valid = uploaded.filter((a): a is ChatAttachment => a !== null);
      setAttachments((prev) => [...prev, ...valid]);
    } finally {
      setIsUploading(false);
    }
  };

  const handleRemoveAttachment = (id: string) => {
    setAttachments((prev) => prev.filter((a) => a.id !== id));
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    if (e.clipboardData.files && e.clipboardData.files.length > 0) {
      e.preventDefault();
      handleAddFiles(e.clipboardData.files);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleAddFiles(e.dataTransfer.files);
    }
  };

  // Load target-isolated chat session
  const loadTargetSession = useCallback(async () => {
    const convId = activeTarget
      ? `target_${activeTarget.target_id}`
      : "conv_global";
    setConversationId(convId);
    try {
      const res = await fetch(`/api/chat/conversations/${convId}/messages`);
      if (res.ok) {
        const data = await res.json();
        if (data.messages && data.messages.length > 0) {
          setMessages(
            data.messages.map((m: any, idx: number) => ({
              id: `msg_${idx}_${m.created_at || Date.now()}`,
              role: m.role,
              content: m.content,
              attachments: m.attachments || [],
              sources: m.sources,
              confidence: m.confidence,
              nextSteps: m.classification?.next_steps || [],
            })),
          );
          return;
        }
      }
    } catch (err) {
      console.error("Failed to load target messages", err);
    }

    // Default welcome message per target session
    if (activeTarget) {
      setMessages([
        {
          id: `welcome_${convId}`,
          role: "assistant",
          content: `### 🎯 Phiên làm việc: **${activeTarget.name}**\n\n- **Địa chỉ:** \`${activeTarget.host || activeTarget.normalized_value}\`\n- **Môi trường:** \`${activeTarget.environment || "lab"}\`\n\nPhiên phân tích bảo mật đã sẵn sàng. Có thể truy vấn các cổng dịch vụ, đối soát CVE hoặc lập kế hoạch kiểm thử an toàn (*read-only*).`,
          nextSteps: [
            `Phân tích các cổng mở của ${activeTarget.name}`,
            `Có phát hiện lỗ hổng hay CVE nào trên ${activeTarget.host || activeTarget.normalized_value} không?`,
            `Tạo verification plan an toàn cho mục tiêu này`,
          ],
        },
      ]);
    } else {
      setMessages([
        {
          id: "welcome_default",
          role: "assistant",
          content:
            "### 🎯 Không gian Phân tích Bảo mật\n\nHệ thống đã sẵn sàng. Chọn một mục tiêu trong **Workspace Explorer** hoặc nhập câu hỏi trực tiếp để bắt đầu.",
          nextSteps: [
            "Apache 2.4.49 có CVE gì nguy hiểm?",
            "Phương pháp kiểm thử an toàn read-only",
            "Phân tích kết quả quét mạng từ Nmap",
          ],
        },
      ]);
    }
  }, [activeTarget?.target_id]);

  useEffect(() => {
    loadTargetSession();
  }, [loadTargetSession]);

  const handleClearSession = async () => {
    const convId = activeTarget
      ? `target_${activeTarget.target_id}`
      : "conv_global";
    try {
      await fetch(`/api/chat/conversations/${convId}`, { method: "DELETE" });
    } catch (e) {
      console.error("Failed to clear conversation", e);
    }
    loadTargetSession();
  };

  // Load LLM providers
  useEffect(() => {
    fetch("/api/llm/providers")
      .then((res) => res.json())
      .then((data) => {
        if (data.providers) setProviders(data.providers);
        if (data.active_provider) {
          setActiveProvider(data.active_provider);
          setSelectedProvider(data.active_provider);
        }
      })
      .catch(() => {
        // Fallback info if offline
        setProviders([
          {
            id: "gemini",
            name: "Google Gemini Flash",
            active: true,
            ready: true,
          },
          {
            id: "offline",
            name: "Local Security Reasoning",
            active: false,
            ready: true,
          },
        ]);
      });
  }, []);

  useEffect(() => {
    if (selectedProvider && selectedProvider !== activeProvider) {
      setActiveProvider(selectedProvider);
    }
  }, [selectedProvider]);

  const switchProvider = async (pId: string) => {
    try {
      const res = await fetch("/api/llm/switch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: pId }),
      });
      if (res.ok) {
        setActiveProvider(pId);
      }
    } catch (err) {
      console.error("Failed to switch provider", err);
    }
  };

  // Setup WebSocket connection
  const setupWebSocket = () => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "localhost:8000";
    const wsUrl = `${protocol}//${host}/ws/chat`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (evt) => {
      try {
        const payload = JSON.parse(evt.data);
        const { type, data, confidence, next_steps, conversation_id } = payload;

        if (conversation_id) {
          setConversationId(conversation_id);
        }

        if (type === "sources") {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === "assistant") {
              updated[lastIdx] = {
                ...updated[lastIdx],
                sources: data,
              };
            }
            return updated;
          });
        } else if (type === "chunk") {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === "assistant") {
              updated[lastIdx] = {
                ...updated[lastIdx],
                content: updated[lastIdx].content + data,
              };
            }
            return updated;
          });
        } else if (type === "done") {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === "assistant") {
              updated[lastIdx] = {
                ...updated[lastIdx],
                content: data,
                confidence: confidence,
                nextSteps: next_steps,
                isStreaming: false,
              };
            }
            return updated;
          });
          setIsSending(false);
        }
      } catch (e) {
        console.error("WS parse error", e);
      }
    };

    ws.onerror = () => {
      // WS error fallback handled on send
    };

    ws.onclose = () => {
      wsRef.current = null;
    };
  };

  useEffect(() => {
    setupWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const handleSendMessage = async (text: string) => {
    const trimmed = text.trim();
    if ((!trimmed && attachments.length === 0) || isSending) return;

    const currentAttachments = [...attachments];
    setAttachments([]);
    setInputMsg("");
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
    }
    setIsSending(true);

    const userMsgId = "u_" + Date.now();
    const botMsgId = "b_" + Date.now();

    const displayContent =
      trimmed ||
      (currentAttachments.length > 0
        ? `Đã gửi ${currentAttachments.length} tệp đính kèm`
        : "");

    setMessages((prev) => [
      ...prev,
      {
        id: userMsgId,
        role: "user",
        content: displayContent,
        attachments: currentAttachments,
      },
      { id: botMsgId, role: "assistant", content: "", isStreaming: true },
    ]);

    const payload = {
      message: trimmed || "Phân tích các tệp và ảnh đính kèm",
      target_id: activeTarget?.target_id || null,
      active_target:
        activeTarget?.normalized_value ||
        activeTarget?.host ||
        activeTarget?.name ||
        null,
      active_file: activeFile || null,
      active_file_content: activeTab?.content || null,
      conversation_id: conversationId,
      attachments: currentAttachments,
    };

    // Attempt WS first
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(payload));
    } else {
      // Reconnect WS or use HTTP REST fallback
      try {
        const res = await fetch("/api/chat/message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        setMessages((prev) => {
          const updated = [...prev];
          const lastIdx = updated.length - 1;
          if (lastIdx >= 0 && updated[lastIdx].id === botMsgId) {
            updated[lastIdx] = {
              ...updated[lastIdx],
              content: data.response || "No response",
              sources: data.sources || [],
              confidence: data.confidence,
              nextSteps: data.next_steps || [],
              isStreaming: false,
            };
          }
          return updated;
        });
        if (data.conversation_id) setConversationId(data.conversation_id);
      } catch (err) {
        setMessages((prev) => {
          const updated = [...prev];
          const lastIdx = updated.length - 1;
          if (lastIdx >= 0 && updated[lastIdx].id === botMsgId) {
            updated[lastIdx] = {
              ...updated[lastIdx],
              content:
                "⚠️ **Lỗi kết nối tới backend service.** Hãy đảm bảo server đang chạy trên cổng `http://127.0.0.1:8000`.",
              isStreaming: false,
            };
          }
          return updated;
        });
      } finally {
        setIsSending(false);
      }
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputMsg(e.target.value);
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${Math.min(
        textareaRef.current.scrollHeight,
        140,
      )}px`;
    }
  };

  return (
    <aside
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className="relative w-full bg-[#0e1320] border-l border-[#1e293b] flex flex-col h-full text-xs"
    >
      {/* Drag & Drop Overlay */}
      {isDragging && (
        <div className="absolute inset-0 z-50 bg-[#0c101ce6] backdrop-blur-sm border-2 border-dashed border-cyan-400 rounded-lg flex flex-col items-center justify-center space-y-2 pointer-events-none">
          <div className="w-12 h-12 rounded-2xl bg-cyan-950/80 border border-cyan-500 flex items-center justify-center text-cyan-300 animate-bounce shadow-lg shadow-cyan-950">
            <ImageIcon className="w-6 h-6" />
          </div>
          <p className="text-sm font-semibold text-cyan-300">Thả hình ảnh hoặc tệp vào đây</p>
          <p className="text-[11px] text-zinc-400">Hỗ trợ ảnh chụp màn hình, logs, kết quả Nmap, mã phân tích</p>
        </div>
      )}
      {/* Header */}
      <div className="p-3 border-b border-[#1e293b] flex items-center justify-between text-zinc-300 bg-[#0e1320]">
        <div className="flex items-center space-x-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold text-zinc-200 tracking-wide">
            AI-PENTEST COPILOT
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={handleClearSession}
            title="Làm mới / Xóa lịch sử phiên chat này"
            className="p-1 text-zinc-400 hover:text-zinc-200 hover:bg-[#151c2e] rounded transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <select
            value={activeProvider}
            onChange={(e) => {
              switchProvider(e.target.value);
              setSelectedProvider(e.target.value);
            }}
            className="bg-[#121829] text-cyan-300 font-medium border border-cyan-800/60 rounded-md px-2 py-1 text-[10px] focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            {providers.map((p) => (
              <option
                key={p.id}
                value={p.id}
                className="bg-[#0e1320] text-zinc-200"
              >
                {p.id === "gemini" ? "✨ Gemini Flash" : p.name.split(" ")[0]}{" "}
                {p.active ? "●" : ""}
              </option>
            ))}
          </select>
          {onClose && (
            <button
              onClick={onClose}
              title="Thu gọn panel Chat Copilot (Đóng vào)"
              className="p-1 text-zinc-400 hover:text-cyan-300 hover:bg-[#151c2e] rounded transition ml-0.5"
            >
              <PanelRightClose className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Target & Context Strip */}
      <div className="px-3 py-1.5 bg-[#0c101c] border-b border-[#1e293b] text-[11px] text-zinc-400 flex items-center justify-between">
        <div className="flex items-center space-x-1.5 truncate max-w-[200px]">
          <span className="text-zinc-500">Session:</span>
          <strong
            className="text-emerald-400 truncate font-mono text-[11px]"
            title={activeTarget?.host || activeTarget?.name}
          >
            {activeTarget?.name || "Chung"}
          </strong>
        </div>
        {activeFile && (
          <span
            className="truncate max-w-[130px] text-cyan-400 font-mono text-[10px] bg-[#121829] px-2 py-0.5 rounded border border-[#1e293b]"
            title={activeFile}
          >
            📄 {activeFile.split("/").pop()}
          </span>
        )}
      </div>

      {/* Message List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-4">
        {messages.length === 0 ? (
          /* Empty State & Starter Prompts */
          <div className="h-full flex flex-col items-center justify-center text-center p-4 select-none space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-cyan-950/60 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/40">
              <Sparkles className="w-6 h-6 animate-pulse" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-zinc-200">
                AI Pentest Copilot
              </h3>
              <p className="text-[11px] text-zinc-400 max-w-xs leading-relaxed">
                Trợ lý an ninh chuyên sâu hỗ trợ phân tích kết quả recon, đối chiếu CVE, đề xuất lệnh và lập verification plan.
              </p>
            </div>

            {activeTarget ? (
              <div className="text-[10px] text-zinc-400 bg-zinc-900/90 border border-zinc-800 px-2.5 py-1 rounded-full font-mono">
                🎯 Target: <span className="text-emerald-400 font-semibold">{activeTarget.host || activeTarget.name}</span>
              </div>
            ) : (
              <div className="text-[10px] text-zinc-500 bg-zinc-900/60 border border-zinc-800/60 px-2.5 py-1 rounded-full">
                💡 Chọn một target từ Explorer để có phân tích chính xác nhất
              </div>
            )}

            {/* Quick Starter Suggestions */}
            <div className="w-full space-y-1.5 pt-2">
              <div className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider text-left">
                Gợi ý câu hỏi:
              </div>
              {[
                "🔍 Tổng hợp các cổng và dịch vụ đang mở của target",
                "🛡️ Phân tích các CVE nguy hiểm nhất và mức độ rủi ro",
                "📋 Đề xuất lệnh quét nâng cao tiếp theo",
                "⚡ Lập kế hoạch xác thực (Verification Plan) an toàn",
              ].map((prompt, pIdx) => (
                <button
                  key={pIdx}
                  onClick={() => handleSendMessage(prompt)}
                  className="w-full text-left p-2 rounded-lg bg-zinc-900/80 hover:bg-zinc-800/90 border border-zinc-800 hover:border-cyan-800/60 text-zinc-300 hover:text-cyan-300 text-[11px] transition flex items-center justify-between group"
                >
                  <span className="truncate">{prompt}</span>
                  <ChevronRight className="w-3 h-3 text-zinc-600 group-hover:text-cyan-400 transition transform group-hover:translate-x-0.5" />
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((m) => {
            const isUser = m.role === "user";
            const isRefusal = m.content.includes("GUARDRAIL REFUSAL");

            if (isUser) {
              return (
                <div key={m.id} className="flex flex-col items-end space-y-1 pl-6">
                  <div className="flex items-center space-x-1.5 text-[10px] font-medium text-cyan-400 select-none">
                    <span>Pentester</span>
                    <div className="w-4 h-4 rounded-full bg-cyan-900/70 border border-cyan-700 flex items-center justify-center">
                      <User className="w-2.5 h-2.5 text-cyan-300" />
                    </div>
                  </div>

                  {/* Render attachments */}
                  {m.attachments && m.attachments.length > 0 && (
                    <div className="flex flex-wrap justify-end gap-2 max-w-[95%]">
                      {m.attachments.map((att) => {
                        const isImg =
                          att.type?.startsWith("image/") ||
                          (att.data && att.data.startsWith("data:image/"));
                        if (isImg) {
                          return (
                            <div
                              key={att.id}
                              onClick={() =>
                                setPreviewImage(att.data || att.url || "")
                              }
                              className="relative group cursor-pointer overflow-hidden rounded-lg border border-cyan-700/60 bg-black/40 shadow-sm max-w-[180px] max-h-[140px]"
                            >
                              <img
                                src={att.data || att.url}
                                alt={att.name}
                                className="w-full h-full object-cover transition transform group-hover:scale-105"
                              />
                              <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition flex items-center justify-center space-x-1 text-white">
                                <Maximize2 className="w-4 h-4 text-cyan-300" />
                              </div>
                              <div className="absolute bottom-0 inset-x-0 bg-gradient-to-t from-black/80 to-transparent p-1 text-[9px] text-zinc-300 truncate font-mono">
                                {att.name}
                              </div>
                            </div>
                          );
                        }
                        return (
                          <div
                            key={att.id}
                            className="flex items-center space-x-2 bg-cyan-950/80 border border-cyan-800/80 rounded-lg px-2.5 py-1.5 text-xs text-cyan-200 font-mono shadow-sm"
                          >
                            <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                            <span
                              className="truncate max-w-[160px] text-[11px]"
                              title={att.name}
                            >
                              {att.name}
                            </span>
                            <span className="text-[9px] text-cyan-400/70">
                              {(att.size / 1024).toFixed(1)} KB
                            </span>
                            {att.url && (
                              <a
                                href={att.url}
                                download={att.name}
                                target="_blank"
                                rel="noreferrer"
                                className="text-cyan-400 hover:text-cyan-200 ml-1"
                                title="Tải xuống tệp"
                              >
                                <Download className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {m.content && (
                    <div className="bg-cyan-950/70 border border-cyan-800/70 text-cyan-100 rounded-2xl rounded-tr-sm px-3.5 py-2.5 text-xs shadow-sm max-w-[95%] whitespace-pre-wrap leading-relaxed selection:bg-cyan-800">
                      {m.content}
                    </div>
                  )}
                </div>
              );
            }

            // Assistant Message
            return (
              <div key={m.id} className="flex flex-col space-y-1.5 pr-2">
                {/* Header with Avatar and Actions */}
                <div className="flex items-center justify-between text-[11px] select-none">
                  <div className="flex items-center space-x-1.5">
                    <div className="w-5 h-5 rounded-md bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center shadow-sm text-white">
                      <Bot className="w-3 h-3" />
                    </div>
                    <span className="font-semibold text-zinc-200">
                      AI Pentest Copilot
                    </span>
                    {m.confidence !== undefined && (
                      <span
                        className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-medium border ${m.confidence >= 0.8
                          ? "bg-emerald-950/60 text-emerald-400 border-emerald-800/60"
                          : m.confidence >= 0.5
                            ? "bg-amber-950/60 text-amber-400 border-amber-800/60"
                            : "bg-zinc-900 text-zinc-400 border-zinc-800"
                          }`}
                        title="Mức độ tin cậy của phân tích"
                      >
                        {(m.confidence * 100).toFixed(0)}% conf
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-1">
                    {m.content && !m.isStreaming && (
                      <button
                        onClick={() => handleCopyMessage(m.id, m.content)}
                        title="Sao chép toàn bộ câu trả lời"
                        className="p-1 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 rounded transition flex items-center space-x-1 text-[10px]"
                      >
                        {copiedMsgId === m.id ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Đã chép</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Sao chép</span>
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Content Container */}
                <div
                  className={`rounded-xl rounded-tl-sm p-3.5 text-xs transition-all shadow-sm ${isRefusal
                    ? "bg-red-950/40 border border-red-800/80 text-red-200"
                    : "bg-[#111827] border border-[#1e293b] text-zinc-200 shadow-md"
                    }`}
                >
                  {isRefusal ? (
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2 text-red-400 font-bold text-xs uppercase tracking-wide">
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                        <span>Chính sách an toàn từ chối (Guardrail Refusal)</span>
                      </div>
                      <div className="whitespace-pre-wrap text-red-300 text-xs leading-relaxed">
                        {m.content}
                      </div>
                    </div>
                  ) : m.content ? (
                    <div>
                      <MarkdownRenderer content={m.content} />
                      {m.isStreaming && (
                        <span className="inline-block w-1.5 h-3.5 ml-1 bg-cyan-400 animate-pulse align-middle" />
                      )}
                    </div>
                  ) : m.isStreaming ? (
                    <div className="flex items-center space-x-2 py-2 text-cyan-400 text-xs">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Đang suy luận bảo mật và đối chiếu bằng chứng...</span>
                    </div>
                  ) : null}

                  {/* Sources Citation Cards */}
                  {m.sources && m.sources.length > 0 && (
                    <div className="mt-3 pt-2.5 border-t border-[#1e293b] space-y-2">
                      <div className="text-[10px] font-semibold text-zinc-400 flex items-center justify-between">
                        <div className="flex items-center space-x-1.5">
                          <Layers className="w-3 h-3 text-cyan-400" />
                          <span>Nguồn bằng chứng trích dẫn ({m.sources.length}):</span>
                        </div>
                      </div>
                      <div className="grid grid-cols-1 gap-1.5">
                        {m.sources.map((s, sIdx) => (
                          <div
                            key={sIdx}
                            className="bg-[#0c101c] border border-[#1e293b] rounded-lg p-2 text-[10px] text-zinc-300 flex flex-col space-y-1"
                          >
                            <div className="flex items-center justify-between font-mono gap-1.5">
                              <span className="text-cyan-400 font-semibold truncate flex-1" title={s.title}>
                                [{sIdx + 1}] {s.title}
                              </span>
                              <div className="flex items-center space-x-1 shrink-0">
                                {s.source && (
                                  <span
                                    className={`text-[9px] px-1.5 py-0.2 rounded border font-sans font-medium ${s.source.toLowerCase().includes("dual")
                                      ? "bg-purple-950/80 text-purple-300 border-purple-700/70"
                                      : s.source.toLowerCase().includes("online") || s.source.toLowerCase().includes("osv")
                                        ? "bg-emerald-950/80 text-emerald-300 border-emerald-700/70"
                                        : "bg-[#151c2e] text-zinc-400 border-[#1e293b]"
                                      }`}
                                  >
                                    {s.source}
                                  </span>
                                )}
                                {s.score && (
                                  <span className="text-zinc-500 text-[9px] bg-[#121829] px-1 py-0.2 rounded border border-[#1e293b]">
                                    {(s.score * 100).toFixed(0)}% match
                                  </span>
                                )}
                              </div>
                            </div>
                            {s.snippet && (
                              <div className="text-zinc-400 text-[10px] line-clamp-2 leading-relaxed">
                                {s.snippet}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Next Steps Suggestions */}
                  {m.nextSteps && m.nextSteps.length > 0 && !m.isStreaming && (
                    <div className="mt-3 pt-2.5 border-t border-[#1e293b] space-y-1.5">
                      <div className="text-[10px] font-semibold text-zinc-400 flex items-center space-x-1">
                        <Sparkles className="w-3 h-3 text-cyan-400" />
                        <span>Đề xuất bước tiếp theo:</span>
                      </div>
                      <div className="flex flex-col space-y-1">
                        {m.nextSteps.map((step, idx) => (
                          <button
                            key={idx}
                            onClick={() => handleSendMessage(step)}
                            className="text-left text-[11px] bg-[#0c101c] hover:bg-[#151c2e] text-zinc-300 hover:text-cyan-300 py-1.5 px-2.5 rounded-lg border border-[#1e293b] hover:border-cyan-700/60 flex items-center justify-between transition group"
                          >
                            <span className="truncate">{step}</span>
                            <ChevronRight className="w-3 h-3 text-zinc-600 group-hover:text-cyan-400 transition" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage(inputMsg);
        }}
        className="p-3 border-t border-[#1e293b] bg-[#0c101c]"
      >
        {/* Pending attachments tray */}
        {attachments.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-2 p-2 bg-[#121829] border border-[#1e293b] rounded-lg max-h-36 overflow-y-auto">
            {attachments.map((att) => {
              const isImg =
                att.type?.startsWith("image/") ||
                (att.data && att.data.startsWith("data:image/"));
              return (
                <div
                  key={att.id}
                  className="relative group flex items-center space-x-1.5 bg-[#0e1320] border border-cyan-800/60 rounded-md px-2 py-1 text-xs text-zinc-200"
                >
                  {isImg ? (
                    <div className="w-7 h-7 rounded overflow-hidden bg-black/50 shrink-0 flex items-center justify-center border border-cyan-900/60">
                      <img
                        src={att.data || att.url}
                        alt={att.name}
                        className="w-full h-full object-cover"
                      />
                    </div>
                  ) : (
                    <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
                  )}
                  <div className="flex flex-col max-w-[120px]">
                    <span
                      className="truncate text-[11px] font-mono text-zinc-200"
                      title={att.name}
                    >
                      {att.name}
                    </span>
                    <span className="text-[9px] text-zinc-500">
                      {(att.size / 1024).toFixed(0)} KB
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRemoveAttachment(att.id)}
                    className="p-0.5 text-zinc-400 hover:text-red-400 hover:bg-zinc-800 rounded transition ml-1"
                    title="Xóa tệp này"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              );
            })}
          </div>
        )}

        <div className="relative flex flex-col bg-[#121829] border border-[#1e293b] rounded-xl focus-within:border-cyan-500 transition-colors shadow-inner">
          <textarea
            ref={textareaRef}
            rows={1}
            value={inputMsg}
            disabled={isSending}
            onChange={handleInputChange}
            onPaste={handlePaste}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSendMessage(inputMsg);
              }
            }}
            placeholder={
              isSending
                ? "Đang xử lý..."
                : attachments.length > 0
                  ? "Thêm mô tả hoặc nhấn gửi để phân tích tệp..."
                  : "Nhập câu lệnh . . ."
            }
            className="w-full bg-transparent px-3 py-2.5 text-zinc-100 placeholder-zinc-500 focus:outline-none text-xs resize-none max-h-36 leading-relaxed disabled:opacity-50 font-sans"
          />

          <div className="flex items-center justify-between px-2.5 pb-2 pt-0 select-none">
            {/* Left action: Paperclip button & hidden file input */}
            <div className="flex items-center space-x-1">
              <input
                ref={fileInputRef}
                type="file"
                multiple
                accept="image/*,.txt,.log,.nmap,.gnmap,.json,.py,.sh,.xml,.md,.pdf,.csv"
                onChange={(e) => {
                  if (e.target.files) {
                    handleAddFiles(e.target.files);
                    e.target.value = "";
                  }
                }}
                className="hidden"
              />
              <button
                type="button"
                disabled={isSending || isUploading}
                onClick={() => fileInputRef.current?.click()}
                title="Đính kèm hình ảnh hoặc tệp (Nmap, log, code...)"
                className="p-1.5 text-zinc-400 hover:text-cyan-400 hover:bg-[#151c2e] disabled:opacity-30 rounded-lg transition flex items-center space-x-1"
              >
                {isUploading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                ) : (
                  <Paperclip className="w-3.5 h-3.5" />
                )}
                <span className="text-[10px] hidden sm:inline text-zinc-400 hover:text-cyan-300">
                  {isUploading ? "Đang tải..." : "Đính kèm"}
                </span>
              </button>
            </div>

            {/* Right action: Send button */}
            <button
              type="submit"
              disabled={
                isSending || (!inputMsg.trim() && attachments.length === 0)
              }
              title="Gửi tin nhắn"
              className="bg-gradient-to-r from-cyan-600 to-teal-600 hover:from-cyan-500 hover:to-teal-500 disabled:opacity-30 text-white p-1.5 rounded-lg transition shadow-sm shadow-cyan-950 flex items-center justify-center"
            >
              {isSending ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Send className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Lightbox Image Preview Modal */}
      {previewImage && (
        <div
          onClick={() => setPreviewImage(null)}
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 cursor-pointer"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="relative max-w-4xl max-h-[90vh] bg-[#0c101c] border border-cyan-800/80 rounded-xl overflow-hidden shadow-2xl flex flex-col"
          >
            <div className="p-2 border-b border-[#1e293b] flex items-center justify-between bg-[#0e1320]">
              <span className="text-xs text-zinc-300 font-mono">
                Xem ảnh đính kèm
              </span>
              <button
                onClick={() => setPreviewImage(null)}
                className="p-1 text-zinc-400 hover:text-white rounded hover:bg-zinc-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="overflow-auto p-2 flex items-center justify-center max-h-[80vh]">
              <img
                src={previewImage}
                alt="Preview"
                className="max-w-full max-h-full object-contain rounded"
              />
            </div>
          </div>
        </div>
      )}
    </aside>
  );
};
