import React, { useState, useEffect, useRef } from 'react'
import { MessageSquare, Send, Sparkles, ShieldAlert, CheckCircle2, ChevronRight, RefreshCw, Layers } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

interface SourceItem {
  id?: number | string;
  source: string;
  title: string;
  url?: string;
  snippet?: string;
  score?: number;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
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

export const ChatPanel: React.FC = () => {
  const { activeTarget, openTabs, activeTabId, selectedProvider, setSelectedProvider } = useWorkspaceStore();
  const activeTab = openTabs.find((t) => t.id === activeTabId);
  const activeFile = activeTab?.path;
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content:
        'Xin chào! Tôi là AI-Pentest Copilot. Tôi tuân thủ nguyên tắc an toàn: không tự động khai thác, đối sánh CVE chính xác từ KB, và cung cấp verification plan an toàn (read-only).',
      nextSteps: [
        'Apache 2.4.49 có CVE gì?',
        'Hướng dẫn safe read-only verification cho target',
        'Phân tích file kết quả scan',
      ],
    },
  ]);
  const [inputMsg, setInputMsg] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [providers, setProviders] = useState<ProviderInfo[]>([]);
  const [activeProvider, setActiveProvider] = useState<string>('offline');

  const wsRef = useRef<WebSocket | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // Load LLM providers
  useEffect(() => {
    fetch('/api/llm/providers')
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
          { id: 'gemini', name: 'Google Gemini Flash', active: true, ready: true },
          { id: 'offline', name: 'Local Security Reasoning', active: false, ready: true },
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
      const res = await fetch('/api/llm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: pId }),
      });
      if (res.ok) {
        setActiveProvider(pId);
      }
    } catch (err) {
      console.error('Failed to switch provider', err);
    }
  };

  // Setup WebSocket connection
  const setupWebSocket = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:8000';
    // In dev Vite proxy or direct backend
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

        if (type === 'sources') {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === 'assistant') {
              updated[lastIdx] = {
                ...updated[lastIdx],
                sources: data,
              };
            }
            return updated;
          });
        } else if (type === 'chunk') {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === 'assistant') {
              updated[lastIdx] = {
                ...updated[lastIdx],
                content: updated[lastIdx].content + data,
              };
            }
            return updated;
          });
        } else if (type === 'done') {
          setMessages((prev) => {
            const updated = [...prev];
            const lastIdx = updated.length - 1;
            if (lastIdx >= 0 && updated[lastIdx].role === 'assistant') {
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
        console.error('WS parse error', e);
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
    if (!trimmed || isSending) return;

    setInputMsg('');
    setIsSending(true);

    const userMsgId = 'u_' + Date.now();
    const botMsgId = 'b_' + Date.now();

    setMessages((prev) => [
      ...prev,
      { id: userMsgId, role: 'user', content: trimmed },
      { id: botMsgId, role: 'assistant', content: '', isStreaming: true },
    ]);

    const payload = {
      message: trimmed,
      active_target: activeTarget?.normalized_value || activeTarget?.host || activeTarget?.name || null,
      active_file: activeFile || null,
      conversation_id: conversationId,
    };

    // Attempt WS first
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(payload));
    } else {
      // Reconnect WS or use HTTP REST fallback
      try {
        const res = await fetch('/api/chat/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        setMessages((prev) => {
          const updated = [...prev];
          const lastIdx = updated.length - 1;
          if (lastIdx >= 0 && updated[lastIdx].id === botMsgId) {
            updated[lastIdx] = {
              ...updated[lastIdx],
              content: data.response || 'No response',
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
              content: 'Lỗi kết nối tới backend service. Hãy đảm bảo server đang chạy trên cổng 8000.',
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

  return (
    <aside className="w-96 bg-[#121214] border-l border-[#27272a] flex flex-col h-full text-xs">
      {/* Header */}
      <div className="p-3 border-b border-[#27272a] flex items-center justify-between text-zinc-300">
        <div className="flex items-center space-x-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="font-semibold text-zinc-200">AI-PENTEST COPILOT</span>
        </div>
        <select
          value={activeProvider}
          onChange={(e) => {
            switchProvider(e.target.value);
            setSelectedProvider(e.target.value);
          }}
          className="bg-zinc-900 text-cyan-300 font-medium border border-cyan-800/80 rounded px-1.5 py-0.5 text-[10px] focus:outline-none focus:border-cyan-500 cursor-pointer"
        >
          {providers.map((p) => (
            <option key={p.id} value={p.id} className="bg-zinc-900 text-zinc-200">
              {p.id === 'gemini' ? '✨ Gemini Flash' : p.name.split(' ')[0]} {p.active ? '●' : ''}
            </option>
          ))}
        </select>
      </div>

      {/* Target & Context Strip */}
      <div className="px-3 py-1.5 bg-[#18181c] border-b border-[#27272a] text-[11px] text-zinc-400 flex items-center justify-between">
        <span className="truncate max-w-[180px]">
          Target: <strong className="text-emerald-400">{activeTarget?.name || 'None'}</strong>
        </span>
        {activeFile && (
          <span className="truncate max-w-[120px] text-zinc-500 font-mono text-[10px]">
            {activeFile.split('/').pop()}
          </span>
        )}
      </div>

      {/* Message List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.map((m) => {
          const isUser = m.role === 'user';
          const isRefusal = m.content.includes('GUARDRAIL REFUSAL');

          return (
            <div
              key={m.id}
              className={`p-3 rounded-lg text-xs leading-relaxed transition-all ${
                isUser
                  ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-200 ml-4'
                  : isRefusal
                  ? 'bg-red-950/40 border border-red-800/80 text-red-200 mr-4'
                  : 'bg-zinc-900/90 border border-zinc-800 text-zinc-200 mr-4'
              }`}
            >
              <div className="flex items-center justify-between text-[10px] font-bold text-zinc-500 mb-1.5 uppercase">
                <span className="flex items-center space-x-1">
                  {isRefusal ? (
                    <ShieldAlert className="w-3 h-3 text-red-400" />
                  ) : isUser ? (
                    <span>Pentester</span>
                  ) : (
                    <span>Copilot</span>
                  )}
                </span>
                {m.confidence !== undefined && (
                  <span className="text-emerald-400 font-mono">
                    conf: {(m.confidence * 100).toFixed(0)}%
                  </span>
                )}
              </div>

              {/* Message Content */}
              <div className="whitespace-pre-wrap font-sans text-xs">
                {m.content || (m.isStreaming ? 'Đang suy luận...' : '')}
              </div>

              {/* Sources Citation Cards */}
              {m.sources && m.sources.length > 0 && (
                <div className="mt-2.5 pt-2 border-t border-zinc-800/80 space-y-1.5">
                  <div className="text-[10px] font-semibold text-zinc-400 flex items-center space-x-1">
                    <Layers className="w-3 h-3 text-cyan-400" />
                    <span>Citations & Evidence Sources ({m.sources.length}):</span>
                  </div>
                  <div className="space-y-1">
                    {m.sources.map((s, sIdx) => (
                      <div
                        key={sIdx}
                        className="bg-black/40 border border-zinc-800 rounded p-1.5 text-[10px] text-zinc-300 flex flex-col"
                      >
                        <div className="flex items-center justify-between font-mono">
                          <span className="text-cyan-400 font-bold">[{sIdx + 1}] {s.title}</span>
                          {s.score && (
                            <span className="text-zinc-500">{(s.score * 100).toFixed(0)}%</span>
                          )}
                        </div>
                        {s.snippet && (
                          <div className="text-zinc-400 text-[10px] mt-0.5 line-clamp-2">
                            {s.snippet}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Next Steps Buttons */}
              {m.nextSteps && m.nextSteps.length > 0 && !m.isStreaming && (
                <div className="mt-2.5 pt-2 border-t border-zinc-800/80 space-y-1">
                  <div className="text-[10px] font-semibold text-zinc-400">Đề xuất tiếp theo:</div>
                  <div className="flex flex-col space-y-1">
                    {m.nextSteps.map((step, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleSendMessage(step)}
                        className="text-left text-[11px] bg-zinc-800/60 hover:bg-zinc-800 text-zinc-300 hover:text-cyan-300 py-1 px-2 rounded border border-zinc-700/50 flex items-center justify-between transition"
                      >
                        <span>{step}</span>
                        <ChevronRight className="w-3 h-3 text-zinc-500" />
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage(inputMsg);
        }}
        className="p-2.5 border-t border-[#27272a] bg-[#141416]"
      >
        <div className="flex items-center space-x-1.5">
          <input
            type="text"
            value={inputMsg}
            disabled={isSending}
            onChange={(e) => setInputMsg(e.target.value)}
            placeholder={
              isSending ? 'Đang phản hồi...' : 'Hỏi về scan, CVE, verification plan...'
            }
            className="flex-1 bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isSending || !inputMsg.trim()}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white p-1.5 rounded transition"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </aside>
  );
};
