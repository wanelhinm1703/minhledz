import React, { useState } from 'react'
import { MessageSquare, Send, Sparkles, BookOpen } from 'lucide-react'
import { useWorkspaceStore } from '../../store/workspaceStore'

export const ChatPanel: React.FC = () => {
  const { activeTarget, selectedProvider } = useWorkspaceStore();
  const [messages, setMessages] = useState<Array<{ role: string; text: string }>>([
    {
      role: 'assistant',
      text: 'Xin chào! Tôi là AI-Pentest Copilot. Tôi có thể hỗ trợ phân tích kết quả quét, tra cứu CVE/CWE, đối sánh phiên bản và đề xuất verification steps an toàn.',
    },
  ]);
  const [inputMsg, setInputMsg] = useState('');

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMsg.trim()) return;

    const userText = inputMsg.trim();
    setInputMsg('');
    setMessages((prev) => [...prev, { role: 'user', text: userText }]);

    // Simulated responsive message for M3 skeleton (M4 brings full RAG + WebSocket stream)
    setTimeout(() => {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: `[Context: ${activeTarget?.name || 'No target'}] Đã ghi nhận câu hỏi. Hệ thống ContextEngine và RAG sẽ trực tiếp stream câu trả lời kèm source citation ở Milestone M4 qua WebSocket.`,
        },
      ]);
    }, 600);
  };

  return (
    <aside className="w-80 bg-[#121214] border-l border-[#27272a] flex flex-col h-full text-xs">
      {/* Chat Header */}
      <div className="p-3 border-b border-[#27272a] flex items-center justify-between text-zinc-300 font-semibold">
        <div className="flex items-center space-x-2">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span>IDE COPILOT</span>
        </div>
        <span className="text-[10px] text-zinc-500 uppercase">{selectedProvider}</span>
      </div>

      {/* Context Badge */}
      <div className="px-3 py-1.5 bg-[#18181c] border-b border-[#27272a] text-[11px] text-zinc-400 flex items-center justify-between">
        <span>Target: <strong className="text-emerald-400">{activeTarget?.name || 'None'}</strong></span>
        <span className="text-zinc-500">M4 Ready</span>
      </div>

      {/* Message List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`p-2.5 rounded-lg text-xs leading-relaxed ${
              m.role === 'user'
                ? 'bg-cyan-950/70 border border-cyan-800/80 text-cyan-200 ml-4'
                : 'bg-zinc-900 border border-zinc-800 text-zinc-300 mr-4'
            }`}
          >
            <div className="text-[10px] font-bold text-zinc-500 mb-1 uppercase">
              {m.role === 'user' ? 'Pentester' : 'AI Copilot'}
            </div>
            <p className="whitespace-pre-wrap">{m.text}</p>
          </div>
        ))}
      </div>

      {/* Chat Input */}
      <form onSubmit={handleSend} className="p-2.5 border-t border-[#27272a] bg-[#141416]">
        <div className="flex items-center space-x-1.5">
          <input
            type="text"
            value={inputMsg}
            onChange={(e) => setInputMsg(e.target.value)}
            placeholder="Hỏi về scan, CVE, verification steps..."
            className="flex-1 bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1.5 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs"
          />
          <button
            type="submit"
            className="bg-cyan-600 hover:bg-cyan-500 text-white p-1.5 rounded transition"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </div>
      </form>
    </aside>
  );
};
