import React, { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Check, Play, Terminal as TerminalIcon, FileCode } from "lucide-react";
import { useWorkspaceStore } from "../../store/workspaceStore";

interface MarkdownRendererProps {
  content: string;
}

interface CodeBlockProps {
  language?: string;
  code: string;
}

const CodeBlock: React.FC<CodeBlockProps> = ({ language = "text", code }) => {
  const [copied, setCopied] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const { executeCommand } = useWorkspaceStore();

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy", err);
    }
  };

  const isExecutable = [
    "bash",
    "sh",
    "shell",
    "zsh",
    "cmd",
    "powershell",
    "nmap",
    "nuclei",
  ].includes(language.toLowerCase());

  const handleRunInTerminal = async () => {
    if (isRunning) return;
    setIsRunning(true);
    try {
      // Execute the trimmed command (or first line if multiline script)
      const cmdToRun = code.trim();
      await executeCommand(cmdToRun);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="my-2.5 rounded-md overflow-hidden border border-zinc-700/80 bg-[#0c0c0e] shadow-md">
      {/* Code Header Bar */}
      <div className="h-7 bg-[#16161a] border-b border-zinc-800 px-3 flex items-center justify-between text-[11px] text-zinc-400 select-none">
        <div className="flex items-center space-x-1.5 font-mono text-zinc-400">
          {isExecutable ? (
            <TerminalIcon className="w-3 h-3 text-cyan-400" />
          ) : (
            <FileCode className="w-3 h-3 text-zinc-400" />
          )}
          <span className="uppercase text-[10px] font-semibold text-zinc-300">
            {language}
          </span>
        </div>

        <div className="flex items-center space-x-1">
          {isExecutable && (
            <button
              onClick={handleRunInTerminal}
              disabled={isRunning}
              title="Chạy lệnh này trong Terminal"
              className="flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 transition disabled:opacity-50"
            >
              <Play className="w-2.5 h-2.5 fill-current" />
              <span>{isRunning ? "Đang chạy..." : "Chạy terminal"}</span>
            </button>
          )}

          <button
            onClick={handleCopy}
            title="Sao chép đoạn mã"
            className="flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-emerald-400" />
                <span className="text-emerald-400 font-medium">Đã chép</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Chép</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Code Content */}
      <pre className="p-3 overflow-x-auto text-[11px] font-mono leading-relaxed text-zinc-200 selection:bg-cyan-900/60">
        <code>{code}</code>
      </pre>
    </div>
  );
};

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({ content }) => {
  return (
    <div className="markdown-body font-sans text-xs text-zinc-300 leading-relaxed break-words">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          code({ className, children, ...props }) {
            const match = /language-(\w+)/.exec(className || "");
            const codeString = String(children).replace(/\n$/, "");
            const isInline = !match && !codeString.includes("\n");

            if (isInline) {
              return (
                <code
                  className="px-1.5 py-0.5 mx-0.5 rounded text-[11px] font-mono bg-zinc-800 text-cyan-300 border border-zinc-700/60"
                  {...props}
                >
                  {children}
                </code>
              );
            }

            return (
              <CodeBlock
                language={match ? match[1] : "text"}
                code={codeString}
              />
            );
          },
          h1({ children }) {
            return (
              <h1 className="text-sm font-bold text-zinc-100 mt-3 mb-1.5 pb-1 border-b border-zinc-800 flex items-center gap-1.5">
                {children}
              </h1>
            );
          },
          h2({ children }) {
            return (
              <h2 className="text-xs font-bold text-cyan-300 mt-2.5 mb-1 flex items-center gap-1.5">
                {children}
              </h2>
            );
          },
          h3({ children }) {
            return (
              <h3 className="text-xs font-semibold text-zinc-200 mt-2 mb-1">
                {children}
              </h3>
            );
          },
          p({ children }) {
            return <p className="my-1.5 leading-relaxed text-zinc-300">{children}</p>;
          },
          ul({ children }) {
            return (
              <ul className="list-disc pl-4 my-1.5 space-y-1 text-zinc-300">
                {children}
              </ul>
            );
          },
          ol({ children }) {
            return (
              <ol className="list-decimal pl-4 my-1.5 space-y-1 text-zinc-300">
                {children}
              </ol>
            );
          },
          li({ children }) {
            return <li className="leading-relaxed">{children}</li>;
          },
          blockquote({ children }) {
            return (
              <blockquote className="border-l-2 border-cyan-500/70 bg-zinc-900/60 pl-3 py-1 my-2 text-zinc-400 italic rounded-r">
                {children}
              </blockquote>
            );
          },
          table({ children }) {
            return (
              <div className="overflow-x-auto my-2 rounded border border-zinc-700/80">
                <table className="w-full text-left text-xs border-collapse">
                  {children}
                </table>
              </div>
            );
          },
          thead({ children }) {
            return <thead className="bg-[#18181c] border-b border-zinc-700/80">{children}</thead>;
          },
          th({ children }) {
            return (
              <th className="p-2 font-semibold text-zinc-200 border-r border-zinc-800 last:border-r-0">
                {children}
              </th>
            );
          },
          td({ children }) {
            return (
              <td className="p-2 text-zinc-300 border-t border-r border-zinc-800/80 last:border-r-0 bg-zinc-900/30">
                {children}
              </td>
            );
          },
          a({ href, children }) {
            return (
              <a
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 transition-colors font-medium"
              >
                {children}
              </a>
            );
          },
          strong({ children }) {
            return <strong className="font-semibold text-zinc-100">{children}</strong>;
          },
          hr() {
            return <hr className="my-3 border-zinc-800" />;
          },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
};
