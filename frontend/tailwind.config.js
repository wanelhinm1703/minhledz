/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        serif: ['"Times New Roman"', 'Times', 'serif'],
      },
      colors: {
        ide: {
          bg: "#0a0d14",
          sidebar: "#0e1320",
          panel: "#121829",
          border: "#1e293b",
          accent: "#06b6d4",
          text: "#e2e8f0",
          muted: "#64748b"
        },
        cyber: {
          bg: "#0a0d14",
          canvas: "#070a10",
          sidebar: "#0e1320",
          panel: "#121829",
          card: "#151c2e",
          cardHover: "#1c253d",
          border: "#1e293b",
          borderLight: "#2a374f",
          accent: "#06b6d4",
          glow: "#22d3ee",
          emerald: "#10b981",
          rose: "#ef4444",
          amber: "#f59e0b"
        }
      },
      boxShadow: {
        'glow-cyan': '0 0 15px -3px rgba(6, 182, 212, 0.35)',
        'glow-emerald': '0 0 15px -3px rgba(16, 185, 129, 0.35)',
        'glow-red': '0 0 15px -3px rgba(239, 68, 68, 0.35)',
      }
    },
  },
  plugins: [],
}
