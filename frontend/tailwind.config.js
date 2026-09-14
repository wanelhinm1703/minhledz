/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        ide: {
          bg: "#18181b",
          sidebar: "#121214",
          panel: "#1e1e24",
          border: "#27272a",
          accent: "#0284c7",
          text: "#e4e4e7",
          muted: "#71717a"
        }
      }
    },
  },
  plugins: [],
}
