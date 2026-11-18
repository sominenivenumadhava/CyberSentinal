/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          DEFAULT: "#14213d",
          dark: "#0b1222",
          surface: "#101b33",
          card: "#19294b",
          light: "#223763",
          border: "#2b457c",
        },
        cream: {
          DEFAULT: "#f4eded",
          pure: "#ffffff",
          muted: "#ded3d3",
          dim: "#b8abab",
          faint: "rgba(244, 237, 237, 0.08)",
          border: "rgba(244, 237, 237, 0.18)",
        },
        coral: {
          DEFAULT: "#ff6b5b",
          hover: "#ff5340",
          light: "#ff8c80",
          dim: "#c94f42",
          bg: "rgba(255, 107, 91, 0.12)",
          border: "rgba(255, 107, 91, 0.4)",
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
