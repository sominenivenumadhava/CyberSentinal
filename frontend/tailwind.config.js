/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: "#0b0f19",
          800: "#111827",
          700: "#1f2937",
          accent: "#00f0ff",
          danger: "#ff3366",
          warning: "#ffaa00",
          success: "#00ff66"
        }
      }
    },
  },
  plugins: [],
}

