/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          darker: "#050811",
          card: "#0b1120",
          border: "#1e293b",
          primary: "#0ea5e9",
          neon: "#06b6d4",
          success: "#10b981",
          warning: "#f59e0b",
          danger: "#ef4444"
        }
      }
    },
  },
  plugins: [],
}
