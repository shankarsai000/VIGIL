/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        vigil: {
          bg: '#030712', // Sleeker premium near-black
          bg2: '#080d1a', // Deep cosmic navy background
          card: '#0f172a', // Sleeker glass-like slate
          border: '#1e293b', // Modern dark border
          teal: '#00f2fe', // Electric neon cyan
          red: '#ff2a5f', // Electric crimson threat red
          amber: '#f59e0b', // Cyber warning amber
          text: '#f8fafc', // Ultra white for maximum readability
          muted: '#94a3b8', // Sophisticated slate-400 muted text
          cyan: '#00f0ff', // High-viz cyan
          purple: '#bc13fe', // Cyber purple
          navy: '#020617', // Terminal dark navy
          surface: 'rgba(15, 23, 42, 0.6)', // Glassmorphism backdrop-blur panel
          surface2: 'rgba(30, 41, 59, 0.8)', // Opaque glassmorphism panel
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Consolas', 'Monaco', 'Courier New', 'monospace'],
        sans: ['Outfit', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      animation: {
        'pulse-teal': 'pulseTeal 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'pulse-red': 'pulseRed 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.2s ease-out',
        'score-fill': 'scoreFill 0.8s ease-out forwards',
        'glow-pulse': 'glowPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 8s linear infinite',
        'ripple': 'ripple 1.5s cubic-bezier(0, 0, 0.2, 1) infinite',
        'node-ping': 'nodePing 2s cubic-bezier(0, 0, 0.2, 1) infinite',
        'border-flow': 'borderFlow 4s linear infinite',
      },
      keyframes: {
        pulseTeal: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
        pulseRed: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(255, 42, 95, 0.4)' },
          '50%': { boxShadow: '0 0 0 10px rgba(255, 42, 95, 0)' },
        },
        glowPulse: {
          '0%, 100%': { opacity: '0.8', filter: 'drop-shadow(0 0 4px var(--glow-color, #00f2fe))' },
          '50%': { opacity: '1', filter: 'drop-shadow(0 0 12px var(--glow-color, #00f2fe))' },
        },
        slideIn: {
          '0%': { transform: 'translateX(100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scoreFill: {
          '0%': { width: '0%' },
          '100%': { width: 'var(--score-width)' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        ripple: {
          '0%': { transform: 'scale(0.8)', opacity: '1' },
          '100%': { transform: 'scale(2.2)', opacity: '0' },
        },
        nodePing: {
          '0%': { transform: 'scale(1)', opacity: '0.8' },
          '50%': { transform: 'scale(1.2)', opacity: '0.3' },
          '100%': { transform: 'scale(1)', opacity: '0.8' },
        },
        borderFlow: {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
      },
    },
  },
  plugins: [],
}
