import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    allowedHosts: ['localhost', '127.0.0.1', 'forge-informed-trinity-bibliography.trycloudflare.com'],
    proxy: {
      '/observe': 'http://localhost:8000',
      '/agents': 'http://localhost:8000',
      '/incidents': 'http://localhost:8000',
      '/audit': 'http://localhost:8000',
      '/attack': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/telegram': 'http://localhost:8000',
      '/api': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
