/// <reference types="vitest" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: process.env.VITE_ALLOWED_HOSTS
      ? process.env.VITE_ALLOWED_HOSTS.split(',')
      : ['localhost', '127.0.0.1'],
    proxy: {
      '/observe': 'http://127.0.0.1:8000',
      '/agents': 'http://127.0.0.1:8000',
      '/incidents': 'http://127.0.0.1:8000',
      '/audit': 'http://127.0.0.1:8000',
      '/attack': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
      '/telegram': 'http://127.0.0.1:8000',
      '/api': 'http://127.0.0.1:8000',
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
        configure: (proxy, _options) => {
          proxy.on('error', (err: any) => {
            // Suppress unhandled ECONNRESET when backend restarts or client reconnects
            if (err?.code !== 'ECONNRESET') {
              console.warn('[Vite Proxy Warning]', err?.message || err);
            }
          });
        },
      },
    },
  },
})
