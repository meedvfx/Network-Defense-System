import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendHttp = process.env.VITE_BACKEND_URL || 'http://localhost:8000'
const backendWs = process.env.VITE_BACKEND_WS_URL || 'ws://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: backendHttp,
        changeOrigin: true,
      },
      '/ws': {
        target: backendWs,
        ws: true,
      },
    },
  },
})
