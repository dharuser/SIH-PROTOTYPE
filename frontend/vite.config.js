import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dev server proxies both the REST API and the WebSocket to the FastAPI
// backend on port 8000. That keeps the frontend same-origin, so there are no
// CORS surprises and the browser can just open ws://localhost:5173/ws.
export default defineConfig({
  plugins: [react()],
  // An inline (empty) PostCSS config stops Vite from searching parent
  // directories for one. Without this, any stray postcss.config.* sitting
  // higher up the drive gets picked up and breaks the build.
  css: {
    postcss: {},
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
