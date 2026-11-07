import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname || '.', '.'),
      },
    },
    build: {
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) {
              return 'vendor-react';
            }
            if (id.includes('node_modules/lucide-react/')) {
              return 'vendor-icons';
            }
            if (id.includes('node_modules/motion/')) {
              return 'vendor-motion';
            }
          },
        },
      },
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://127.0.0.1:8080',
          configure: (proxy) => {
            proxy.on('error', (err, _req, res) => {
              console.error('[proxy] backend unreachable on :8080 —', err.message);
              const response = res as import('http').ServerResponse;
              if (!response.headersSent) response.writeHead(502, { 'Content-Type': 'application/json' });
              response.end(JSON.stringify({ error: 'API server not running on :8080. Run `npm run dev:server`.' }));
            });
          },
        },
      },
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
