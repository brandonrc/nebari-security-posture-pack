/// <reference types="vitest/config" />
import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: true,
    port: 5173,
    proxy: process.env.VITE_API_MOCK
      ? undefined
      : { '/api': process.env.API_PROXY ?? 'http://localhost:8000' },
  },
  preview: { host: true, port: 4173 },
  build: {
    chunkSizeWarningLimit: 700,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (/recharts|d3-|victory-vendor|decimal\.js|es-toolkit|immer|reselect|@reduxjs|redux/.test(id)) return 'charts';
          if (/@base-ui|@floating-ui/.test(id)) return 'base-ui';
          if (/@tanstack/.test(id)) return 'tanstack';
          if (/lucide-react/.test(id)) return 'icons';
          if (/react-router|react-dom|scheduler|\/react\//.test(id)) return 'react';
          return 'vendor';
        },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
