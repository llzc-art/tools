import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: {
          'onnx-runtime': ['@imgly/background-removal'],
        },
      },
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  optimizeDeps: {
    exclude: ['@imgly/background-removal'],
  },
  // 确保 WASM 和 ONNX 文件被正确处理
  assetsInclude: ['**/*.wasm', '**/*.onnx'],
})
