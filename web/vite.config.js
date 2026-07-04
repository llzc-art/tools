import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { copyFileSync, existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

/**
 * 复制 ONNX Runtime Web 的 jsep WASM/MJS 到 dist/assets/
 *
 * 为什么需要这个插件？
 *   onnxruntime-web 1.21 在 worker 内部以字符串拼接方式加载资源：
 *     `${wasmPaths}/ort-wasm-simd-threaded.jsep.mjs` （pthread proxy worker）
 *     `${wasmPaths}/ort-wasm-simd-threaded.jsep.wasm`（WASM 二进制）
 *   Vite 的静态分析无法跟踪这种动态拼接（运行时 new URL），
 *   也不会主动扫描 node_modules 中的 asset，因此这两个文件不会被打包到 dist。
 *
 *   当 worker 启动时，浏览器请求 `/assets/ort-wasm-simd-threaded.jsep.mjs`，
 *   后端找不到该文件 → SPA fallback 到 index.html (text/html) →
 *   "Failed to load module script: ... text/html" MIME 错误。
 *
 * 解决方案：构建结束后手动从 onnxruntime-web 包内复制这两个固定文件名的资源。
 *           配合 worker 中 `ort.env.wasm.wasmPaths = '/assets/'` 即可正确加载。
 */
function copyOrtWasmPlugin() {
  return {
    name: 'copy-ort-wasm',
    apply: 'build',
    closeBundle() {
      const ortDist = resolve(
        __dirname,
        'node_modules/onnxruntime-web/dist'
      )
      const targetDir = resolve(__dirname, 'dist/assets')
      const files = [
        'ort-wasm-simd-threaded.jsep.mjs',
        'ort-wasm-simd-threaded.jsep.wasm',
      ]
      for (const f of files) {
        const src = resolve(ortDist, f)
        const dst = resolve(targetDir, f)
        if (!existsSync(src)) {
          console.warn(`[copy-ort-wasm] source not found: ${src}`)
          continue
        }
        copyFileSync(src, dst)
        console.log(`[copy-ort-wasm] copied ${f}`)
      }
    },
  }
}

export default defineConfig({
  plugins: [vue(), copyOrtWasmPlugin()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: {
          'onnx-runtime': ['onnxruntime-web'],
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        // 关键：保留 wasm / mjs 资源的原始文件名（不带 hash）
        // 原因：onnxruntime-web 内部会以字符串拼接方式加载这些资源
        //      (`wasmPaths + 'ort-wasm-simd-threaded.jsep.{mjs,wasm}'`),
        //      文件名带 hash 会导致运行时 404 + SPA fallback → text/html → MIME 报错。
        assetFileNames: (assetInfo) => {
          const names = assetInfo.names || []
          const name = names[0] || assetInfo.name || ''
          if (/\.(wasm|mjs)$/.test(name)) {
            return 'assets/[name][extname]'
          }
          return 'assets/[name]-[hash][extname]'
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
    exclude: ['onnxruntime-web'],
  },
  // 不再把 wasm 标记为 asset（交给 Vite 默认的 import 解析 + assetFileNames 控制）
  worker: {
    format: 'es',
  },
})
