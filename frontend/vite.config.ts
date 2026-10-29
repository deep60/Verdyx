import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets"),
    },
  },
  root: path.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": {
        target: process.env.API_GATEWAY_URL || "http://localhost:8080",
        changeOrigin: true,
        rewrite: (reqPath: string) =>
          reqPath.startsWith("/api/v1") ? reqPath : reqPath.replace(/^\/api/, "/api/v1"),
      },
      "/ws": {
        target: process.env.WS_GATEWAY_URL || "ws://localhost:8080",
        ws: true,
      },
    },
    fs: {
      strict: true,
      deny: ["**/.*"],
    },
  },
});
