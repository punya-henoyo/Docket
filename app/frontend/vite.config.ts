import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output is served by engine/docket/interface/connect.py (frontend_dist()).
// In dev, /api and /auth proxy to that same server so the OAuth round-trip and the
// scan endpoints behave identically with hot-reload on.
const BACKEND = "http://127.0.0.1:7717";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: BACKEND, changeOrigin: false },
      "/auth": { target: BACKEND, changeOrigin: false },
      // ws:true, or the live-run stream silently fails under `npm run dev` while
      // working fine in the built console — the most confusing possible split.
      "/ws": { target: BACKEND.replace("http", "ws"), ws: true },
    },
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
