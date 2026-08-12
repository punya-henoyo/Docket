import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output is served by engine/docket/interface/connect.py (frontend_dist()).
// In dev, /api and /auth proxy to that same server so the OAuth round-trip and the
// scan endpoints behave identically with hot-reload on.
const BACKEND = "http://127.0.0.1:8765";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: BACKEND, changeOrigin: false },
      "/auth": { target: BACKEND, changeOrigin: false },
    },
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
