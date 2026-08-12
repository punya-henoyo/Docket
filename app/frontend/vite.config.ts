import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` serves the UI on 5173 and forwards data calls to the FastAPI backend
// on 7717, so the two run independently during development. `npm run build` emits
// dist/, which the backend mounts itself — one process, one port, for the demo.
export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:7717", changeOrigin: true },
      "/ws": { target: "ws://127.0.0.1:7717", ws: true },
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
  plugins: [react()],
});
