import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The dev server proxies the API to a local edr_server (python -m edr_server serve).
const api = process.env.EDR_API_URL ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": api,
      "/healthz": api,
    },
  },
  build: { outDir: "dist", sourcemap: false },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
