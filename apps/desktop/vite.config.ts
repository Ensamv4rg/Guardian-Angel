import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { execFile } from "node:child_process";
import { resolve } from "node:path";

/**
 * Development only: lets the UI run in a normal browser against the real,
 * running service. POST /__ipc {method, params} is relayed through
 * `guardian service <method> [params]`. Never part of a build.
 */
function devServiceBridge(): Plugin {
  const cli = resolve(__dirname, "../../target/release/guardian.exe");
  return {
    name: "guardian-dev-service-bridge",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/__ipc", (req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          let method = "";
          let params: unknown = undefined;
          try {
            ({ method, params } = JSON.parse(body));
          } catch {
            res.statusCode = 400;
            return res.end(JSON.stringify({ error: "bad request" }));
          }
          if (!/^[a-z_]+$/.test(method)) {
            res.statusCode = 400;
            return res.end(JSON.stringify({ error: "bad method" }));
          }
          const args = ["service", method];
          if (params !== undefined) args.push(JSON.stringify(params));
          execFile(cli, args, { maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
            res.setHeader("content-type", "application/json");
            if (err) {
              res.statusCode = 502;
              return res.end(JSON.stringify({ error: (stderr || err.message).trim() }));
            }
            res.end(JSON.stringify({ result: JSON.parse(stdout || "null") }));
          });
        });
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), devServiceBridge()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2022", outDir: "dist" },
});
