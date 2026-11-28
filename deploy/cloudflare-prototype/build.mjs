import { build } from "esbuild";

await build({
  entryPoints: ["web/devices.ts", "web/device-details.ts"],
  outdir: ".build/ui",
  outExtension: { ".js": ".txt" },
  bundle: true,
  format: "esm",
  target: "es2022",
});
await build({
  entryPoints: ["worker.ts"],
  outfile: ".build/worker.mjs",
  bundle: true,
  format: "esm",
  target: "es2022",
  loader: { ".html": "text", ".css": "text", ".txt": "text" },
});
