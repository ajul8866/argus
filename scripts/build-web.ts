export {};
import { relative } from "node:path";
import { rmSync } from "node:fs";

rmSync("web/dist/assets", { recursive: true, force: true });
const result = await Bun.build({
  entrypoints: ["web/src/main.ts"],
  outdir: "web/dist/assets",
  target: "browser",
  format: "esm",
  minify: true,
  sourcemap: "external",
  naming: "[name]-[hash].[ext]",
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}

let script = "";
let stylesheet = "";
for (const output of result.outputs) {
  const path = relative("web/dist", output.path).replaceAll("\\", "/");
  if (path.endsWith(".js")) script = `/${path}`;
  if (path.endsWith(".css")) stylesheet = `/${path}`;
}
if (!script) {
  console.error("No JavaScript bundle produced");
  process.exit(1);
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="description" content="Argus self-hosted autonomous multi-agent source code security audit platform">
<title>Argus | Autonomous Security Audit</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='10' fill='%23151619'/%3E%3Cpath d='M20 44 L32 18 L44 44' fill='none' stroke='%23f2c56b' stroke-width='3'/%3E%3Cpath d='M25 36 H39' stroke='%23f2c56b' stroke-width='3'/%3E%3C/svg%3E">
${stylesheet ? `<link rel="stylesheet" href="${stylesheet}">` : ""}
</head>
<body>
<div id="app"></div>
<script type="module" src="${script}"></script>
</body>
</html>
`;

await Bun.write("web/dist/index.html", html);
console.log(`Built web dashboard: ${script}${stylesheet ? `, ${stylesheet}` : ""}`);
