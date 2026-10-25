import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadConfig } from "../src/config.ts";
import { DEFAULT_HARNESS_CONFIG } from "../src/settings.ts";
import { prepareHarnessHome, baseHarnessEnv } from "../src/harness/sandbox.ts";
import { writeSessionResources } from "../src/harness/resources.ts";
import { runCommand } from "../src/harness/process.ts";

const dir = await mkdtemp(join(tmpdir(), "argus-native-mcp-"));
try {
  const fixture = join(dir, "fixture.ts");
  await writeFile(fixture, `let buffer='';
for await(const chunk of Bun.stdin.stream()) {
  buffer+=new TextDecoder().decode(chunk);
  while(buffer.includes('\\n')) {
    const index=buffer.indexOf('\\n'); const line=buffer.slice(0,index); buffer=buffer.slice(index+1);
    const request=JSON.parse(line); if(request.id===undefined) continue;
    const result=request.method==='initialize'
      ? {protocolVersion:request.params.protocolVersion,capabilities:{tools:{}},serverInfo:{name:'argus-fixture',version:'1.0'}}
      : request.method==='tools/list'
        ? {tools:[{name:'inspect',description:'Read-only local fixture',inputSchema:{type:'object',properties:{}}}]}
        : request.method==='resources/list' ? {resources:[]} : request.method==='prompts/list' ? {prompts:[]} : {};
    console.log(JSON.stringify({jsonrpc:'2.0',id:request.id,result}));
  }
}
`);
  const config = { ...loadConfig(), dataDir: dir };
  const home = prepareHarnessHome(config, "pi", "native-probe", DEFAULT_HARNESS_CONFIG.pi);
  writeSessionResources(home, "pi", { skills: [], servers: [{ id: "probe", key: "argus_probe", name: "fixture",
    connection: { type: "stdio", command: process.execPath, args: [fixture] } }] });
  const result = await runCommand([config.piBin, "mcp", "list", "--json"], {
    cwd: dir, env: { ...baseHarnessEnv("pi", {}), HOME: home }, timeoutMs: 20_000,
  });
  if (result.code !== 0 || result.timedOut) throw new Error(`Native Pi MCP fixture failed: ${result.stderr.slice(0, 1000)}`);
  const output = JSON.parse(result.stdout);
  const serialized = JSON.stringify(output);
  if (!serialized.includes("argus_probe") || !serialized.includes("inspect")) throw new Error("Native Pi did not discover the session-scoped fixture tool");
  console.log(JSON.stringify({ native_client: "Pi MCP", fixture_tool_detected: true, source: "temporary local stdio fixture", model_provider_called: false }, null, 2));
} finally { await rm(dir, { recursive: true, force: true }); }
