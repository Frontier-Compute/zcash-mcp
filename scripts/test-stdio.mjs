import path from "node:path";
import { fileURLToPath } from "node:url";

import { runMcpSmokeTest } from "./test-client.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

await runMcpSmokeTest(path.join(repoRoot, "dist", "index.js"), {
  cwd: repoRoot,
  label: "workspace build",
});

console.log("workspace build: MCP stdio smoke passed");
