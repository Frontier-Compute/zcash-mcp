#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerBalanceTool } from "./tools/balance.js";
import { registerSendTool } from "./tools/send.js";
import { registerMemoTool } from "./tools/memo.js";
import { registerAttestTool } from "./tools/attest.js";
import { registerVerifyTool } from "./tools/verify.js";
import { registerStatsTool } from "./tools/stats.js";
import { registerChainTools } from "./tools/chain.js";

const server = new McpServer({
  name: "zcash-mcp",
  version: "0.1.0",
});

// Register all tools
registerBalanceTool(server);
registerSendTool(server);
registerMemoTool(server);
registerAttestTool(server);
registerVerifyTool(server);
registerStatsTool(server);
registerChainTools(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("zcash-mcp server running on stdio");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
