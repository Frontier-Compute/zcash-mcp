#!/usr/bin/env node

import process from "node:process";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerBalanceTool } from "./tools/balance.js";
import { registerSendTool } from "./tools/send.js";
import { registerMemoTool } from "./tools/memo.js";
import { registerAttestTool } from "./tools/attest.js";
import { registerVerifyTool } from "./tools/verify.js";
import { registerStatsTool } from "./tools/stats.js";
import { registerChainTools } from "./tools/chain.js";
import { registerAnchorTools } from "./tools/anchors.js";
import { registerEventTools } from "./tools/events.js";
import { registerInvoiceTool } from "./tools/invoice.js";
import { registerWatchTool } from "./tools/watch.js";
import { registerReceiptTool } from "./tools/receipt.js";
import { registerIdentityTool } from "./tools/identity.js";
import { registerReputationTool } from "./tools/reputation.js";
import { registerCrosschainTool } from "./tools/crosschain.js";

const server = new McpServer({
  name: "zcash-mcp",
  version: "1.1.0",
});

registerBalanceTool(server);
registerSendTool(server);
registerMemoTool(server);
registerAttestTool(server);
registerVerifyTool(server);
registerStatsTool(server);
registerChainTools(server);
registerAnchorTools(server);
registerEventTools(server);
registerInvoiceTool(server);
registerWatchTool(server);
registerReceiptTool(server);
registerIdentityTool(server);
registerReputationTool(server);
registerCrosschainTool(server);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stdin.resume();
  console.error("zcash-mcp server running on stdio (18 tools)");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
