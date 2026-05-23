import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const API_TIMEOUT_MS = 15_000;

export function registerAnchorTools(server: McpServer) {
  server.tool(
    "get_anchor_history",
    "Get all ZAP1 Merkle root anchors with Zcash txids and block heights.",
    {},
    async () => {
      try {
        const res = await fetch(`${ZAP1_API}/anchor/history`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(await res.json(), null, 2) }],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  server.tool(
    "get_anchor_status",
    "Get current ZAP1 Merkle tree state: root hash, unanchored leaves, anchor recommendation.",
    {},
    async () => {
      try {
        const res = await fetch(`${ZAP1_API}/anchor/status`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(await res.json(), null, 2) }],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
