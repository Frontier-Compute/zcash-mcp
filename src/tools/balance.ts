import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";
const API_TIMEOUT_MS = 15_000;

export function registerBalanceTool(server: McpServer) {
  server.tool(
    "get_balance",
    "Get attestation and anchor status for a wallet hash via ZAP1 API. Returns lifecycle events, leaf count, and verification links.",
    {
      wallet_hash: z.string().describe("Wallet hash or agent ID to look up"),
    },
    async ({ wallet_hash }) => {
      try {
        const safeHash = encodeURIComponent(wallet_hash);
        const res = await fetch(`${ZAP1_API}/lifecycle/${safeHash}`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        // Size-capped response: prevents OOM from large histories or malicious ZAP1_API_URL
        const text = await res.text();
        if (text.length > 1_048_576) throw new Error(`lifecycle response too large: ${text.length} bytes`);
        const data = JSON.parse(text);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data, null, 2),
            },
          ],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: "text" as const, text: `Error: ${msg}` }],
          isError: true,
        };
      }
    }
  );
}
