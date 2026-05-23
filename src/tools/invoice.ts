import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const API_TIMEOUT_MS = 15_000;

export function registerInvoiceTool(server: McpServer) {
  server.tool(
    "zap1_create_receipt_invoice",
    "Create ZAP1 receipt metadata for an external payment workflow. Returns invoice metadata for later receipt verification; this server does not sign, scan, or broadcast.",
    {
      amount_zat: z.number().int().positive().describe("Payment amount in zatoshis (1 ZEC = 100_000_000 zatoshis)"),
      memo: z.string().max(512).describe("Memo text attached to the invoice (max 512 bytes)"),
      wallet_hash: z.string().max(128).describe("Wallet identifier or hash for routing the payment"),
    },
    async ({ amount_zat, memo, wallet_hash }) => {
      try {
        const res = await fetch(`${ZAP1_API}/invoice`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ amount_zat, memo, wallet_hash }),
          signal: AbortSignal.timeout(API_TIMEOUT_MS),
        });

        if (!res.ok) {
          const text = await res.text();
          throw new Error(`${res.status}: ${text}`);
        }

        const data = await res.json();
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
