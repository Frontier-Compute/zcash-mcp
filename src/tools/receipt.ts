import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const API_TIMEOUT_MS = 15_000;

export function registerReceiptTool(server: McpServer) {
  server.tool(
    "zcash_prove_payment",
    "Fetch a ZAP1 Merkle proof bundle for a leaf hash. Returns the full proof: leaf, path, root, and anchor. Use this to prove payment inclusion on-chain.",
    {
      leaf_hash: z.string().regex(/^[0-9a-fA-F]{64}$/, "leaf_hash must be 64-char hex").describe("Hex-encoded leaf hash (64 chars)"),
    },
    async ({ leaf_hash }) => {
      try {
        const res = await fetch(`${ZAP1_API}/verify/${leaf_hash}/proof.json`, {
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
