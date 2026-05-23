import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const API_TIMEOUT_MS = 15_000;

export function registerVerifyTool(server: McpServer) {
  server.tool(
    "verify_proof",
    "Verify a ZAP1 Merkle proof. Checks whether a leaf hash exists in the ZAP1 attestation tree and returns the proof path.",
    {
      leaf_hash: z.string().regex(/^[0-9a-fA-F]{64}$/, "leaf_hash must be 64-char hex").describe("Hex-encoded leaf hash to verify (64 chars)"),
    },
    async ({ leaf_hash }) => {
      try {
        const res = await fetch(`${ZAP1_API}/verify/${leaf_hash}/check`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });

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
