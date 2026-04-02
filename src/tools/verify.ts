import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";

export function registerVerifyTool(server: McpServer) {
  server.tool(
    "verify_proof",
    "Verify a ZAP1 Merkle proof. Checks whether a leaf hash exists in the ZAP1 attestation tree and returns the proof path.",
    {
      leaf_hash: z.string().describe("Hex-encoded leaf hash to verify"),
    },
    async ({ leaf_hash }) => {
      try {
        const res = await fetch(`${ZAP1_API}/verify/${leaf_hash}/check`);

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
