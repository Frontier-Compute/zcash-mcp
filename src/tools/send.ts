import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerSendTool(server: McpServer) {
  server.tool(
    "send_shielded",
    "Generate a zcash: payment URI for shielded ZEC. Encodes address, amount, and optional memo into a scannable URI.",
    {
      address: z.string().regex(/^(u1|zs1|t1|t3)[a-zA-Z0-9]+$/, "Invalid Zcash address format").describe("Recipient Zcash shielded address"),
      amount: z.number().positive().max(21_000_000).describe("Amount in ZEC"),
      memo: z.string().max(512).optional().describe("Optional memo text (max 512 bytes)"),
      label: z.string().optional().describe("Optional label for the payment"),
    },
    async ({ address, amount, memo, label }) => {
      try {
        // Build zcash: URI per ZIP 321
        const params: string[] = [];
        params.push(`amount=${amount}`);
        if (memo) {
          // ZIP 321 requires memo as base64url (RFC 4648, no padding)
          const base64Memo = Buffer.from(memo, "utf-8").toString("base64url");
          params.push(`memo=${base64Memo}`);
        }
        if (label) {
          params.push(`label=${encodeURIComponent(label)}`);
        }

        const uri = `zcash:${address}?${params.join("&")}`;

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  uri,
                  address,
                  amount,
                  memo: memo ?? null,
                  note: "Scan this URI with any Zcash wallet to send the payment",
                },
                null,
                2
              ),
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
