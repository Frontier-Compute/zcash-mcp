import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export function registerSendTool(server: McpServer) {
  server.tool(
    "send_shielded",
    "Generate a zcash: payment URI for shielded ZEC. Encodes address, amount, and optional memo into a scannable URI.",
    {
      address: z.string().describe("Recipient Zcash shielded address"),
      amount: z.number().positive().describe("Amount in ZEC"),
      memo: z.string().optional().describe("Optional memo text (max 512 bytes)"),
      label: z.string().optional().describe("Optional label for the payment"),
    },
    async ({ address, amount, memo, label }) => {
      try {
        // Build zcash: URI per ZIP 321
        const params: string[] = [];
        params.push(`amount=${amount}`);
        if (memo) {
          // Memo gets hex-encoded in ZIP 321
          const hexMemo = Buffer.from(memo, "utf-8").toString("hex");
          params.push(`memo=${hexMemo}`);
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
