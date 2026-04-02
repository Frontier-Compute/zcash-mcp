import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const ZEBRA_RPC = process.env.ZEBRA_RPC_URL ?? "http://127.0.0.1:8232";

async function zebraRpc(method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(ZEBRA_RPC, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (json.error) throw new Error(json.error.message);
  return json.result;
}

export function registerBalanceTool(server: McpServer) {
  server.tool(
    "get_balance",
    "Get shielded ZEC balance for an address or viewing key via Zebra RPC",
    {
      address: z.string().describe("Zcash shielded address or viewing key"),
    },
    async ({ address }) => {
      try {
        // z_getbalance returns the balance for a given address
        const balance = await zebraRpc("z_getbalance", [address]);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ address, balance }, null, 2),
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
