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

export function registerChainTools(server: McpServer) {
  server.tool(
    "get_block_height",
    "Get the current Zcash blockchain height from Zebra.",
    {},
    async () => {
      try {
        const height = await zebraRpc("getblockcount");
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ height }, null, 2),
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

  server.tool(
    "lookup_transaction",
    "Get raw transaction details from Zebra by txid.",
    {
      txid: z.string().describe("Transaction ID (hex)"),
      verbose: z.boolean().optional().describe("Return decoded JSON instead of raw hex (default: true)"),
    },
    async ({ txid, verbose }) => {
      try {
        const verbosity = verbose === false ? 0 : 1;
        const tx = await zebraRpc("getrawtransaction", [txid, verbosity]);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(tx, null, 2),
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
