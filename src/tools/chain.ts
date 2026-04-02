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
    "Get the current Zcash chain height from Zebra.",
    {},
    async () => {
      try {
        const info = (await zebraRpc("getblockchaininfo")) as { blocks?: number };
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({ height: info.blocks }, null, 2),
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
    "Get raw transaction data by txid from Zebra.",
    {
      txid: z.string().describe("Transaction ID (64-char hex)"),
      verbose: z.boolean().optional().describe("Return decoded JSON instead of raw hex (default true)"),
    },
    async ({ txid, verbose }) => {
      try {
        const verbosity = verbose === false ? 0 : 1;
        const data = await zebraRpc("getrawtransaction", [txid, verbosity]);
        return {
          content: [
            {
              type: "text" as const,
              text: typeof data === "string" ? data : JSON.stringify(data, null, 2),
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
