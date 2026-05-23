import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const POLL_INTERVAL_MS = 5_000;
const API_TIMEOUT_MS = 10_000;

export function registerWatchTool(server: McpServer) {
  server.tool(
    "zap1_watch_receipt_invoice",
    "Poll ZAP1 receipt-invoice status until paid or timeout. Returns public receipt status only; this server does not scan wallet state.",
    {
      invoice_id: z.string().describe("Invoice ID returned by zap1_create_receipt_invoice"),
      timeout_seconds: z.number().int().positive().default(300).describe("Maximum seconds to wait for payment (default 300)"),
    },
    async ({ invoice_id, timeout_seconds }) => {
      const deadline = Date.now() + timeout_seconds * 1000;

      try {
        while (Date.now() < deadline) {
          const res = await fetch(`${ZAP1_API}/invoice/${invoice_id}`, {
            signal: AbortSignal.timeout(API_TIMEOUT_MS),
          });

          if (!res.ok) {
            const text = await res.text();
            throw new Error(`${res.status}: ${text}`);
          }

          const data = await res.json();

          if (data.status === "paid") {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(
                    {
                      paid: true,
                      txid: data.txid ?? null,
                      height: data.height ?? null,
                      amount: data.amount ?? null,
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }

          const remaining = Math.ceil((deadline - Date.now()) / 1000);
          if (remaining <= 0) break;

          await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { paid: false, txid: null, height: null, amount: null, reason: "timeout" },
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
