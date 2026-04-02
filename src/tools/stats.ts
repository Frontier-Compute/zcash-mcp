import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";
const API_TIMEOUT_MS = 15_000;

export function registerStatsTool(server: McpServer) {
  server.tool(
    "get_stats",
    "Get ZAP1 protocol stats: total leaves, anchors, type distribution, and tree height.",
    {},
    async () => {
      try {
        const res = await fetch(`${ZAP1_API}/stats`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });

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
