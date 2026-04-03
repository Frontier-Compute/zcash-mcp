import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";
const API_TIMEOUT_MS = 15_000;

export function registerEventTools(server: McpServer) {
  server.tool(
    "get_events",
    "Get recent ZAP1 attestation events. Returns event type, wallet hash, leaf hash, and timestamps.",
    {
      limit: z.number().int().min(1).max(200).optional().describe("Number of events (default 20)"),
    },
    async ({ limit }) => {
      try {
        const n = limit ?? 20;
        const res = await fetch(`${ZAP1_API}/events?limit=${n}`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(await res.json(), null, 2) }],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
      }
    }
  );

  server.tool(
    "get_agent_status",
    "Get attestation summary for a ZAP1 agent: registration, policies, actions, event history.",
    {
      agent_id: z.string().describe("Agent identifier"),
    },
    async ({ agent_id }) => {
      try {
        const safeId = encodeURIComponent(agent_id);
        const res = await fetch(`${ZAP1_API}/agent/${safeId}`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) });
        if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(await res.json(), null, 2) }],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
