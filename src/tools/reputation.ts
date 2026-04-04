import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";
const API_TIMEOUT_MS = 15_000;

export function registerReputationTool(server: McpServer) {
  server.tool(
    "zcash_reputation_score",
    "Fetch an agent's reputation from ZAP1. Combines bond data and policy compliance into a single object: attestation count, violations, bonds, and compliant flag.",
    {
      agent_id: z.string().max(128).describe("Agent identifier to look up"),
    },
    async ({ agent_id }) => {
      try {
        const [bondRes, policyRes] = await Promise.all([
          fetch(`${ZAP1_API}/agent/${encodeURIComponent(agent_id)}/bond`, {
            signal: AbortSignal.timeout(API_TIMEOUT_MS),
          }),
          fetch(`${ZAP1_API}/agent/${encodeURIComponent(agent_id)}/policy/verify`, {
            signal: AbortSignal.timeout(API_TIMEOUT_MS),
          }),
        ]);

        if (!bondRes.ok) {
          const text = await bondRes.text();
          throw new Error(`bond ${bondRes.status}: ${text}`);
        }
        if (!policyRes.ok) {
          const text = await policyRes.text();
          throw new Error(`policy ${policyRes.status}: ${text}`);
        }

        const bond = await bondRes.json();
        const policy = await policyRes.json();

        const reputation = {
          agent_id,
          attestation_count: bond.attestation_count ?? null,
          violations: bond.violations ?? null,
          bonds: bond.bonds ?? null,
          compliant: policy.compliant ?? null,
        };

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(reputation, null, 2),
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
