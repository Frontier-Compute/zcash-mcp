import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";

export function registerAttestTool(server: McpServer) {
  server.tool(
    "attest_event",
    "Create a ZAP1 attestation event on Zcash. Writes a typed lifecycle, governance, or agent event to the Merkle tree. Returns leaf hash for verification.",
    {
      event_type: z.string().describe("Event type: DEPLOYMENT, CONTRACT_ANCHOR, AGENT_ACTION, GOVERNANCE_PROPOSAL, etc."),
      wallet_hash: z.string().describe("Wallet hash or agent identifier"),
      serial_number: z.string().optional().describe("Serial number or version tag"),
      action_type: z.string().optional().describe("Action type for AGENT_ACTION events"),
      input_hash: z.string().optional().describe("SHA-256 of action input"),
      output_hash: z.string().optional().describe("SHA-256 of action output"),
      proposal_id: z.string().optional().describe("Proposal ID for governance events"),
      api_key: z.string().optional().describe("ZAP1 API key (or set ZAP1_API_KEY env var)"),
    },
    async ({ api_key, ...fields }) => {
      const key = api_key ?? process.env.ZAP1_API_KEY;
      if (!key) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: No API key. Pass api_key or set ZAP1_API_KEY env var.",
            },
          ],
          isError: true,
        };
      }

      try {
        const res = await fetch(`${ZAP1_API}/attest`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${key}`,
          },
          body: JSON.stringify(fields),
        });

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
