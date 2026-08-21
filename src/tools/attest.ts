import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";

export function registerAttestTool(server: McpServer) {
  server.tool(
    "attest_event",
    "Create a typed ZAP1 attestation event leaf for later anchoring. Returns a leaf hash for verification.",
    {
      event_type: z.string().max(64).describe("Event type: DEPLOYMENT, CONTRACT_ANCHOR, AGENT_ACTION, GOVERNANCE_PROPOSAL, etc."),
      wallet_hash: z.string().max(128).optional().describe("Wallet hash. Required for non-AGENT_ACTION events; derived from agent_id for AGENT_ACTION when omitted."),
      agent_id: z.string().max(128).optional().describe("Agent identifier. Required by the supported AGENT_ACTION wire contract."),
      serial_number: z.string().max(128).optional().describe("Serial number or version tag"),
      action_type: z.string().max(64).optional().describe("Action type for AGENT_ACTION events"),
      input_hash: z.string().regex(/^[0-9a-fA-F]{64}$/).optional().describe("SHA-256 of action input"),
      output_hash: z.string().regex(/^[0-9a-fA-F]{64}$/).optional().describe("SHA-256 of action output"),
      expected_leaf_hash: z
        .string()
        .regex(/^[0-9a-fA-F]{64}$/)
        .optional()
        .describe("Local-only expected typed leaf. Never sent to ZAP1; a mismatching response fails closed."),
      proposal_id: z.string().max(128).optional().describe("Proposal ID for governance events"),
      api_key: z.string().optional().describe("ZAP1 API key (or set ZAP1_API_KEY env var)"),
    },
    async ({ api_key, expected_leaf_hash, ...fields }) => {
      if (fields.event_type === "AGENT_ACTION") {
        const missing = [
          ...(!fields.agent_id ? ["agent_id"] : []),
          ...(!fields.action_type ? ["action_type"] : []),
          ...(!fields.input_hash ? ["input_hash"] : []),
          ...(!fields.output_hash ? ["output_hash"] : []),
        ];
        if (missing.length > 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Error: AGENT_ACTION requires ${missing.join(", ")}.`,
              },
            ],
            isError: true,
          };
        }
        fields.wallet_hash ??= fields.agent_id;
      } else if (!fields.wallet_hash) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: wallet_hash is required for non-AGENT_ACTION events.",
            },
          ],
          isError: true,
        };
      }

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
        const res = await fetch(`${ZAP1_API}/event`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${key}`,
          },
          body: JSON.stringify(fields),
          signal: AbortSignal.timeout(15_000),
        });

        if (!res.ok) {
          const text = await res.text();
          throw new Error(`${res.status}: ${text}`);
        }

        const data = await res.json();
        if (expected_leaf_hash) {
          const returnedLeafHash =
            data && typeof data === "object" && "leaf_hash" in data && typeof data.leaf_hash === "string"
              ? data.leaf_hash
              : null;
          if (!returnedLeafHash || returnedLeafHash.toLowerCase() !== expected_leaf_hash.toLowerCase()) {
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(
                    {
                      valid: false,
                      status: "attest_response_leaf_mismatch",
                      expected_leaf_hash: expected_leaf_hash.toLowerCase(),
                      returned_leaf_hash: returnedLeafHash,
                      boundary: "The server response was rejected before proof assembly because it did not return the locally computed typed leaf.",
                    },
                    null,
                    2
                  ),
                },
              ],
              isError: true,
            };
          }
        }
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
