import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://api.frontiercompute.cash";
const API_TIMEOUT_MS = 15_000;

export function registerIdentityTool(server: McpServer) {
  server.tool(
    "zcash_identity_register",
    "Register an agent identity on ZAP1 via an AGENT_REGISTER attestation. Returns the leaf hash and verification URLs for the registration event.",
    {
      agent_id: z.string().max(128).describe("Unique agent identifier to register"),
      pubkey_hash: z.string().regex(/^[0-9a-fA-F]{64}$/, "pubkey_hash must be 64-char hex").describe("SHA-256 of the agent's public key (64-char hex)"),
      model_hash: z.string().regex(/^[0-9a-fA-F]{64}$/, "model_hash must be 64-char hex").describe("Hash of the registered model identity"),
      policy_hash: z.string().regex(/^[0-9a-fA-F]{64}$/, "policy_hash must be 64-char hex").describe("Hash of the registered agent policy"),
      api_key: z.string().optional().describe("ZAP1 API key (or set ZAP1_API_KEY env var)"),
    },
    async ({ agent_id, pubkey_hash, model_hash, policy_hash, api_key }) => {
      const key = api_key ?? process.env.ZAP1_API_KEY;
      if (!key) {
        return {
          content: [{ type: "text" as const, text: "Error: No API key. Pass api_key or set ZAP1_API_KEY env var." }],
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
          body: JSON.stringify({
            event_type: "AGENT_REGISTER",
            wallet_hash: agent_id,
            agent_id,
            pubkey_hash,
            model_hash,
            policy_hash,
          }),
          signal: AbortSignal.timeout(API_TIMEOUT_MS),
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
