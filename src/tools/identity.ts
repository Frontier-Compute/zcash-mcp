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
    },
    async ({ agent_id, pubkey_hash }) => {
      try {
        const res = await fetch(`${ZAP1_API}/attest`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            event_type: "AGENT_REGISTER",
            wallet_hash: agent_id,
            input_hash: pubkey_hash,
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
