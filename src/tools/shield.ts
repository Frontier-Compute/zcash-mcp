import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerShieldTool(server: McpServer) {
  server.tool(
    "zcash_shield",
    "Return a shield-to-Orchard transition plan with ZAP1 attestation metadata. This server does not build, sign, or broadcast the spend.",
    {
      wallet_id: z.string().describe("dWallet object ID (transparent side)"),
      encryption_seed: z.string().describe("Hex encryption seed from wallet creation"),
      shielded_address: z.string().describe("Zcash unified address (u1...) for the Orchard pool"),
      amount_zatoshis: z.number().int().positive().describe("Amount in zatoshis to shield"),
      memo: z.string().max(512).optional().describe("Optional memo for the shielding transaction"),
      sui_private_key: z.string().describe("Sui private key for the MPC sign transaction"),
    },
    async ({ wallet_id, shielded_address, amount_zatoshis, memo }) => {
      try {
        const zec = amount_zatoshis / 1e8;

        const result = {
          status: "shield_flow",
          description: `Shield ${zec} ZEC from MPC custody to Orchard pool`,
          flow: [
            "1. List UTXOs on the t-addr (Zebra: z_listunspent)",
            "2. Build transparent TX: t-addr -> shielded_address",
            "3. Compute sighash (DoubleSHA256)",
            "4. Sign via Ika 2PC-MPC (secp256k1/ECDSA)",
            "5. Attach signature to TX",
            "6. Broadcast via Zebra (sendrawtransaction)",
            "7. Attest custody transition to ZAP1 (AGENT_ACTION)",
          ],
          custody_transition: {
            from: "MPC (split-key, neither party holds full key)",
            to: "Local Orchard wallet (RedPallas, full privacy)",
          },
          wallet_id,
          shielded_address,
          amount_zatoshis,
          memo: memo || null,
          note: "After shielding, ZEC is in the Orchard pool with full Zcash privacy. " +
            "The MPC wallet still exists for receiving new deposits.",
        };

        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
      }
    }
  );
}
