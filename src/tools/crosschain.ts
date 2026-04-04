import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerCrosschainTool(server: McpServer) {
  server.tool(
    "zcash_crosschain_swap",
    "Cross-chain swap intent for Zcash transparent, Bitcoin, or EVM assets. " +
      "Custody via Ika (split-key on Sui), NEAR Chain Signatures, or direct wallet. " +
      "Zcash shielded (Orchard) requires RedPallas - not available via Ika or NEAR. " +
      "Only transparent ZEC works through external MPC custody.",
    {
      source_chain: z
        .enum(["zcash-transparent", "bitcoin", "ethereum"])
        .describe("Source chain (transparent ZEC, BTC, or ETH)"),
      dest_chain: z
        .enum(["zcash-transparent", "bitcoin", "ethereum", "usdc", "usdt"])
        .describe("Destination chain or asset"),
      amount: z.string().describe("Amount in source denomination"),
      recipient: z.string().describe("Recipient address on destination chain"),
      custody: z
        .enum(["ika", "near", "direct"])
        .optional()
        .describe("Custody provider (default: direct)"),
    },
    async ({ source_chain, dest_chain, amount, recipient, custody }) => {
      const provider = custody ?? "direct";

      const signingParams: Record<string, { curve: string; algorithm: string; hash: string }> = {
        "zcash-transparent": { curve: "secp256k1", algorithm: "ECDSA", hash: "DoubleSHA256" },
        bitcoin: { curve: "secp256k1", algorithm: "ECDSA", hash: "DoubleSHA256" },
        ethereum: { curve: "secp256k1", algorithm: "ECDSA", hash: "KECCAK256" },
        usdc: { curve: "secp256k1", algorithm: "ECDSA", hash: "KECCAK256" },
        usdt: { curve: "secp256k1", algorithm: "ECDSA", hash: "KECCAK256" },
      };

      const custodyInfo: Record<string, { name: string; security: string; pkg: string | null }> = {
        ika: {
          name: "Ika 2PC-MPC on Sui",
          security: "Split-key: agent holds half, network holds half. Neither signs alone.",
          pkg: "@frontiercompute/zcash-ika",
        },
        near: {
          name: "NEAR Chain Signatures (v1.signer)",
          security: "Threshold Cait-Sith MPC across NEAR nodes. secp256k1 only.",
          pkg: "@frontiercompute/zap1-near",
        },
        direct: {
          name: "Local Zebra wallet",
          security: "Full key on machine. Use ika or near for split-key custody.",
          pkg: null,
        },
      };

      const result = {
        intent: { from: source_chain, to: dest_chain, amount, recipient },
        signing: {
          source: signingParams[source_chain],
          destination: signingParams[dest_chain],
        },
        custody: custodyInfo[provider],
        attestation: {
          protocol: "ZAP1",
          event_type: "AGENT_ACTION",
          api: "https://pay.frontiercompute.io/attest",
        },
        limitations: {
          shielded: "Zcash Orchard requires RedPallas on Pallas curve. Not available via Ika or NEAR MPC. Use direct wallet for shielded.",
        },
        status: "Intent recorded. Execution requires active custody + solver.",
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );
}
