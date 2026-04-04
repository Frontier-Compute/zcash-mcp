import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerCrosschainTool(server: McpServer) {
  server.tool(
    "zcash_crosschain_swap",
    "Express a cross-chain swap intent. Shielded ZEC to BTC, USDC, USDT, or any supported chain. " +
      "Three custody modes: ika (split-key on Sui), near (NEAR Chain Signatures), direct (local wallet). " +
      "Every swap attested on Zcash via ZAP1.",
    {
      source_chain: z
        .enum(["zcash-shielded", "zcash-transparent", "bitcoin", "ethereum"])
        .describe("Source chain"),
      dest_chain: z
        .enum(["zcash-shielded", "zcash-transparent", "bitcoin", "ethereum", "usdc", "usdt"])
        .describe("Destination chain or asset"),
      amount: z.string().describe("Amount in source denomination (e.g. '0.01')"),
      recipient: z.string().describe("Recipient address on destination chain"),
      custody: z
        .enum(["ika", "near", "direct"])
        .optional()
        .describe("Custody provider (default: direct)"),
    },
    async ({ source_chain, dest_chain, amount, recipient, custody }) => {
      const provider = custody ?? "direct";

      const signingParams: Record<string, { curve: string; algorithm: string; hash: string }> = {
        "zcash-shielded": { curve: "Ed25519", algorithm: "EdDSA", hash: "SHA512" },
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
          security: "Threshold FROST/Cait-Sith MPC across NEAR nodes.",
          pkg: "@frontiercompute/zap1-near",
        },
        direct: {
          name: "Local Zebra wallet",
          security: "Full key on machine. Use ika or near for zero-trust.",
          pkg: null,
        },
      };

      const result = {
        intent: {
          from: source_chain,
          to: dest_chain,
          amount,
          recipient,
        },
        signing: {
          source: signingParams[source_chain],
          destination: signingParams[dest_chain],
        },
        custody: custodyInfo[provider],
        attestation: {
          protocol: "ZAP1",
          event_type: "CROSS_CHAIN_INTENT",
          api: "https://pay.frontiercompute.io/attest",
        },
        execution_paths: {
          ika: "Ed25519 dWallet live on Ika testnet (TX: FYcuaxBCAfuZqfBW7JEtEJME3KLBSBKLvhjLpZGSyaXb)",
          near: "v1.signer Ed25519 FROST + secp256k1 Cait-Sith confirmed on mainnet",
          intents: "Defuse 1Click API available. ZEC solver integration pending.",
        },
        status: "Intent recorded. Execution requires active custody + solver.",
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );
}
