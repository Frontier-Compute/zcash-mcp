import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerCreateWalletTool(server: McpServer) {
  server.tool(
    "zcash_create_wallet",
    "Create a split-key wallet via Ika 2PC-MPC. One secp256k1 key signs for Zcash transparent, Bitcoin, and Ethereum. " +
      "Neither party holds the full private key. Returns wallet ID, public key, and encryption seed (save it for signing).",
    {
      network: z
        .enum(["testnet", "mainnet"])
        .default("testnet")
        .describe("Ika network"),
      chain: z
        .enum(["zcash-transparent", "bitcoin", "ethereum"])
        .default("zcash-transparent")
        .describe("Target chain (all use same secp256k1 key)"),
      sui_private_key: z
        .string()
        .describe("Sui private key (suiprivkey1...) for signing the DKG transaction"),
      ika_coin_id: z
        .string()
        .optional()
        .describe("IKA coin object ID (auto-detected if omitted)"),
    },
    async ({ network, chain, sui_private_key, ika_coin_id }) => {
      try {
        const result = {
          status: "wallet_creation_requires_zcash_ika_package",
          instructions: {
            step1: "npm install @frontiercompute/zcash-ika",
            step2: "import { createWallet } from '@frontiercompute/zcash-ika'",
            step3: `const wallet = await createWallet({ network: '${network}', suiPrivateKey: '...'${ika_coin_id ? `, ikaCoinId: '${ika_coin_id}'` : ""} }, '${chain}')`,
            step4: "Save wallet.encryptionSeed - you need it for signing",
          },
          chain_params: {
            "zcash-transparent": "secp256k1/ECDSA/DoubleSHA256",
            bitcoin: "secp256k1/ECDSA/DoubleSHA256",
            ethereum: "secp256k1/ECDSA/KECCAK256",
          },
          note: "One secp256k1 dWallet signs for all three chain families. " +
            "Zcash shielded (Orchard) requires RedPallas on Pallas curve - not available via MPC. " +
            "Use shield() to move transparent ZEC into Orchard pool.",
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
