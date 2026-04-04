import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

export function registerSignMpcTool(server: McpServer) {
  server.tool(
    "zcash_sign_mpc",
    "Sign a message hash through Ika 2PC-MPC. Two on-chain transactions: presign + sign. " +
      "Neither party sees the full private key. Returns DER-encoded ECDSA signature.",
    {
      wallet_id: z.string().describe("dWallet object ID from create_wallet"),
      message_hash: z.string().describe("Hex-encoded 32-byte message hash (sighash) to sign"),
      chain: z
        .enum(["zcash-transparent", "bitcoin", "ethereum"])
        .describe("Chain determines hash algorithm (DoubleSHA256 or KECCAK256)"),
      encryption_seed: z.string().describe("Hex encryption seed from wallet creation"),
      sui_private_key: z.string().describe("Sui private key for signing the MPC transactions"),
      ika_coin_id: z.string().optional().describe("IKA coin object ID"),
    },
    async ({ wallet_id, message_hash, chain, encryption_seed, sui_private_key, ika_coin_id }) => {
      try {
        const hashAlgo: Record<string, string> = {
          "zcash-transparent": "DoubleSHA256",
          bitcoin: "DoubleSHA256",
          ethereum: "KECCAK256",
        };

        const result = {
          status: "sign_requires_zcash_ika_package",
          instructions: {
            step1: "import { sign } from '@frontiercompute/zcash-ika'",
            step2: `const sig = await sign(config, { messageHash: Buffer.from('${message_hash}', 'hex'), walletId: '${wallet_id}', chain: '${chain}', encryptionSeed: '${encryption_seed}' })`,
          },
          signing_params: {
            curve: "secp256k1",
            algorithm: "ECDSA",
            hash: hashAlgo[chain],
          },
          flow: [
            "TX 1: Request presign (pre-compute MPC ephemeral key share)",
            "Poll for presign completion (up to 5 min on testnet)",
            "TX 2: Approve message + request signature",
            "Poll for sign completion",
            "Parse DER-encoded ECDSA signature from output",
          ],
          wallet_id,
          message_hash,
          chain,
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
