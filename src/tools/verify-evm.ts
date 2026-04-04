import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const VERIFIER_ADDRESSES: Record<string, { address: string; rpc: string }> = {
  sepolia: {
    address: "0x3fD65055A8dC772C848E7F227CE458803005C87F",
    rpc: "https://ethereum-sepolia-rpc.publicnode.com",
  },
  base: {
    address: "", // deployed in Track 2
    rpc: "https://mainnet.base.org",
  },
  arbitrum: {
    address: "0x9D0B26010C9a7a2a8509Fd1a3407B741d9C10e3a",
    rpc: "https://arb1.arbitrum.io/rpc",
  },
};

const VERIFIER_ABI = [
  "function verifyProofStateless(bytes32 leafHash, bytes32[] calldata siblings, uint256 positions, bytes32 expectedRoot) external view returns (bool)",
  "function isAnchorRegistered(bytes32 root) external view returns (bool, uint64)",
  "function computeLeafHash(bytes calldata payload) external view returns (bytes32)",
];

export function registerVerifyEvmTool(server: McpServer) {
  server.tool(
    "zcash_verify_evm",
    "Verify a ZAP1 Merkle proof on-chain via the EVM ZAP1Verifier contract. " +
      "Checks that a leaf hash is included in a registered Zcash anchor root. " +
      "Supports Sepolia (testnet), Base, and Arbitrum.",
    {
      chain: z
        .enum(["sepolia", "base", "arbitrum"])
        .describe("EVM chain to verify on"),
      leaf_hash: z
        .string()
        .regex(/^[0-9a-fA-F]{64}$/)
        .describe("64-char hex leaf hash (no 0x prefix)"),
      siblings: z
        .array(z.string().regex(/^[0-9a-fA-F]{64}$/))
        .describe("Ordered hex sibling hashes for the Merkle proof"),
      positions: z
        .number()
        .int()
        .describe("Bit-packed position flags (0 = left, 1 = right per level)"),
      expected_root: z
        .string()
        .regex(/^[0-9a-fA-F]{64}$/)
        .describe("64-char hex expected Merkle root"),
    },
    async ({ chain, leaf_hash, siblings, positions, expected_root }) => {
      try {
        const deployment = VERIFIER_ADDRESSES[chain];
        if (!deployment?.address) {
          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                error: `ZAP1Verifier not yet deployed on ${chain}. Use 'sepolia' for testing.`,
                available: Object.entries(VERIFIER_ADDRESSES)
                  .filter(([, v]) => v.address)
                  .map(([k]) => k),
              }, null, 2),
            }],
            isError: true,
          };
        }

        const result = {
          verification: {
            chain,
            contract: deployment.address,
            rpc: deployment.rpc,
            leaf_hash: `0x${leaf_hash}`,
            siblings: siblings.map((s) => `0x${s}`),
            positions,
            expected_root: `0x${expected_root}`,
          },
          abi: VERIFIER_ABI,
          call: {
            method: "verifyProofStateless",
            args: [
              `0x${leaf_hash}`,
              siblings.map((s) => `0x${s}`),
              positions,
              `0x${expected_root}`,
            ],
            note: "This is a view call (no gas cost). Returns true if the proof is valid.",
          },
          anchor_check: {
            method: "isAnchorRegistered",
            args: [`0x${expected_root}`],
            note: "Check if this root is registered as a Zcash anchor. Returns (exists, zcashHeight).",
          },
          how_to_call: `cast call ${deployment.address} 'verifyProofStateless(bytes32,bytes32[],uint256,bytes32)(bool)' 0x${leaf_hash} '[${siblings.map((s) => `0x${s}`).join(",")}]' ${positions} 0x${expected_root} --rpc-url ${deployment.rpc}`,
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
