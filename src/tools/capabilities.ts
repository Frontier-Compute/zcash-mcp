import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const CAPABILITY_MANIFEST = {
  name: "zcash-mcp",
  layer: "ZAP1 attestation and proof verification",
  posture: "attestation_layer_not_wallet",
  primary_use_cases: [
    "create ZAP1 attestations for agent and workflow events",
    "query ZAP1 attestation, anchor, event, and agent state",
    "verify ZAP1 proof receipts and Merkle inclusion",
    "decode Zcash memo payloads that carry ZAP1 or receipt data",
    "read public chain context needed to interpret ZAP1 anchors",
  ],
  supported_surfaces: {
    attestation: [
      "attest_event",
      "zcash_identity_register",
      "get_events",
      "get_agent_status",
      "zcash_reputation_score",
    ],
    proof_verification: [
      "verify_proof",
      "zcash_prove_payment",
      "zcash_verify_evm",
      "get_anchor_history",
      "get_anchor_status",
      "get_stats",
    ],
    receipt_and_memo: [
      "decode_memo",
      "zcash_create_invoice",
      "zcash_watch_payment",
    ],
    chain_context: [
      "get_block_height",
      "lookup_transaction",
    ],
  },
  wallet_boundary: {
    in_scope: [
      "ZAP1 receipts",
      "attestation lifecycle state",
      "proof verification",
      "memo decoding",
      "payment URI and invoice metadata",
    ],
    out_of_scope: [
      "private key custody",
      "seed handling",
      "balance scanning",
      "PCZT signing",
      "shielded spend construction",
      "lightwalletd or Zaino wallet synchronization",
    ],
  },
  agent_policy: {
    safe_default: "Use this server for receipts, attestations, and verification before or after wallet-layer actions.",
    reject_as_wallet: "Do not ask this server to hold keys, scan wallet state, or sign transactions.",
    compose_with_wallet_mcp: "Pair with a wallet MCP when an agent needs balance, signing, sync, or spend construction.",
  },
};

export function registerCapabilityTool(server: McpServer) {
  server.tool(
    "zcash_capability_manifest",
    "Return the ZAP1 capability manifest: what this MCP owns, what it deliberately does not own, and how agents should compose it with wallet-layer tools.",
    {},
    async () => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(CAPABILITY_MANIFEST, null, 2),
        },
      ],
    })
  );
}
