import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const CAPABILITY_MANIFEST = {
  name: "zcash-mcp",
  layer: "ZAP1 attestation and proof verification",
  posture: "attestation_layer_not_wallet",
  category_claim: "ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute maintains the reference ZAP1 implementation.",
  trust_boundary: "A wrapper makes you trust the server. ZAP1 makes the server unnecessary to trust.",
  operating_rule: "Observe state, bound the claim, hash evidence, issue a receipt, verify later.",
  motto: "ZAP1 coule de source: receipt truth flows from observed state, bounded claims, hashes, anchors, and independent verification.",
  proof_rail_verbs: ["attest", "anchor", "prove", "verify"],
  primary_use_cases: [
    "create ZAP1 attestations for agent and workflow events",
    "query ZAP1 attestation, anchor, event, and agent state",
    "verify ZAP1 proof receipts and Merkle inclusion",
    "decode Zcash memo payloads that carry ZAP1 or receipt data",
    "read public chain context needed to interpret ZAP1 anchors",
    "convert wallet-layer action results into hash-only ZAP1 receipt requests",
    "convert external-rail action evidence into hash-only ZAP1 receipt requests",
    "validate, extract, compare, and audit ZAP1 receipt packets without calling external rails",
  ],
  market_fit: {
    problem: "Agents can call wallets and services, but they also need receipts that prove what happened after the fact.",
    zap1_role: "ZAP1 records typed workflow events, commits them into a Merkle tree, and anchors roots to Zcash.",
    composition: "Use wallet-layer tools for balance, signing, sync, and spend construction. Use this server for attestations, proof packets, and verification.",
    durable_value: "A receiver can verify the receipt from the schema, proof material, and Zcash anchor without trusting the original server.",
  },
  proof_rail_boundary: {
    covers: "receipts, anchor proofs, Merkle inclusion, memo decoding, and verification context",
    composes_with: "wallets, signers, custody systems, lightwalletd stacks, Zaino stacks, and application workflows",
    rejects: [
      "payment URI as proof of payment",
      "quote or route hash as settlement evidence by itself",
      "pending leaf as anchored finality",
      "custody or seed handling",
      "transaction signing or broadcast",
      "wallet scan state as ZAP1 truth",
      "claims that ZAP1 operates or guarantees an external rail",
    ],
  },
  receipt_packet: [
    "event_type",
    "agent_or_wallet_hash",
    "leaf_hash",
    "merkle_root",
    "merkle_path",
    "anchor_txid",
    "anchor_height",
    "verification_url",
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
      "zap1_prove_receipt",
      "zap1_verify_evm",
      "get_anchor_history",
      "get_anchor_status",
      "get_stats",
    ],
    receipt_and_memo: [
      "decode_memo",
      "zap1_create_receipt_invoice",
      "zap1_watch_receipt_invoice",
      "zap1_wallet_receipt_request",
      "zap1_attest_external_action",
    ],
    receipt_verification: [
      "zap1_verify_external_receipt",
      "zap1_verify_receipt_v2",
      "zap1_extract_proof_artifact",
      "zap1_check_anchor_freshness_at_height",
      "zap1_verify_receipt_chain",
      "zap1_compare_receipt_claims",
      "zap1_audit_event_log",
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
      "receipt invoice metadata",
      "external action receipt requests",
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
    compose_with_wallet_mcp: "Pair with a wallet MCP when an agent needs balance, signing, sync, or spend construction. Use zap1_wallet_receipt_request to hash the wallet result before attestation.",
  },
};

export function registerCapabilityTool(server: McpServer) {
  server.tool(
    "zcash_capability_manifest",
    "Return the ZAP1 capability manifest: what this MCP covers, what it deliberately excludes, and how agents should compose it with wallet-layer tools.",
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
