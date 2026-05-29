import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const SCHEMA_VERSION = "zap1-receipt-v1";

const ReceiptSchema = z.object({
  schema_version: z.literal(SCHEMA_VERSION),
  event_type: z.string().min(1).max(64),
  profile: z
    .enum([
      "public_hash_only",
      "counterparty_receipt",
      "auditor_packet",
      "operator_internal",
      "grant_proof_packet",
      "compliance_audit_packet",
    ])
    .optional(),
  subject_hash: z.string().regex(HEX_64, "subject_hash must be 64-char hex"),
  claim_hash: z.string().regex(HEX_64, "claim_hash must be 64-char hex"),
  evidence_hash: z.string().regex(HEX_64, "evidence_hash must be 64-char hex"),
  leaf_hash: z.string().regex(HEX_64, "leaf_hash must be 64-char hex"),
  merkle_root: z.string().regex(HEX_64, "merkle_root must be 64-char hex"),
  merkle_path: z.array(z.string().regex(HEX_64, "merkle_path entries must be 64-char hex")).default([]),
  anchor_txid: z.string().regex(HEX_64, "anchor_txid must be 64-char hex").optional(),
  anchor_height: z.number().int().nonnegative().optional(),
  verification_url: z.string().url().optional(),
  disclosed_fields: z.array(z.string().min(1).max(64)).optional(),
  redacted_fields: z.array(z.string().min(1).max(64)).optional(),
  redaction_policy: z
    .enum([
      "hash_only",
      "counterparty_visible",
      "auditor_visible",
      "operator_private",
      "grant_public",
      "compliance_limited",
    ])
    .optional(),
  status: z.enum(["requested", "attested", "anchored", "verified", "disputed", "expired", "revoked"]).optional(),
  grant_context: z.record(z.string(), z.unknown()).optional(),
  audit_context: z.record(z.string(), z.unknown()).optional(),
});

function validateReceipt(receipt: unknown) {
  const parsed = ReceiptSchema.safeParse(receipt);

  if (!parsed.success) {
    return {
      valid: false,
      status: "malformed",
      schema_version: SCHEMA_VERSION,
      errors: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
      rule: "Observe state, bound the claim, hash evidence, issue a receipt, verify later.",
    };
  }

  const value = parsed.data;
  const anchored = Boolean(value.anchor_txid || value.anchor_height !== undefined);

  return {
    valid: true,
    status: anchored ? "anchored" : "pending",
    schema_version: SCHEMA_VERSION,
    receipt: value,
    acceptance_checks: {
      has_leaf_hash: true,
      has_merkle_root: true,
      has_claim_hash: true,
      has_evidence_hash: true,
      anchored,
      hash_only_payload: true,
      has_disclosure_profile: Boolean(value.profile),
      has_redaction_policy: Boolean(value.redaction_policy),
    },
    rule: "Observe state, bound the claim, hash evidence, issue a receipt, verify later.",
    boundary: "ZAP1 verifies the receipt contract. It does not hold keys, scan balances, sign transactions, or broadcast spends.",
  };
}

export function registerConformanceTool(server: McpServer) {
  server.tool(
    "zcash_conformance_check",
    "Validate a ZAP1 receipt packet against the frozen v1 receipt contract. Returns malformed, pending, or anchored.",
    {
      receipt: z.unknown().describe("ZAP1 receipt packet to validate."),
    },
    async ({ receipt }) => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(validateReceipt(receipt), null, 2),
        },
      ],
    })
  );
}
