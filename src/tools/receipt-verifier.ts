import { createHash } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

const receiptProfile = z.enum([
  "public_hash_only",
  "counterparty_receipt",
  "auditor_packet",
  "operator_internal",
  "grant_proof_packet",
  "compliance_audit_packet",
]);

const redactionPolicy = z.enum([
  "hash_only",
  "counterparty_visible",
  "auditor_visible",
  "operator_private",
  "grant_public",
  "compliance_limited",
]);

const receiptStatus = z.enum([
  "requested",
  "attested",
  "anchored",
  "verified",
  "disputed",
  "expired",
  "revoked",
]);

const ReceiptSchema = z.object({
  schema_version: z.literal("zap1-receipt-v1"),
  event_type: z.string().min(1).max(64),
  profile: receiptProfile.optional(),
  subject_hash: z.string().regex(HEX_64, "subject_hash must be 64-char hex"),
  claim_hash: z.string().regex(HEX_64, "claim_hash must be 64-char hex"),
  evidence_hash: z.string().regex(HEX_64, "evidence_hash must be 64-char hex"),
  leaf_hash: z.string().regex(HEX_64, "leaf_hash must be 64-char hex"),
  merkle_root: z.string().regex(HEX_64, "merkle_root must be 64-char hex"),
  merkle_path: z.array(z.string().regex(HEX_64, "merkle_path entries must be 64-char hex")),
  anchor_txid: z.string().regex(HEX_64, "anchor_txid must be 64-char hex").optional(),
  anchor_height: z.number().int().nonnegative().optional(),
  verification_url: z.string().url().optional(),
  disclosed_fields: z.array(z.string().min(1).max(64)).optional(),
  redacted_fields: z.array(z.string().min(1).max(64)).optional(),
  redaction_policy: redactionPolicy.optional(),
  status: receiptStatus.optional(),
}).strict();

type Receipt = z.infer<typeof ReceiptSchema>;
type ReceiptValidation =
  | {
      valid: true;
      status: "shape_only";
      claimedStatus: z.infer<typeof receiptStatus> | null;
      anchorReferencePresent: boolean;
      receipt: Receipt;
      warnings: string[];
    }
  | {
      valid: false;
      status: "malformed";
      errors: { path: string; message: string }[];
    };

function validateReceipt(receipt: unknown): ReceiptValidation {
  const parsed = ReceiptSchema.safeParse(receipt);

  if (!parsed.success) {
    return {
      valid: false,
      status: "malformed",
      errors: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    };
  }

  const value = parsed.data;
  const anchorReferencePresent = Boolean(value.anchor_txid || value.anchor_height !== undefined);

  return {
    valid: true,
    status: "shape_only",
    claimedStatus: value.status ?? null,
    anchorReferencePresent,
    receipt: value,
    warnings: [
      "zap1-receipt-v1 has no sibling positions or leaf_count, so this tool cannot recompute Merkle inclusion.",
      ...(anchorReferencePresent
        ? ["anchor txid/height are unverified references, not chain confirmation"]
        : ["receipt has no anchor reference"]),
      ...(value.profile ? [] : ["receipt has no disclosure profile"]),
      ...(value.redaction_policy ? [] : ["receipt has no redaction_policy"]),
    ],
  };
}

function sha256Hex(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex");
}

function proofArtifact(receipt: Receipt) {
  return {
    schema_version: receipt.schema_version,
    event_type: receipt.event_type,
    profile: receipt.profile ?? null,
    subject_hash: receipt.subject_hash,
    claim_hash: receipt.claim_hash,
    evidence_hash: receipt.evidence_hash,
    leaf_hash: receipt.leaf_hash,
    merkle_root: receipt.merkle_root,
    merkle_path: receipt.merkle_path,
    anchor_txid: receipt.anchor_txid ?? null,
    anchor_height: receipt.anchor_height ?? null,
    verification_url: receipt.verification_url ?? null,
  };
}

export function registerReceiptVerifierTools(server: McpServer) {
  server.tool(
    "zap1_verify_external_receipt",
    "Validate an external-action ZAP1 receipt packet. This is a stateless receipt-contract check; it does not trust or call the external rail.",
    {
      receipt: z.unknown().describe("ZAP1 receipt packet produced for an external action."),
      expected_event_type: z.string().min(1).max(64).optional(),
      expected_profile: receiptProfile.optional(),
    },
    async ({ receipt, expected_event_type, expected_profile }) => {
      const validation = validateReceipt(receipt);
      if (!validation.valid) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify(validation, null, 2) }],
          isError: true,
        };
      }

      const value = validation.receipt;
      const mismatches = [
        ...(expected_event_type && value.event_type !== expected_event_type
          ? [`event_type ${value.event_type} did not match expected ${expected_event_type}`]
          : []),
        ...(expected_profile && value.profile !== expected_profile
          ? [`profile ${value.profile ?? "missing"} did not match expected ${expected_profile}`]
          : []),
      ];

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                valid: false,
                schema_valid: true,
                status: "unverified_v1_shape",
                claimed_status: validation.claimedStatus,
                cryptographic_inclusion_valid: false,
                anchor_reference_present: validation.anchorReferencePresent,
                anchor_confirmed: false,
                acceptance_ready: false,
                profile: value.profile ?? null,
                acceptance_checks: {
                  has_leaf_hash: true,
                  has_merkle_root: true,
                  has_merkle_path: true,
                  has_claim_hash: true,
                  has_evidence_hash: true,
                  anchor_reference_present: validation.anchorReferencePresent,
                  anchor_confirmed: false,
                  hash_only_payload: value.redaction_policy === "hash_only",
                  external_rail_not_called: true,
                },
                mismatches,
                warnings: validation.warnings,
                boundary:
                  "This legacy tool validates v1 packet shape only. Use zap1_verify_receipt_v2 to recompute a positioned, count-bound proof; verify any Zcash anchor separately.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
  );

  server.tool(
    "zap1_extract_proof_artifact",
    "Extract the portable proof artifact from a ZAP1 receipt: leaf, Merkle path, root, anchor context, and verification URL.",
    {
      receipt: z.unknown().describe("ZAP1 receipt packet to extract proof material from."),
    },
    async ({ receipt }) => {
      const validation = validateReceipt(receipt);
      if (!validation.valid) {
        return {
          content: [{ type: "text" as const, text: JSON.stringify(validation, null, 2) }],
          isError: true,
        };
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                artifact_type: "zap1-proof-artifact",
                artifact_hash: sha256Hex(proofArtifact(validation.receipt)),
                proof_artifact: proofArtifact(validation.receipt),
                boundary:
                  "The artifact contains proof material only. It does not contain private keys, wallet state, or raw external-rail payloads.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.tool(
    "zap1_check_anchor_freshness_at_height",
    "Check anchor age and confirmation depth from a receipt anchor height and a supplied current Zcash height. Stateless; does not call a node.",
    {
      anchor_height: z.number().int().nonnegative(),
      current_height: z.number().int().nonnegative(),
      min_confirmations: z.number().int().nonnegative().default(10),
    },
    async ({ anchor_height, current_height, min_confirmations }) => {
      const confirmations = current_height >= anchor_height ? current_height - anchor_height + 1 : 0;
      const heightArithmeticSufficient = confirmations >= min_confirmations;

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                fresh: false,
                height_arithmetic_sufficient: heightArithmeticSufficient,
                anchor_confirmed: false,
                anchor_height,
                current_height,
                confirmations,
                min_confirmations,
                status: heightArithmeticSufficient ? "unverified_height_sufficient" : "unverified_height_insufficient",
                boundary:
                  "This is arithmetic over caller-supplied heights only. It cannot confirm the txid, root commitment, block, or canonical-chain membership.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.tool(
    "zap1_verify_receipt_chain",
    "Validate a sequence of ZAP1 receipt packets and summarize whether all packets are well-formed and anchored.",
    {
      receipts: z.array(z.unknown()).min(1).max(50).describe("Receipt packets to validate in order."),
    },
    async ({ receipts }) => {
      const results = receipts.map((receipt, index) => {
        const validation = validateReceipt(receipt);
        return {
          index,
          valid: false,
          schema_valid: validation.valid,
          status: validation.valid ? validation.status : "malformed",
          anchor_reference_present: validation.valid ? validation.anchorReferencePresent : false,
          anchor_confirmed: false,
          leaf_hash: validation.valid ? validation.receipt.leaf_hash : null,
          event_type: validation.valid ? validation.receipt.event_type : null,
          errors: validation.valid ? [] : validation.errors,
          warnings: validation.valid ? validation.warnings : [],
        };
      });

      const allShapeValid = results.every((result) => result.schema_valid);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                valid: false,
                schema_valid: allShapeValid,
                status: allShapeValid ? "unverified_v1_chain" : "malformed_chain",
                count: results.length,
                all_anchored: false,
                anchor_confirmed: false,
                results,
                boundary:
                  "V1 chain validation is shape-only: it cannot recompute positioned proofs or confirm anchors, and it does not reconstruct workflow causality.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
  );

  server.tool(
    "zap1_compare_receipt_claims",
    "Compare two ZAP1 receipts and report whether subject, claim, evidence, event type, and anchor context match.",
    {
      left: z.unknown().describe("First ZAP1 receipt packet."),
      right: z.unknown().describe("Second ZAP1 receipt packet."),
    },
    async ({ left, right }) => {
      const leftValidation = validateReceipt(left);
      const rightValidation = validateReceipt(right);

      if (!leftValidation.valid || !rightValidation.valid) {
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  valid: false,
                  left: leftValidation,
                  right: rightValidation,
                },
                null,
                2
              ),
            },
          ],
          isError: true,
        };
      }

      const fields = ["event_type", "subject_hash", "claim_hash", "evidence_hash", "leaf_hash", "merkle_root", "anchor_txid", "anchor_height"] as const;
      const comparisons = Object.fromEntries(
        fields.map((field) => [
          field,
          {
            left: leftValidation.receipt[field] ?? null,
            right: rightValidation.receipt[field] ?? null,
            match: leftValidation.receipt[field] === rightValidation.receipt[field],
          },
        ])
      );
      const allMatch = Object.values(comparisons).every((entry) => entry.match);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                schema_valid: true,
                comparison_performed: true,
                cryptographic_verification_performed: false,
                all_match: allMatch,
                comparisons,
                boundary:
                  "Comparison only checks receipt claims and anchor context. It does not merge or arbitrate the underlying external workflow.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.tool(
    "zap1_audit_event_log",
    "Replay a small receipt sequence against an expected event-type policy. Stateless audit helper for agents and reviewers.",
    {
      receipts: z.array(z.unknown()).min(1).max(50),
      allowed_event_types: z.array(z.string().min(1).max(64)).min(1),
      require_anchored: z.boolean().default(false),
    },
    async ({ receipts, allowed_event_types, require_anchored }) => {
      const allowed = new Set(allowed_event_types);
      const results = receipts.map((receipt, index) => {
        const validation = validateReceipt(receipt);
        if (!validation.valid) {
          return {
            index,
            pass: false,
            reason: "malformed_receipt",
            errors: validation.errors,
          };
        }

        const typeAllowed = allowed.has(validation.receipt.event_type);
        const anchorOk = !require_anchored;

        return {
          index,
          pass: typeAllowed && anchorOk,
          event_type: validation.receipt.event_type,
          type_allowed: typeAllowed,
          anchor_ok: anchorOk,
          anchor_reference_present: validation.anchorReferencePresent,
          anchor_confirmed: false,
          status: validation.status,
          leaf_hash: validation.receipt.leaf_hash,
        };
      });

      const pass = results.every((result) => result.pass);

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                pass,
                metadata_policy_pass: pass,
                cryptographic_verification_performed: false,
                require_anchored,
                allowed_event_types,
                results,
                boundary:
                  "This audits v1 metadata against caller-supplied policy. V1 anchor references are never accepted as chain confirmation.",
              },
              null,
              2
            ),
          },
        ],
        isError: !pass,
      };
    }
  );
}
