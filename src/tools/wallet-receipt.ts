import { createHash } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .filter((key) => record[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
    .join(",")}}`;
}

function sha256Hex(value: unknown): string {
  const input = typeof value === "string" ? value : canonicalize(value);
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function registerWalletReceiptTool(server: McpServer) {
  server.tool(
    "zap1_wallet_receipt_request",
    "Build a ZAP1 receipt request from a wallet-layer action result. The wallet keeps custody, signing, scanning, and broadcast; ZAP1 receives only bounded hashes.",
    {
      wallet_provider: z
        .string()
        .min(1)
        .max(64)
        .describe("Wallet, service, or product producing the action result, for example a wallet MCP, mobile wallet, service wallet, or custom product."),
      action_type: z
        .string()
        .min(1)
        .max(64)
        .describe("Wallet-layer action type, for example shielded_send, invoice_paid, pczt_created, policy_approved, or sync_checkpoint."),
      action_status: z
        .enum(["requested", "approved", "submitted", "confirmed", "completed", "failed"])
        .default("completed")
        .describe("Wallet-layer action state being attested."),
      action_reference: z
        .string()
        .max(128)
        .optional()
        .describe("Wallet-local action, operation, invoice, quote, or policy reference. Hash first if sensitive."),
      txid: z
        .string()
        .regex(HEX_64, "txid must be 64-char hex")
        .optional()
        .describe("Optional public Zcash transaction id when the wallet action produced one."),
      amount_zat: z
        .number()
        .int()
        .nonnegative()
        .optional()
        .describe("Optional amount in zatoshis. Omit when amount should stay private."),
      asset_code: z
        .string()
        .max(32)
        .default("ZEC")
        .describe("Asset code or application asset label. Keep generic if the asset label is sensitive."),
      observed_at: z
        .string()
        .max(64)
        .optional()
        .describe("Optional ISO timestamp or block reference for the wallet observation."),
      subject_hash: z
        .string()
        .regex(HEX_64, "subject_hash must be 64-char hex")
        .optional()
        .describe("Optional precomputed hash of the wallet, user, or account subject. Use this to avoid sharing identifiers."),
      claim_hash: z
        .string()
        .regex(HEX_64, "claim_hash must be 64-char hex")
        .optional()
        .describe("Optional precomputed hash of the wallet action claim."),
      evidence_hash: z
        .string()
        .regex(HEX_64, "evidence_hash must be 64-char hex")
        .optional()
        .describe("Optional precomputed hash of the supporting evidence packet."),
      result_hash: z
        .string()
        .regex(HEX_64, "result_hash must be 64-char hex")
        .optional()
        .describe("Optional hash of the wallet result object, log packet, or receipt returned by the wallet layer."),
    },
    async (input) => {
      const subjectHash =
        input.subject_hash ??
        sha256Hex({
          domain: "zap1-wallet-subject-v1",
          wallet_provider: input.wallet_provider,
          action_reference: input.action_reference ?? null,
        });

      const claimHash =
        input.claim_hash ??
        sha256Hex({
          domain: "zap1-wallet-claim-v1",
          wallet_provider: input.wallet_provider,
          action_type: input.action_type,
          action_status: input.action_status,
          action_reference: input.action_reference ?? null,
          txid: input.txid ?? null,
          amount_zat: input.amount_zat ?? null,
          asset_code: input.asset_code,
          observed_at: input.observed_at ?? null,
        });

      const evidenceHash =
        input.evidence_hash ??
        sha256Hex({
          domain: "zap1-wallet-evidence-v1",
          wallet_provider: input.wallet_provider,
          action_type: input.action_type,
          action_status: input.action_status,
          claim_hash: claimHash,
          result_hash: input.result_hash ?? null,
          txid: input.txid ?? null,
        });

      const serial = input.action_reference ?? input.txid ?? claimHash.slice(0, 32);

      const response = {
        use_case: "wallet_action_receipt",
        boundary:
          "Wallet executes the action. ZAP1 records a bounded receipt request and later proves inclusion. No keys, seeds, PCZTs, wallet scan state, or spend authority enter ZAP1.",
        trust_boundary:
          "A wrapper makes you trust the server. ZAP1 makes the server unnecessary to trust.",
        wallet_action: {
          wallet_provider: input.wallet_provider,
          action_type: input.action_type,
          action_status: input.action_status,
          action_reference: input.action_reference ?? null,
          txid: input.txid ?? null,
          amount_zat: input.amount_zat ?? null,
          asset_code: input.asset_code,
          observed_at: input.observed_at ?? null,
        },
        hashes: {
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
          result_hash: input.result_hash ?? null,
        },
        attest_event_args: {
          event_type: "WALLET_ACTION_RECEIPT",
          wallet_hash: subjectHash,
          serial_number: serial,
          action_type: input.action_type,
          input_hash: claimHash,
          output_hash: evidenceHash,
        },
        receipt_stub: {
          schema_version: "zap1-receipt-v1",
          event_type: "WALLET_ACTION_RECEIPT",
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
          leaf_hash: "returned by attest_event",
          merkle_root: "returned by proof bundle",
          merkle_path: [],
          anchor_txid: "present after anchoring",
          anchor_height: "present when known",
          verification_url: "present after leaf is accepted",
        },
        next_steps: [
          "Call attest_event with attest_event_args.",
          "Call get_anchor_status to see whether the new leaf is anchored or pending.",
          "Call zap1_prove_receipt with the returned leaf_hash once a handoff proof is needed.",
          "Call zcash_conformance_check on the final receipt packet before another service accepts it.",
        ],
        red_team_rejects: [
          "Do not send private keys, seeds, PCZTs, viewing keys, balances, raw customer rows, or raw payment data.",
          "Do not treat a wallet action result as a ZAP1 proof until attest_event returns a leaf and the receipt verifies.",
          "Do not treat an unanchored leaf as settlement finality.",
        ],
      };

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(response, null, 2),
          },
        ],
      };
    }
  );
}
