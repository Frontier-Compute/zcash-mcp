import { createHash } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

const externalStatus = z.enum([
  "rail_pending",
  "rail_broadcasted",
  "rail_settled",
  "rail_failed",
  "rail_refunded",
]);

const redactionPolicy = z.enum([
  "hash_only",
  "counterparty_visible",
  "auditor_visible",
  "operator_private",
  "grant_public",
  "compliance_limited",
]);

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

export function registerExternalActionTool(server: McpServer) {
  server.tool(
    "zap1_attest_external_action",
    "Build a ZAP1 receipt request for an action executed by an external rail. ZAP1 does not route, swap, sign, custody, broadcast, or settle the action.",
    {
      rail_id: z
        .string()
        .min(1)
        .max(64)
        .describe("Generic external rail or integration identifier. Avoid partner claims unless they are public and authorized."),
      action_type: z
        .string()
        .min(1)
        .max(64)
        .describe("External action type, for example cross_chain_route_completed, spending_policy_enforced, or validator_outcome_settled."),
      status: externalStatus.describe("External action state being attested."),
      intent_hash: z.string().regex(HEX_64, "intent_hash must be 64-char hex").optional(),
      quote_hash: z.string().regex(HEX_64, "quote_hash must be 64-char hex").optional(),
      route_hash: z.string().regex(HEX_64, "route_hash must be 64-char hex").optional(),
      origin_txid: z.string().regex(HEX_64, "origin_txid must be 64-char hex").optional(),
      settlement_txid: z.string().regex(HEX_64, "settlement_txid must be 64-char hex").optional(),
      destination_txid: z.string().regex(HEX_64, "destination_txid must be 64-char hex").optional(),
      disclosed_fields: z
        .array(z.string().min(1).max(64))
        .default([])
        .describe("Fields intentionally disclosed to the receiver."),
      redaction_policy: redactionPolicy.default("hash_only").describe("Receipt disclosure profile applied to withheld fields."),
      counterparty_digest: z.string().regex(HEX_64, "counterparty_digest must be 64-char hex").optional(),
      operator_digest: z.string().regex(HEX_64, "operator_digest must be 64-char hex").optional(),
      subject_hash: z.string().regex(HEX_64, "subject_hash must be 64-char hex").optional(),
      claim_hash: z.string().regex(HEX_64, "claim_hash must be 64-char hex").optional(),
      evidence_hash: z.string().regex(HEX_64, "evidence_hash must be 64-char hex").optional(),
    },
    async (input) => {
      const externalAction = {
        rail_id: input.rail_id,
        action_type: input.action_type,
        status: input.status,
        intent_hash: input.intent_hash ?? null,
        quote_hash: input.quote_hash ?? null,
        route_hash: input.route_hash ?? null,
        origin_txid: input.origin_txid ?? null,
        settlement_txid: input.settlement_txid ?? null,
        destination_txid: input.destination_txid ?? null,
        disclosed_fields: input.disclosed_fields,
        redaction_policy: input.redaction_policy,
        counterparty_digest: input.counterparty_digest ?? null,
        operator_digest: input.operator_digest ?? null,
      };

      const subjectHash =
        input.subject_hash ??
        sha256Hex({
          domain: "zap1-external-action-subject-v1",
          rail_id: input.rail_id,
          counterparty_digest: input.counterparty_digest ?? null,
          operator_digest: input.operator_digest ?? null,
        });

      const claimHash =
        input.claim_hash ??
        sha256Hex({
          domain: "zap1-external-action-claim-v1",
          rail_id: input.rail_id,
          action_type: input.action_type,
          status: input.status,
          intent_hash: input.intent_hash ?? null,
          quote_hash: input.quote_hash ?? null,
          route_hash: input.route_hash ?? null,
        });

      const evidenceHash =
        input.evidence_hash ??
        sha256Hex({
          domain: "zap1-external-action-evidence-v1",
          ...externalAction,
          claim_hash: claimHash,
        });

      const serial =
        input.settlement_txid ??
        input.destination_txid ??
        input.origin_txid ??
        input.route_hash ??
        claimHash.slice(0, 32);

      const response = {
        use_case: "external_action_receipt",
        boundary:
          "The external rail executes the action. ZAP1 binds bounded evidence into a receipt request and later proves inclusion. No routing, swapping, signing, custody, broadcast, settlement, keys, balances, or raw private payloads enter ZAP1.",
        trust_boundary:
          "A wrapper makes you trust the server. ZAP1 makes the server unnecessary to trust.",
        external_action: externalAction,
        hashes: {
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
        },
        attest_event_args: {
          event_type: "EXTERNAL_ACTION_RECEIPT",
          wallet_hash: subjectHash,
          serial_number: serial,
          action_type: input.action_type,
          input_hash: claimHash,
          output_hash: evidenceHash,
        },
        receipt_stub: {
          schema_version: "zap1-receipt-v1",
          event_type: "EXTERNAL_ACTION_RECEIPT",
          profile: input.redaction_policy === "hash_only" ? "public_hash_only" : "counterparty_receipt",
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
          leaf_hash: "returned by attest_event",
          merkle_root: "returned by proof bundle",
          merkle_path: [],
          anchor_txid: "present after anchoring",
          anchor_height: "present when known",
          verification_url: "present after leaf is accepted",
          disclosed_fields: input.disclosed_fields,
          redaction_policy: input.redaction_policy,
        },
        next_steps: [
          "Call attest_event with attest_event_args when write authority is explicitly allowed.",
          "Call get_anchor_status to determine whether the new leaf is anchored or pending.",
          "Call zap1_prove_receipt with the returned leaf_hash when a handoff proof is needed.",
          "Call zap1_verify_external_receipt on the final packet before another service accepts it.",
        ],
        red_team_rejects: [
          "Do not send private keys, seeds, viewing keys, balances, raw customer rows, raw route payloads, or venue credentials.",
          "Do not treat a quote, route, or intent hash as settlement evidence by itself.",
          "Do not claim ZAP1 audited, operated, or guaranteed the external rail.",
        ],
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    }
  );
}
