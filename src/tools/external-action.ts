import { createHash } from "node:crypto";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

import { computeAgentActionLeafHex } from "./receipt-v2-verifier.js";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

const externalStatus = z.enum([
  "verification_completed",
  "verification_failed",
  "rail_pending",
  "rail_broadcasted",
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
        .describe("Bounded action type, for example price_integrity_receipt_verified."),
      status: externalStatus.describe("External action state being attested."),
      agent_id: z.string().regex(HEX_64, "agent_id must be a 64-char hash").optional(),
      request_hash: z
        .string()
        .regex(HEX_64, "request_hash must be 64-char hex")
        .optional()
        .describe("Hash of the verification request. Do not place this value in quote_hash."),
      intent_hash: z.string().regex(HEX_64, "intent_hash must be 64-char hex").optional(),
      quote_hash: z
        .string()
        .regex(HEX_64, "quote_hash must be 64-char hex")
        .optional()
        .describe("Hash of a real economic quote, if one exists; never an alias for request_hash."),
      route_hash: z.string().regex(HEX_64, "route_hash must be 64-char hex").optional(),
      action_instance_commitment: z
        .string()
        .regex(HEX_64, "action_instance_commitment must be 64-char hex")
        .optional()
        .describe("Unique salted commitment that prevents identical verification events from collapsing into one action instance."),
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
      if (
        input.status === "verification_completed" &&
        (!input.request_hash || !input.action_instance_commitment)
      ) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: verification_completed requires request_hash and a unique salted action_instance_commitment.",
            },
          ],
          isError: true,
        };
      }

      if (
        input.agent_id &&
        input.subject_hash &&
        input.agent_id.toLowerCase() !== input.subject_hash.toLowerCase()
      ) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: subject_hash must equal agent_id for the AGENT_ACTION receipt-v2 binding.",
            },
          ],
          isError: true,
        };
      }

      const externalAction = {
        rail_id: input.rail_id,
        action_type: input.action_type,
        status: input.status,
        request_hash: input.request_hash ?? null,
        intent_hash: input.intent_hash ?? null,
        quote_hash: input.quote_hash ?? null,
        route_hash: input.route_hash ?? null,
        action_instance_commitment: input.action_instance_commitment ?? null,
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
        input.agent_id ??
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
          request_hash: input.request_hash ?? null,
          intent_hash: input.intent_hash ?? null,
          quote_hash: input.quote_hash ?? null,
          route_hash: input.route_hash ?? null,
          action_instance_commitment: input.action_instance_commitment ?? null,
        });

      const evidenceHash =
        input.evidence_hash ??
        sha256Hex({
          domain: "zap1-external-action-evidence-v1",
          ...externalAction,
          claim_hash: claimHash,
        });

      const agentId = input.agent_id ?? subjectHash;
      const zap1AgentActionArgs = {
        agent_id: agentId,
        action_type: input.action_type,
        input_hash: claimHash,
        output_hash: evidenceHash,
      };
      const expectedLeafHash = computeAgentActionLeafHex(
        zap1AgentActionArgs.agent_id,
        zap1AgentActionArgs.action_type,
        zap1AgentActionArgs.input_hash,
        zap1AgentActionArgs.output_hash
      );

      const response = {
        use_case: "external_verification_receipt",
        boundary:
          "The external rail executes the action. ZAP1 binds bounded evidence into a receipt request and later proves inclusion. No routing, swapping, signing, custody, broadcast, settlement, keys, balances, or raw private payloads enter ZAP1.",
        trust_boundary:
          "A wrapper makes you trust the server. ZAP1 makes the server unnecessary to trust.",
        external_action: externalAction,
        hashes: {
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
          expected_leaf_hash: expectedLeafHash,
        },
        zap1_agent_action_args: zap1AgentActionArgs,
        attest_event_args: {
          event_type: "AGENT_ACTION",
          wallet_hash: subjectHash,
          ...zap1AgentActionArgs,
          expected_leaf_hash: expectedLeafHash,
        },
        receipt_stub: {
          schema_version: "zap1-receipt-v2",
          event_type: "AGENT_ACTION",
          profile: input.redaction_policy === "hash_only" ? "public_hash_only" : "counterparty_receipt",
          subject_hash: subjectHash,
          claim_hash: claimHash,
          evidence_hash: evidenceHash,
          leaf: {
            hash: expectedLeafHash,
            event_type: "AGENT_ACTION",
            ...zap1AgentActionArgs,
          },
          proof: [{ hash: "replace with each sibling hash", position: "left or right" }],
          root: {
            hash: "replace with the count-bound root",
            leaf_count: "replace with the committed leaf count",
            scheme: "ZAP1_COUNT_BOUND_V2",
          },
          anchor: "optional reference only; confirmation requires a separately verified anchor-opening artifact",
          disclosed_fields: input.disclosed_fields,
          redaction_policy: input.redaction_policy,
        },
        next_steps: [
          "Call attest_event with attest_event_args when write authority is explicitly allowed.",
          "Reject the attest_event response unless its leaf_hash exactly equals hashes.expected_leaf_hash.",
          "Call get_anchor_status to determine whether the new leaf is anchored or pending.",
          "Call zap1_prove_receipt with the returned leaf_hash when a handoff proof is needed.",
          "Preserve each Merkle sibling position and the committed leaf_count in the final zap1-receipt-v2 packet.",
          "Call zap1_verify_receipt_v2 on the final packet to recompute the typed leaf and count-bound root.",
          "Verify any Zcash anchor separately from a complete anchor-opening artifact and independent chain state.",
        ],
        red_team_rejects: [
          "Do not send private keys, seeds, viewing keys, balances, raw customer rows, raw route payloads, or venue credentials.",
          "Do not treat a quote, route, or intent hash as settlement evidence by itself.",
          "Do not translate verification_completed into rail_settled; it means only that the external verifier completed its bounded check.",
          "Do not claim ZAP1 audited, operated, or guaranteed the external rail.",
        ],
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    }
  );
}
