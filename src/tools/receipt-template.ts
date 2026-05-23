import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const USE_CASES = {
  agent_action: {
    event_type: "AGENT_ACTION",
    intent: "Prove that an agent performed a named action with specific input and output hashes.",
    required_fields: ["agent_id", "action_type", "input_hash", "output_hash"],
    customer_value: "A receiver can verify the action receipt without trusting the agent runtime.",
  },
  payment_receipt: {
    event_type: "PAYMENT_RECEIPT",
    intent: "Bind invoice or payment metadata to a ZAP1 leaf and later prove inclusion under an anchored root.",
    required_fields: ["wallet_hash", "invoice_id", "amount_zat", "payment_reference_hash"],
    customer_value: "A payment flow gets an audit-grade receipt without giving this server custody or signing authority.",
  },
  operator_lifecycle: {
    event_type: "OPERATOR_EVENT",
    intent: "Record deployment, upgrade, incident, recovery, or policy state as a verifiable lifecycle event.",
    required_fields: ["operator_id", "action_type", "input_hash", "output_hash"],
    customer_value: "Operations teams can prove what changed and when without exposing private logs.",
  },
  policy_attestation: {
    event_type: "POLICY_ATTESTATION",
    intent: "Record an agent, service, or workflow policy decision as a verifiable event.",
    required_fields: ["agent_id", "policy_id", "decision_hash", "evidence_hash"],
    customer_value: "Downstream systems can check policy receipts before accepting an action.",
  },
} as const;

type UseCase = keyof typeof USE_CASES;

function buildTemplate(useCase: UseCase) {
  const selected = USE_CASES[useCase];

  return {
    use_case: useCase,
    positioning: "Wallet tools move value. ZAP1 proves the workflow around the value.",
    event_template: selected,
    recommended_flow: [
      {
        step: 1,
        tool: "zcash_capability_manifest",
        purpose: "Confirm this server is being used for attestation and proof verification, not custody or signing.",
      },
      {
        step: 2,
        tool: "attest_event",
        purpose: "Create the typed ZAP1 leaf for the workflow event.",
      },
      {
        step: 3,
        tool: "get_anchor_status",
        purpose: "Check whether the leaf is anchored or waiting under the current root.",
      },
      {
        step: 4,
        tool: "verify_proof",
        purpose: "Verify that the leaf exists in the ZAP1 attestation tree.",
      },
      {
        step: 5,
        tool: "zcash_prove_payment",
        purpose: "Fetch the proof bundle for handoff to another agent, user, auditor, or service.",
      },
    ],
    receipt_packet: {
      event_type: selected.event_type,
      leaf_hash: "64-char hex leaf hash returned by attest_event",
      merkle_root: "root returned by proof bundle",
      merkle_path: "ordered sibling path returned by proof bundle",
      anchor_txid: "Zcash transaction anchoring the root, when anchored",
      anchor_height: "Zcash block height for the anchor transaction, when known",
      verification_url: "ZAP1 verification endpoint for the leaf hash",
    },
    acceptance_checks: [
      "the receipt has a leaf_hash",
      "the leaf verifies under a returned Merkle root",
      "anchored receipts include an anchor txid or anchor height",
      "the verifier can repeat verification without trusting the original agent",
      "no private keys, seeds, PCZTs, or wallet scan state are sent to this server",
    ],
    red_team_rejects: [
      "request asks this server to sign a transaction",
      "request asks this server to hold or recover a seed",
      "request asks this server to scan balances as a source of wallet truth",
      "request treats a payment URI as proof of payment",
      "request treats an unanchored leaf as final settlement evidence",
    ],
  };
}

export function registerReceiptTemplateTool(server: McpServer) {
  server.tool(
    "zcash_receipt_template",
    "Return a customer-ready ZAP1 receipt workflow for agent actions, payment receipts, operator lifecycle events, or policy attestations.",
    {
      use_case: z
        .enum(["agent_action", "payment_receipt", "operator_lifecycle", "policy_attestation"])
        .default("agent_action")
        .describe("Receipt workflow to generate."),
    },
    async ({ use_case }) => ({
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(buildTemplate(use_case), null, 2),
        },
      ],
    })
  );
}
