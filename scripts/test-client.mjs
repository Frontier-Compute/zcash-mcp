import assert from "node:assert/strict";
import process from "node:process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  assertDecodeMemoResult,
  assertToolRegistration,
  parseJsonTextResult,
} from "./test-helpers.mjs";

export async function runMcpSmokeTest(serverEntry, { cwd, label }) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    cwd,
    env: { ...process.env },
    stderr: "pipe",
  });

  let stderr = "";
  const stderrStream = transport.stderr;
  if (stderrStream && typeof stderrStream.on === "function") {
    if (typeof stderrStream.setEncoding === "function") {
      stderrStream.setEncoding("utf8");
    }
    stderrStream.on("data", (chunk) => {
      stderr += chunk.toString();
    });
  }

  const client = new Client({
    name: "zcash-mcp-smoke",
    version: "0.2.0",
  });
  let stage = "connect";

  try {
    await client.connect(transport);

    stage = "server metadata";
    const serverInfo = client.getServerVersion();
    assert(serverInfo, `${label}: server did not report version metadata`);
    assert.equal(serverInfo.name, "zcash-mcp", `${label}: unexpected server name`);
    assert.match(serverInfo.version, /^\d+\.\d+\.\d+/, `${label}: invalid server version`);

    stage = "list tools";
    const tools = await client.listTools();
    assertToolRegistration(tools.tools);
    assert.equal(tools.tools.length, 27, `${label}: tool count drifted`);

    stage = "capability manifest";
    const capabilityResult = await client.callTool({
      name: "zcash_capability_manifest",
      arguments: {},
    });
    assert(!capabilityResult.isError, `${label}: zcash_capability_manifest returned an error`);
    const manifest = parseJsonTextResult(capabilityResult);
    assert.equal(manifest.posture, "attestation_layer_not_wallet", `${label}: bad capability posture`);
    assert(manifest.wallet_boundary.out_of_scope.includes("PCZT signing"), `${label}: missing wallet boundary`);

    stage = "receipt template";
    const receiptTemplateResult = await client.callTool({
      name: "zcash_receipt_template",
      arguments: { use_case: "payment_receipt" },
    });
    assert(!receiptTemplateResult.isError, `${label}: zcash_receipt_template returned an error`);
    const receiptTemplate = parseJsonTextResult(receiptTemplateResult);
    assert.equal(receiptTemplate.event_template.event_type, "PAYMENT_RECEIPT", `${label}: bad receipt use case`);
    assert(
      receiptTemplate.acceptance_checks.includes("the verifier can repeat verification without trusting the original agent"),
      `${label}: missing customer verification check`
    );

    stage = "wallet receipt request";
    const walletReceiptResult = await client.callTool({
      name: "zap1_wallet_receipt_request",
      arguments: {
        wallet_provider: "wallet-demo",
        action_type: "shielded_send",
        action_status: "confirmed",
        action_reference: "op-123",
        txid: "2".repeat(64),
        amount_zat: 1000,
        result_hash: "3".repeat(64),
      },
    });
    assert(!walletReceiptResult.isError, `${label}: zap1_wallet_receipt_request returned an error`);
    const walletReceipt = parseJsonTextResult(walletReceiptResult);
    assert.equal(walletReceipt.use_case, "wallet_action_receipt", `${label}: bad wallet receipt use case`);
    assert.equal(walletReceipt.attest_event_args.event_type, "WALLET_ACTION_RECEIPT", `${label}: bad wallet receipt event type`);
    assert.match(walletReceipt.hashes.subject_hash, /^[0-9a-f]{64}$/, `${label}: bad wallet subject hash`);
    assert(
      walletReceipt.next_steps.includes("Call attest_event with attest_event_args."),
      `${label}: missing attest_event next step`
    );

    stage = "external action receipt request";
    const externalActionResult = await client.callTool({
      name: "zap1_attest_external_action",
      arguments: {
        rail_id: "external-demo",
        action_type: "cross_chain_route_completed",
        status: "rail_settled",
        intent_hash: "a".repeat(64),
        quote_hash: "b".repeat(64),
        route_hash: "c".repeat(64),
        settlement_txid: "2".repeat(64),
        disclosed_fields: ["rail_id", "action_type", "status", "settlement_txid"],
        redaction_policy: "counterparty_visible",
      },
    });
    assert(!externalActionResult.isError, `${label}: zap1_attest_external_action returned an error`);
    const externalAction = parseJsonTextResult(externalActionResult);
    assert.equal(externalAction.use_case, "external_action_receipt", `${label}: bad external action use case`);
    assert.equal(externalAction.attest_event_args.event_type, "EXTERNAL_ACTION_RECEIPT", `${label}: bad external receipt event type`);
    assert.match(externalAction.hashes.claim_hash, /^[0-9a-f]{64}$/, `${label}: bad external claim hash`);

    stage = "conformance check";
    const conformanceResult = await client.callTool({
      name: "zcash_conformance_check",
      arguments: {
        receipt: {
          schema_version: "zap1-receipt-v1",
          event_type: "OPERATOR_EVENT",
          subject_hash: "a".repeat(64),
          claim_hash: "b".repeat(64),
          evidence_hash: "c".repeat(64),
          leaf_hash: "d".repeat(64),
          merkle_root: "e".repeat(64),
          merkle_path: ["f".repeat(64)],
          anchor_txid: "1".repeat(64),
          anchor_height: 123,
          verification_url: "https://api.frontiercompute.cash/verify/" + "d".repeat(64),
        },
      },
    });
    assert(!conformanceResult.isError, `${label}: zcash_conformance_check returned an error`);
    const conformance = parseJsonTextResult(conformanceResult);
    assert.equal(conformance.valid, true, `${label}: sample receipt did not validate`);
    assert.equal(conformance.status, "anchored", `${label}: sample receipt should be anchored`);

    const sampleReceipt = {
      schema_version: "zap1-receipt-v1",
      event_type: "EXTERNAL_ACTION_RECEIPT",
      profile: "counterparty_receipt",
      subject_hash: "a".repeat(64),
      claim_hash: "b".repeat(64),
      evidence_hash: "c".repeat(64),
      leaf_hash: "d".repeat(64),
      merkle_root: "e".repeat(64),
      merkle_path: ["f".repeat(64)],
      anchor_txid: "1".repeat(64),
      anchor_height: 123,
      verification_url: "https://api.frontiercompute.cash/verify/" + "d".repeat(64),
      disclosed_fields: ["event_type", "profile", "anchor_txid"],
      redaction_policy: "counterparty_visible",
    };

    stage = "external receipt verifier";
    const externalVerifyResult = await client.callTool({
      name: "zap1_verify_external_receipt",
      arguments: {
        receipt: sampleReceipt,
        expected_event_type: "EXTERNAL_ACTION_RECEIPT",
        expected_profile: "counterparty_receipt",
      },
    });
    assert(!externalVerifyResult.isError, `${label}: zap1_verify_external_receipt returned an error`);
    const externalVerify = parseJsonTextResult(externalVerifyResult);
    assert.equal(externalVerify.valid, true, `${label}: external receipt did not validate`);

    stage = "proof artifact";
    const artifactResult = await client.callTool({
      name: "zap1_extract_proof_artifact",
      arguments: { receipt: sampleReceipt },
    });
    assert(!artifactResult.isError, `${label}: zap1_extract_proof_artifact returned an error`);
    const artifact = parseJsonTextResult(artifactResult);
    assert.equal(artifact.artifact_type, "zap1-proof-artifact", `${label}: bad proof artifact type`);

    stage = "anchor freshness";
    const freshnessResult = await client.callTool({
      name: "zap1_check_anchor_freshness_at_height",
      arguments: { anchor_height: 100, current_height: 120, min_confirmations: 10 },
    });
    assert(!freshnessResult.isError, `${label}: zap1_check_anchor_freshness_at_height returned an error`);
    const freshness = parseJsonTextResult(freshnessResult);
    assert.equal(freshness.fresh, true, `${label}: anchor freshness should pass`);

    stage = "receipt chain verifier";
    const chainResult = await client.callTool({
      name: "zap1_verify_receipt_chain",
      arguments: { receipts: [sampleReceipt] },
    });
    assert(!chainResult.isError, `${label}: zap1_verify_receipt_chain returned an error`);
    const chain = parseJsonTextResult(chainResult);
    assert.equal(chain.valid, true, `${label}: receipt chain did not validate`);

    stage = "receipt claim compare";
    const compareResult = await client.callTool({
      name: "zap1_compare_receipt_claims",
      arguments: { left: sampleReceipt, right: sampleReceipt },
    });
    assert(!compareResult.isError, `${label}: zap1_compare_receipt_claims returned an error`);
    const compare = parseJsonTextResult(compareResult);
    assert.equal(compare.all_match, true, `${label}: identical receipts did not match`);

    stage = "event log audit";
    const auditResult = await client.callTool({
      name: "zap1_audit_event_log",
      arguments: {
        receipts: [sampleReceipt],
        allowed_event_types: ["EXTERNAL_ACTION_RECEIPT"],
        require_anchored: true,
      },
    });
    assert(!auditResult.isError, `${label}: zap1_audit_event_log returned an error`);
    const audit = parseJsonTextResult(auditResult);
    assert.equal(audit.pass, true, `${label}: receipt audit did not pass`);

    stage = "ping";
    await client.ping();

    stage = "decode_memo";
    const memoResult = await client.callTool({
      name: "decode_memo",
      arguments: {
        memo: Buffer.from("hello world", "utf8").toString("hex"),
      },
    });
    assert(!memoResult.isError, `${label}: decode_memo returned an error`);
    assertDecodeMemoResult(parseJsonTextResult(memoResult));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const suffix = stderr.trim() ? `\nserver stderr:\n${stderr.trim()}` : "";
    throw new Error(`${label} failed during ${stage}: ${message}${suffix}`);
  } finally {
    await transport.close().catch(() => {});
  }
}
