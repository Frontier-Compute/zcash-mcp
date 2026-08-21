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
    assert.equal(tools.tools.length, 28, `${label}: tool count drifted`);

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
        action_type: "price_integrity_receipt_verified",
        status: "verification_completed",
        agent_id: "a".repeat(64),
        request_hash: "1".repeat(64),
        intent_hash: "2".repeat(64),
        quote_hash: "3".repeat(64),
        route_hash: "4".repeat(64),
        action_instance_commitment: "5".repeat(64),
        disclosed_fields: ["rail_id", "action_type", "status", "request_hash"],
        redaction_policy: "counterparty_visible",
      },
    });
    assert(!externalActionResult.isError, `${label}: zap1_attest_external_action returned an error`);
    const externalAction = parseJsonTextResult(externalActionResult);
    assert.equal(externalAction.use_case, "external_verification_receipt", `${label}: bad external action use case`);
    assert.equal(externalAction.external_action.status, "verification_completed", `${label}: bad external verification status`);
    assert.equal(externalAction.attest_event_args.event_type, "AGENT_ACTION", `${label}: unsupported external receipt event type`);
    assert.equal(externalAction.attest_event_args.agent_id, "a".repeat(64), `${label}: agent_id was not bridged`);
    assert.deepEqual(
      externalAction.zap1_agent_action_args,
      {
        agent_id: "a".repeat(64),
        action_type: "price_integrity_receipt_verified",
        input_hash: externalAction.hashes.claim_hash,
        output_hash: externalAction.hashes.evidence_hash,
      },
      `${label}: AGENT_ACTION mapping drifted`
    );
    assert.match(externalAction.hashes.claim_hash, /^[0-9a-f]{64}$/, `${label}: bad external claim hash`);
    assert.match(externalAction.hashes.expected_leaf_hash, /^[0-9a-f]{64}$/, `${label}: typed leaf was not precomputed`);
    assert.equal(
      externalAction.receipt_stub.leaf.hash,
      externalAction.hashes.expected_leaf_hash,
      `${label}: receipt stub did not retain the expected typed leaf`
    );
    assert.equal(
      externalAction.attest_event_args.expected_leaf_hash,
      externalAction.hashes.expected_leaf_hash,
      `${label}: attest handoff lost its local response-substitution guard`
    );
    assert.equal(externalAction.external_action.request_hash, "1".repeat(64), `${label}: request_hash was renamed or lost`);
    assert.equal(externalAction.external_action.quote_hash, "3".repeat(64), `${label}: quote_hash no longer means a real quote`);

    stage = "external action instance replay separation";
    const replaySeparatedResult = await client.callTool({
      name: "zap1_attest_external_action",
      arguments: {
        rail_id: "external-demo",
        action_type: "price_integrity_receipt_verified",
        status: "verification_completed",
        agent_id: "a".repeat(64),
        request_hash: "1".repeat(64),
        intent_hash: "2".repeat(64),
        quote_hash: "3".repeat(64),
        route_hash: "4".repeat(64),
        action_instance_commitment: "6".repeat(64),
        redaction_policy: "counterparty_visible",
      },
    });
    assert(!replaySeparatedResult.isError, `${label}: second action instance did not build`);
    const replaySeparated = parseJsonTextResult(replaySeparatedResult);
    assert.notEqual(
      replaySeparated.hashes.claim_hash,
      externalAction.hashes.claim_hash,
      `${label}: distinct salted action instances collapsed to one claim`
    );

    stage = "external action instance commitment guard";
    const unboundInstanceResult = await client.callTool({
      name: "zap1_attest_external_action",
      arguments: {
        rail_id: "external-demo",
        action_type: "price_integrity_receipt_verified",
        status: "verification_completed",
        agent_id: "a".repeat(64),
        request_hash: "1".repeat(64),
      },
    });
    assert(unboundInstanceResult.isError, `${label}: verification_completed accepted no instance commitment`);

    stage = "AGENT_ACTION local contract guard";
    const incompleteAgentActionResult = await client.callTool({
      name: "attest_event",
      arguments: {
        event_type: "AGENT_ACTION",
        wallet_hash: "a".repeat(64),
        action_type: "price_integrity_receipt_verified",
        input_hash: "b".repeat(64),
        output_hash: "c".repeat(64),
        api_key: "offline-contract-test",
      },
    });
    assert(incompleteAgentActionResult.isError, `${label}: AGENT_ACTION without agent_id escaped local validation`);

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
    assert(conformanceResult.isError, `${label}: v1 conformance falsely passed verification`);
    const conformance = parseJsonTextResult(conformanceResult);
    assert.equal(conformance.schema_valid, true, `${label}: sample v1 receipt shape did not validate`);
    assert.equal(conformance.valid, false, `${label}: v1 receipt falsely reported cryptographic validity`);
    assert.equal(conformance.acceptance_checks.anchor_confirmed, false, `${label}: fake v1 anchor metadata was trusted`);

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
    assert(externalVerifyResult.isError, `${label}: v1 shape-only receipt was falsely accepted`);
    const externalVerify = parseJsonTextResult(externalVerifyResult);
    assert.equal(externalVerify.schema_valid, true, `${label}: v1 receipt shape did not validate`);
    assert.equal(externalVerify.valid, false, `${label}: v1 receipt falsely claimed cryptographic validity`);
    assert.equal(externalVerify.anchor_confirmed, false, `${label}: fake v1 anchor metadata was trusted`);
    assert.equal(externalVerify.acceptance_ready, false, `${label}: v1 receipt falsely became acceptance-ready`);

    const validReceiptV2 = {
      schema_version: "zap1-receipt-v2",
      event_type: "AGENT_ACTION",
      profile: "counterparty_receipt",
      subject_hash: "a".repeat(64),
      claim_hash: "b".repeat(64),
      evidence_hash: "c".repeat(64),
      leaf: {
        hash: "0c3035ffe24cea43bed1384d2788e155c1516d9e5cd0f8e777879713e35014be",
        event_type: "AGENT_ACTION",
        agent_id: "a".repeat(64),
        action_type: "price_integrity_receipt_verified",
        input_hash: "b".repeat(64),
        output_hash: "c".repeat(64),
      },
      proof: [{ hash: "d".repeat(64), position: "right" }],
      root: {
        hash: "7a9bd7c0dcd7ca5feb01904fd4d5768b4bd6a34ec64e8f5e5432f417fa31ced0",
        leaf_count: 2,
        scheme: "ZAP1_COUNT_BOUND_V2",
      },
      anchor: { txid: "1".repeat(64), height: 123 },
      status: "verified",
      redaction_policy: "hash_only",
    };

    // Leaf/witness are the published ZAP1 AGENT_ACTION vector. The single-leaf
    // root is independently derived with the published count-bound v2 rule.
    const officialAgentActionWitness = {
      event_type: "AGENT_ACTION",
      agent_id: "agent_001",
      action_type: "tool_call",
      input_hash: "input_hash_001",
      output_hash: "output_hash_001",
    };
    const officialProofBundleV2 = {
      protocol: "ZAP1",
      version: "2",
      leaf: {
        hash: "d68620ccc6de6957ab6b01fe8830ac64e2e2c455b80ce4506ef41078bcbb76f6",
        event_type: "AGENT_ACTION",
        created_at: "2026-08-13T00:00:00Z",
        preimage_disclosure: "withheld from the public proof bundle",
        event_type_authentication: "unverified_server_metadata_without_disclosed_witness",
      },
      proof: [],
      root: {
        hash: "638ae58981d04c67ebf7379111059287af5935807989915f6173a6a185666bb4",
        leaf_count: 1,
        created_at: "2026-08-13T00:00:01Z",
        scheme: "ZAP1_COUNT_BOUND_V2",
        legacy_allowed: false,
        legacy_max_anchor_height: 3317133,
      },
      anchor: { txid: null, height: null },
      verify_command: "python3 examples/verify_proof.py proof.json",
    };

    stage = "official proof-bundle-v2 conformance vector";
    const officialBundleResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        proof_bundle: officialProofBundleV2,
        agent_action_witness: officialAgentActionWitness,
        expected_agent_id: "agent_001",
        expected_action_type: "tool_call",
        expected_input_hash: "input_hash_001",
        expected_output_hash: "output_hash_001",
      },
    });
    assert(!officialBundleResult.isError, `${label}: official AGENT_ACTION conformance vector failed`);
    const officialBundle = parseJsonTextResult(officialBundleResult);
    assert.equal(
      officialBundle.source_format,
      "official_proof_bundle_v2_with_witness",
      `${label}: official bundle source was not retained`
    );
    assert.equal(officialBundle.typed_witness_authenticated, true, `${label}: official typed witness did not authenticate`);
    assert.equal(officialBundle.cryptographic_inclusion_valid, true, `${label}: official count-bound bundle failed`);
    assert.equal(officialBundle.anchor_reference_present, false, `${label}: null anchor became a reference`);
    assert.equal(officialBundle.anchor_confirmed, false, `${label}: null anchor became confirmed`);
    assert.equal(officialBundle.acceptance_ready, false, `${label}: inclusion-only official bundle became acceptable`);
    assert.equal(
      Object.hasOwn(officialBundle.normalized_receipt, "anchor"),
      false,
      `${label}: null anchor was not omitted during normalization`
    );

    stage = "official proof-bundle typed witness mismatch";
    const officialWitnessMismatchResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        proof_bundle: officialProofBundleV2,
        agent_action_witness: { ...officialAgentActionWitness, output_hash: "substituted_output" },
      },
    });
    assert(officialWitnessMismatchResult.isError, `${label}: substituted official witness was accepted`);
    const officialWitnessMismatch = parseJsonTextResult(officialWitnessMismatchResult);
    assert.equal(officialWitnessMismatch.typed_leaf_valid, false, `${label}: witness substitution did not change leaf`);
    assert.equal(officialWitnessMismatch.valid, false, `${label}: witness substitution reported valid`);

    stage = "official proof-bundle count-bound scheme guard";
    const legacySchemeResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        proof_bundle: {
          ...officialProofBundleV2,
          root: {
            ...officialProofBundleV2.root,
            scheme: "ZAP1_LEGACY_DUPLICATE_ODD",
            legacy_allowed: true,
          },
        },
        agent_action_witness: officialAgentActionWitness,
      },
    });
    assert(legacySchemeResult.isError, `${label}: legacy scheme entered the v2 count-bound verifier`);
    assert.equal(parseJsonTextResult(legacySchemeResult).schema_valid, false, `${label}: legacy scheme passed v2 schema`);

    stage = "receipt-v2 cryptographic verifier";
    const v2Result = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: validReceiptV2,
        expected_agent_id: "a".repeat(64),
        expected_action_type: "price_integrity_receipt_verified",
        expected_input_hash: "b".repeat(64),
        expected_output_hash: "c".repeat(64),
      },
    });
    assert(!v2Result.isError, `${label}: valid receipt-v2 proof failed`);
    const v2 = parseJsonTextResult(v2Result);
    assert.equal(v2.typed_leaf_valid, true, `${label}: typed AGENT_ACTION leaf did not recompute`);
    assert.equal(v2.cryptographic_inclusion_valid, true, `${label}: count-bound proof did not recompute`);
    assert.equal(v2.anchor_reference_present, true, `${label}: anchor reference was not reported`);
    assert.equal(v2.anchor_confirmed, false, `${label}: fake txid/height/status confirmed an anchor`);
    assert.equal(v2.acceptance_ready, false, `${label}: inclusion-only receipt became acceptance-ready`);
    assert.equal(v2.status, "included_anchor_unverified", `${label}: anchor boundary status drifted`);

    stage = "receipt-v2 fake root rejection";
    const fakeRootResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: {
          ...validReceiptV2,
          root: { ...validReceiptV2.root, hash: "e".repeat(64) },
        },
      },
    });
    assert(fakeRootResult.isError, `${label}: fake Merkle root was accepted`);
    const fakeRoot = parseJsonTextResult(fakeRootResult);
    assert.equal(fakeRoot.valid, false, `${label}: fake Merkle root reported valid`);
    assert.equal(fakeRoot.root_valid, false, `${label}: fake Merkle root recomputed`);

    stage = "receipt-v2 sibling position rejection";
    const flippedPositionResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: {
          ...validReceiptV2,
          proof: [{ hash: "d".repeat(64), position: "left" }],
        },
      },
    });
    assert(flippedPositionResult.isError, `${label}: flipped sibling position was accepted`);
    assert.equal(parseJsonTextResult(flippedPositionResult).root_valid, false, `${label}: sibling position was ignored`);

    stage = "receipt-v2 leaf count binding rejection";
    const fakeLeafCountResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: {
          ...validReceiptV2,
          root: { ...validReceiptV2.root, leaf_count: 3 },
        },
      },
    });
    assert(fakeLeafCountResult.isError, `${label}: fake leaf_count was accepted`);
    assert.equal(parseJsonTextResult(fakeLeafCountResult).root_valid, false, `${label}: leaf_count was not bound to root`);

    stage = "receipt-v2 fake leaf rejection";
    const fakeLeafResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: {
          ...validReceiptV2,
          leaf: { ...validReceiptV2.leaf, hash: "f".repeat(64) },
        },
      },
    });
    assert(fakeLeafResult.isError, `${label}: fake typed leaf hash was accepted`);
    assert.equal(parseJsonTextResult(fakeLeafResult).typed_leaf_valid, false, `${label}: fake leaf hash recomputed`);

    stage = "receipt-v2 claim binding rejection";
    const fakeClaimResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: { receipt: { ...validReceiptV2, claim_hash: "f".repeat(64) } },
    });
    assert(fakeClaimResult.isError, `${label}: claim/input mismatch was accepted`);
    assert.equal(parseJsonTextResult(fakeClaimResult).binding_valid, false, `${label}: claim/input binding was skipped`);

    stage = "receipt-v2 valid single-leaf empty path";
    const singleLeafResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: {
          ...validReceiptV2,
          proof: [],
          root: {
            ...validReceiptV2.root,
            hash: "fcb4a0904be92a55da72c1fb78521f7486a403dd5b4d5260cb003dd3468370c0",
            leaf_count: 1,
          },
          anchor: undefined,
          status: "verification_completed",
        },
      },
    });
    assert(!singleLeafResult.isError, `${label}: legitimate single-leaf empty path failed`);
    const singleLeaf = parseJsonTextResult(singleLeafResult);
    assert.equal(singleLeaf.valid, true, `${label}: single-leaf proof did not verify`);
    assert.equal(singleLeaf.anchor_reference_present, false, `${label}: absent anchor reference was invented`);
    assert.equal(singleLeaf.status, "included_unanchored", `${label}: single-leaf anchor boundary drifted`);

    stage = "receipt-v2 empty path rejection";
    const emptyPathResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: { receipt: { ...validReceiptV2, proof: [] } },
    });
    assert(emptyPathResult.isError, `${label}: empty path with leaf_count=2 was accepted`);
    assert.equal(
      parseJsonTextResult(emptyPathResult).proof_topology_valid,
      false,
      `${label}: impossible proof topology passed`
    );

    stage = "receipt-v2 partial anchor rejection";
    const partialAnchorResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: { receipt: { ...validReceiptV2, anchor: { txid: "1".repeat(64) } } },
    });
    assert(partialAnchorResult.isError, `${label}: partial anchor metadata was accepted`);
    assert.equal(parseJsonTextResult(partialAnchorResult).schema_valid, false, `${label}: partial anchor passed schema`);

    stage = "proof artifact";
    const artifactResult = await client.callTool({
      name: "zap1_extract_proof_artifact",
      arguments: { receipt: sampleReceipt },
    });
    assert(!artifactResult.isError, `${label}: zap1_extract_proof_artifact returned an error`);
    const artifact = parseJsonTextResult(artifactResult);
    assert.equal(artifact.artifact_type, "zap1-proof-artifact", `${label}: bad proof artifact type`);
    assert.equal(artifact.proof_artifact.claim_hash, sampleReceipt.claim_hash, `${label}: artifact dropped claim binding`);

    const changedClaimArtifactResult = await client.callTool({
      name: "zap1_extract_proof_artifact",
      arguments: { receipt: { ...sampleReceipt, claim_hash: "9".repeat(64) } },
    });
    assert(!changedClaimArtifactResult.isError, `${label}: changed-claim proof artifact did not extract`);
    const changedClaimArtifact = parseJsonTextResult(changedClaimArtifactResult);
    assert.notEqual(
      changedClaimArtifact.artifact_hash,
      artifact.artifact_hash,
      `${label}: proof artifact hash omitted the claim/evidence binding`
    );

    stage = "anchor freshness";
    const freshnessResult = await client.callTool({
      name: "zap1_check_anchor_freshness_at_height",
      arguments: { anchor_height: 100, current_height: 120, min_confirmations: 10 },
    });
    assert(!freshnessResult.isError, `${label}: zap1_check_anchor_freshness_at_height returned an error`);
    const freshness = parseJsonTextResult(freshnessResult);
    assert.equal(freshness.height_arithmetic_sufficient, true, `${label}: height arithmetic should pass`);
    assert.equal(freshness.fresh, false, `${label}: caller-supplied heights falsely confirmed freshness`);
    assert.equal(freshness.anchor_confirmed, false, `${label}: caller-supplied heights falsely confirmed an anchor`);

    stage = "receipt chain verifier";
    const chainResult = await client.callTool({
      name: "zap1_verify_receipt_chain",
      arguments: { receipts: [sampleReceipt] },
    });
    assert(chainResult.isError, `${label}: v1 chain falsely passed cryptographic verification`);
    const chain = parseJsonTextResult(chainResult);
    assert.equal(chain.schema_valid, true, `${label}: v1 receipt-chain shape did not validate`);
    assert.equal(chain.valid, false, `${label}: v1 receipt chain falsely reported valid`);

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
    assert(auditResult.isError, `${label}: v1 anchor references passed require_anchored`);
    const audit = parseJsonTextResult(auditResult);
    assert.equal(audit.pass, false, `${label}: fake v1 anchor metadata passed audit`);

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
