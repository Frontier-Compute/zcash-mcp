import assert from "node:assert/strict";
import { createServer } from "node:http";
import path from "node:path";
import process from "node:process";
import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { computeAgentActionLeafHex, computeCountBoundRootHex } from "../../dist/tools/receipt-v2-verifier.js";

import { createInMemoryReplayGuard, verifyAndBuildZap1ReceiverBinding } from "./adapter.mjs";
import { assembleZap1ReceiptV2 } from "./receipt-v2.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const readJson = async (...parts) => JSON.parse(await readFile(path.join(here, ...parts), "utf8"));

export async function runMcpContractTest(expectedBinding = null) {
  const [provenance, unitContract, actionInstance, fixtureManifest, registry, receipt, proofShape] = await Promise.all([
    readJson("BASE-PROVENANCE.json"),
    readJson("UNIT-CONTRACT.json"),
    readJson("ACTION-INSTANCE.json"),
    readJson("fixtures", "FIXTURE-MANIFEST.json"),
    readJson("fixtures", "registry-20260821.json"),
    readJson("fixtures", "oracle-safety-valid-20260821.json"),
    readJson("PROOF-SHAPE-PROVENANCE.json"),
  ]);
  const repositoryRoot = path.resolve(here, provenance.zcash_mcp.repository_root_relative);
  const relativePackagePath = path.relative(repositoryRoot, here).replaceAll(path.sep, "/");
  assert.equal(relativePackagePath, "examples/insight-zap1-receiver-v1");
  const serverEntrypoint = path.join(repositoryRoot, provenance.zcash_mcp.server_entrypoint_after_build);
  await Promise.all([
    access(path.join(repositoryRoot, "package.json")),
    access(path.join(repositoryRoot, provenance.zcash_mcp.critical_contract_source)),
    access(serverEntrypoint),
  ]);
  const validMeta = fixtureManifest.vectors.find((vector) => vector.label === "FRESHLY_SIGNED_REPRESENTATIVE_DEMO_SNAPSHOT");
  const registryBodyB64 = await readFile(path.join(here, "fixtures", "registry-20260821.body.b64"), "utf8");
  const registryRaw = Buffer.from(registryBodyB64.replace(/\s/g, ""), "base64");
  const receiverResult = verifyAndBuildZap1ReceiverBinding({
    receipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
    replayGuard: createInMemoryReplayGuard(),
  });
  assert.equal(receiverResult.ok, true, JSON.stringify(receiverResult.verification.failures));
  const binding = expectedBinding ?? receiverResult.binding;
  assert.equal(proofShape.classification, "LIVE_DEPLOYED_SHAPE_ONLY");
  assert.equal(proofShape.source_body_sha256, "79ddc37c89868ba15d3154ce3cc97b765bb94c294f099477941053e0213c4340");

  const agentAction = binding.zap1_agent_action_args;
  const syntheticLeafHash = computeAgentActionLeafHex(
    agentAction.agent_id,
    agentAction.action_type,
    agentAction.input_hash,
    agentAction.output_hash,
  );
  const syntheticRootHash = computeCountBoundRootHex(syntheticLeafHash, 1);
  const structuralProofBundle = {
    protocol: "ZAP1",
    version: "2",
    leaf: {
      hash: syntheticLeafHash,
      event_type: "AGENT_ACTION",
      created_at: "2026-08-21T10:00:10.000Z",
      event_type_authentication: "unverified_server_metadata_without_disclosed_witness",
      preimage_disclosure: "withheld from the public proof bundle",
    },
    proof: [],
    root: {
      hash: syntheticRootHash,
      leaf_count: 1,
      scheme: "ZAP1_COUNT_BOUND_V2",
      created_at: "2026-08-21T10:00:11.000Z",
      legacy_allowed: false,
      legacy_max_anchor_height: 3317133,
    },
    anchor: { txid: null, height: null },
    verify_command: "structural local conformance fixture; no network action",
  };
  const receiptV2 = assembleZap1ReceiptV2({ binding, proofBundle: structuralProofBundle });
  assert.equal(Object.hasOwn(receiptV2, "anchor"), false);
  const partialAnchor = structuredClone(structuralProofBundle);
  partialAnchor.anchor = { txid: null, height: 3317134 };
  assert.throws(() => assembleZap1ReceiptV2({ binding, proofBundle: partialAnchor }), /anchor must be either fully null/);

  const wireRequests = [];
  const mockApi = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    wireRequests.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      body,
    });
    if (request.headers.authorization === "Bearer local-oversize-key") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ padding: "x".repeat(65 * 1024) }));
      return;
    }
    if (request.headers.authorization === "Bearer local-wrong-type-key") {
      response.writeHead(200, { "Content-Type": "text/plain" });
      response.end(JSON.stringify({ leaf_hash: "f".repeat(64) }));
      return;
    }
    const leafHash = computeAgentActionLeafHex(
      body.agent_id,
      body.action_type,
      body.input_hash,
      body.output_hash,
    );
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ leaf_hash: leafHash, accepted: true }));
  });
  await new Promise((resolve, reject) => {
    mockApi.once("error", reject);
    mockApi.listen(0, "127.0.0.1", resolve);
  });
  const mockAddress = mockApi.address();
  assert(mockAddress && typeof mockAddress === "object", "local mock API did not bind");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntrypoint],
    cwd: repositoryRoot,
    env: {
      ...process.env,
      ZAP1_API_URL: "http://127.0.0.1:" + mockAddress.port,
    },
    stderr: "pipe",
  });
  const client = new Client({ name: "insight-zap1-receiver-v1", version: "0.1.0" });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "zap1_attest_external_action", arguments: binding.zap1_external_action_args });
    assert.notEqual(result.isError, true);
    const content = result.content.find((item) => item.type === "text")?.text;
    assert(content, "MCP tool returned no text content");
    const packet = JSON.parse(content);
    assert.equal(packet.attest_event_args.event_type, "AGENT_ACTION");
    assert.equal(packet.hashes.subject_hash, binding.zap1_hashes.subject_hash);
    assert.equal(packet.hashes.claim_hash, binding.zap1_hashes.claim_hash);
    assert.equal(packet.hashes.evidence_hash, binding.zap1_hashes.evidence_hash);
    assert.equal(packet.hashes.expected_leaf_hash, syntheticLeafHash);
    assert.deepEqual(packet.zap1_agent_action_args, binding.zap1_agent_action_args);
    assert.equal(packet.external_action.status, "verification_completed");
    assert.equal(packet.external_action.request_hash, binding.zap1_external_action_args.request_hash);
    assert.equal(packet.external_action.quote_hash, null);
    assert(packet.next_steps.some((step) => step.includes("attest_event")));
    assert(packet.next_steps.some((step) => step.includes("zap1_prove_receipt")));

    const localAttestResult = await client.callTool({
      name: "attest_event",
      arguments: {
        ...packet.attest_event_args,
        api_key: "local-mock-only-key",
      },
    });
    assert.notEqual(localAttestResult.isError, true, "exact binding did not reach the local /event mock");
    const localAttestContent = localAttestResult.content.find((item) => item.type === "text")?.text;
    assert(localAttestContent, "local attest response had no text content");
    const localAttest = JSON.parse(localAttestContent);
    assert.equal(localAttest.leaf_hash, syntheticLeafHash);
    assert.equal(wireRequests.length, 1);
    assert.equal(wireRequests[0].method, "POST");
    assert.equal(wireRequests[0].url, "/event");
    assert.equal(wireRequests[0].authorization, "Bearer local-mock-only-key");
    const { expected_leaf_hash: _localExpectedLeaf, ...expectedWireBody } = packet.attest_event_args;
    assert.deepEqual(wireRequests[0].body, expectedWireBody);
    assert.equal(Object.hasOwn(wireRequests[0].body, "expected_leaf_hash"), false);

    const substitutedResponseResult = await client.callTool({
      name: "attest_event",
      arguments: {
        ...expectedWireBody,
        expected_leaf_hash: "0".repeat(64),
        api_key: "local-mock-only-key",
      },
    });
    assert.equal(substitutedResponseResult.isError, true, "substituted response leaf escaped the local guard");
    const substitutedContent = substitutedResponseResult.content.find((item) => item.type === "text")?.text;
    assert(substitutedContent, "substitution rejection had no text content");
    assert.equal(JSON.parse(substitutedContent).status, "attest_response_leaf_mismatch");
    assert.equal(wireRequests.length, 2);

    const oversizedResponseResult = await client.callTool({
      name: "attest_event",
      arguments: {
        ...packet.attest_event_args,
        api_key: "local-oversize-key",
      },
    });
    assert.equal(oversizedResponseResult.isError, true, "oversized ZAP1 response was accepted");
    const oversizedContent = oversizedResponseResult.content.find((item) => item.type === "text")?.text;
    assert.match(oversizedContent ?? "", /more than 65536 bytes|exceeded 65536 bytes/);
    assert.equal(wireRequests.length, 3);

    const wrongContentTypeResult = await client.callTool({
      name: "attest_event",
      arguments: {
        ...packet.attest_event_args,
        api_key: "local-wrong-type-key",
      },
    });
    assert.equal(wrongContentTypeResult.isError, true, "non-JSON ZAP1 response was accepted");
    const wrongContentType = wrongContentTypeResult.content.find((item) => item.type === "text")?.text;
    assert.match(wrongContentType ?? "", /unexpected response content type/);
    assert.equal(wireRequests.length, 4);

    const receiptResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        receipt: receiptV2,
        expected_agent_id: agentAction.agent_id,
        expected_action_type: agentAction.action_type,
        expected_input_hash: agentAction.input_hash,
        expected_output_hash: agentAction.output_hash,
      },
    });
    assert.notEqual(receiptResult.isError, true);
    const receiptContent = receiptResult.content.find((item) => item.type === "text")?.text;
    assert(receiptContent, "receipt-v2 verifier returned no text content");
    const receiptVerification = JSON.parse(receiptContent);
    assert.equal(receiptVerification.valid, true);
    assert.equal(receiptVerification.cryptographic_inclusion_valid, true);
    assert.equal(receiptVerification.anchor_reference_present, false);
    assert.equal(receiptVerification.anchor_confirmed, false);
    assert.equal(receiptVerification.acceptance_ready, false);
    assert.equal(receiptVerification.status, "included_unanchored");

    const officialResult = await client.callTool({
      name: "zap1_verify_receipt_v2",
      arguments: {
        proof_bundle: structuralProofBundle,
        agent_action_witness: {
          event_type: "AGENT_ACTION",
          ...agentAction,
        },
        expected_agent_id: agentAction.agent_id,
        expected_action_type: agentAction.action_type,
        expected_input_hash: agentAction.input_hash,
        expected_output_hash: agentAction.output_hash,
      },
    });
    assert.notEqual(officialResult.isError, true);
    const officialContent = officialResult.content.find((item) => item.type === "text")?.text;
    assert(officialContent, "official proof-bundle verifier returned no text content");
    const officialVerification = JSON.parse(officialContent);
    assert.equal(officialVerification.valid, true);
    assert.equal(officialVerification.source_format, "official_proof_bundle_v2_with_witness");
    assert.equal(officialVerification.typed_witness_authenticated, true);
    assert.equal(officialVerification.anchor_reference_present, false);
    assert.equal(Object.hasOwn(officialVerification.normalized_receipt, "anchor"), false);
    return {
      pass: true,
      contract_source: provenance.zcash_mcp.critical_contract_source,
      event_type: packet.attest_event_args.event_type,
      hashes_match: true,
      receipt_v2_inclusion_valid: true,
      official_proof_bundle_mode_valid: true,
      local_event_contract_verified: true,
      response_leaf_substitution_rejected: true,
      oversized_response_rejected: true,
      non_json_response_rejected: true,
      anchor_omitted: true,
      deployed_proof_shape_sha256: proofShape.source_body_sha256,
      state: "LOCAL_EVENT_CONTRACT_VERIFIED_NO_LIVE_WRITE_NOT_ANCHORED",
    };
  } finally {
    await transport.close().catch(() => {});
    await new Promise((resolve) => mockApi.close(resolve));
  }
}
