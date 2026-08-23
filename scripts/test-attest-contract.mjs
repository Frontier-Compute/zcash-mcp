import assert from "node:assert/strict";
import { createServer } from "node:http";
import path from "node:path";
import process from "node:process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { computeAgentActionLeafHex } from "../dist/tools/receipt-v2-verifier.js";

const requests = [];
const mockApi = createServer(async (request, response) => {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  requests.push({
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
  const leafHash =
    body.event_type === "AGENT_ACTION"
      ? computeAgentActionLeafHex(body.agent_id, body.action_type, body.input_hash, body.output_hash)
      : "f".repeat(64);
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ leaf_hash: leafHash, accepted: true }));
});

await new Promise((resolve, reject) => {
  mockApi.once("error", reject);
  mockApi.listen(0, "127.0.0.1", resolve);
});

const address = mockApi.address();
assert(address && typeof address === "object", "mock API did not bind a TCP port");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.resolve("dist/index.js")],
  cwd: process.cwd(),
  env: {
    ...process.env,
    ZAP1_API_URL: `http://127.0.0.1:${address.port}`,
  },
  stderr: "pipe",
});
const client = new Client({ name: "zcash-mcp-attest-contract", version: "0.1.0" });

try {
  await client.connect(transport);
  const agentId = "a".repeat(64);
  const bridgeResult = await client.callTool({
    name: "zap1_attest_external_action",
    arguments: {
      rail_id: "oracleinsight.xyz",
      action_type: "price_integrity_receipt_verified",
      status: "verification_completed",
      agent_id: agentId,
      request_hash: "1".repeat(64),
      action_instance_commitment: "2".repeat(64),
      claim_hash: "b".repeat(64),
      evidence_hash: "c".repeat(64),
    },
  });
  assert(!bridgeResult.isError, "AGENT_ACTION bridge did not build");
  const bridge = JSON.parse(bridgeResult.content[0].text);
  assert.match(bridge.hashes.expected_leaf_hash, /^[0-9a-f]{64}$/);

  const result = await client.callTool({
    name: "attest_event",
    arguments: {
      ...bridge.attest_event_args,
      api_key: "local-mock-key",
    },
  });
  assert(!result.isError, "complete AGENT_ACTION did not reach the local mock API");
  const attestResponse = JSON.parse(result.content[0].text);
  assert.equal(
    attestResponse.leaf_hash,
    bridge.hashes.expected_leaf_hash,
    "attest response leaf_hash did not match the locally precomputed typed leaf"
  );
  assert.equal(requests.length, 1, "complete AGENT_ACTION did not produce exactly one request");
  assert.equal(requests[0].method, "POST");
  assert.equal(requests[0].url, "/event");
  assert.equal(requests[0].authorization, "Bearer local-mock-key");
  const { expected_leaf_hash: _localOnlyExpectedLeaf, ...wireArgs } = bridge.attest_event_args;
  assert.deepEqual(requests[0].body, {
    ...wireArgs,
  });

  const substitutedLeafResult = await client.callTool({
    name: "attest_event",
    arguments: {
      ...wireArgs,
      expected_leaf_hash: "0".repeat(64),
      api_key: "local-mock-key",
    },
  });
  assert(substitutedLeafResult.isError, "mismatching attest response leaf was accepted");
  const substitutedLeaf = JSON.parse(substitutedLeafResult.content[0].text);
  assert.equal(substitutedLeaf.status, "attest_response_leaf_mismatch");
  assert.equal(requests.length, 2, "substitution test did not produce exactly one additional request");

  const oversizedResponseResult = await client.callTool({
    name: "attest_event",
    arguments: {
      ...wireArgs,
      expected_leaf_hash: bridge.hashes.expected_leaf_hash,
      api_key: "local-oversize-key",
    },
  });
  assert(oversizedResponseResult.isError, "oversized ZAP1 response was accepted");
  assert.match(oversizedResponseResult.content[0].text, /more than 65536 bytes|exceeded 65536 bytes/);
  assert.equal(requests.length, 3, "oversize test did not produce one request");

  const wrongContentTypeResult = await client.callTool({
    name: "attest_event",
    arguments: {
      ...wireArgs,
      expected_leaf_hash: bridge.hashes.expected_leaf_hash,
      api_key: "local-wrong-type-key",
    },
  });
  assert(wrongContentTypeResult.isError, "non-JSON ZAP1 response was accepted");
  assert.match(wrongContentTypeResult.content[0].text, /unexpected response content type/);
  assert.equal(requests.length, 4, "content-type test did not produce one request");

  const missingAgent = await client.callTool({
    name: "attest_event",
    arguments: {
      event_type: "AGENT_ACTION",
      action_type: "price_integrity_receipt_verified",
      input_hash: "b".repeat(64),
      output_hash: "c".repeat(64),
      api_key: "local-mock-key",
    },
  });
  assert(missingAgent.isError, "AGENT_ACTION without agent_id was not rejected locally");
  assert.equal(requests.length, 4, "invalid AGENT_ACTION reached the API");

  const missingWallet = await client.callTool({
    name: "attest_event",
    arguments: {
      event_type: "DEPLOYMENT",
      api_key: "local-mock-key",
    },
  });
  assert(missingWallet.isError, "non-AGENT_ACTION without wallet_hash was not rejected locally");
  assert.equal(requests.length, 4, "invalid non-AGENT_ACTION reached the API");

  const identityResult = await client.callTool({
    name: "zcash_identity_register",
    arguments: {
      agent_id: "agent_001",
      pubkey_hash: "1".repeat(64),
      model_hash: "2".repeat(64),
      policy_hash: "3".repeat(64),
      api_key: "local-mock-key",
    },
  });
  assert(!identityResult.isError, "complete AGENT_REGISTER did not reach the local mock API");
  assert.equal(requests.length, 5, "AGENT_REGISTER did not produce exactly one additional request");
  assert.equal(requests[4].url, "/event");
  assert.equal(requests[4].authorization, "Bearer local-mock-key");
  assert.deepEqual(requests[4].body, {
    event_type: "AGENT_REGISTER",
    wallet_hash: "agent_001",
    agent_id: "agent_001",
    pubkey_hash: "1".repeat(64),
    model_hash: "2".repeat(64),
    policy_hash: "3".repeat(64),
  });

  console.log(
    "event contract: AGENT_ACTION/AGENT_REGISTER mock POST, bounded responses, and fail-closed guards passed"
  );
} finally {
  await transport.close().catch(() => {});
  await new Promise((resolve) => mockApi.close(resolve));
}
