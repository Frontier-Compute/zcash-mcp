import assert from "node:assert/strict";
import process from "node:process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  SAMPLE_ADDRESS,
  assertDecodeMemoResult,
  assertSendShieldedResult,
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
    assert.equal(tools.tools.length, 25, `${label}: tool count drifted`);

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

    stage = "ping";
    await client.ping();

    stage = "send_shielded";
    const sendResult = await client.callTool({
      name: "send_shielded",
      arguments: {
        address: SAMPLE_ADDRESS,
        amount: 0.01,
        memo: "hello world",
        label: "zcash mcp",
      },
    });
    assert(!sendResult.isError, `${label}: send_shielded returned an error`);
    assertSendShieldedResult(parseJsonTextResult(sendResult));

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
