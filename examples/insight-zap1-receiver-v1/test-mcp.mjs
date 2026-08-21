import assert from "node:assert/strict";
import path from "node:path";
import process from "node:process";
import { access, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { buildZap1ExternalReceiptBinding, verifyOracleSafetyCheckV2 } from "./adapter.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const readJson = async (...parts) => JSON.parse(await readFile(path.join(here, ...parts), "utf8"));

export async function runMcpContractTest(expectedBinding = null) {
  const [provenance, unitContract, actionInstance, fixtureManifest, registry, receipt] = await Promise.all([
    readJson("BASE-PROVENANCE.json"),
    readJson("UNIT-CONTRACT.json"),
    readJson("ACTION-INSTANCE.json"),
    readJson("fixtures", "FIXTURE-MANIFEST.json"),
    readJson("fixtures", "registry-20260821.json"),
    readJson("fixtures", "oracle-safety-valid-20260821.json"),
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
  const validMeta = fixtureManifest.vectors.find((vector) => vector.label === "VALID_LIVE_SNAPSHOT");
  const verification = verifyOracleSafetyCheckV2({
    receipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(verification.ok, true, JSON.stringify(verification.failures));
  const registryRaw = (await readFile(path.join(here, "fixtures", "registry-20260821.json"), "utf8")).trimEnd();
  const binding = expectedBinding ?? buildZap1ExternalReceiptBinding({ receipt, registry, registryRaw, actionInstance, unitContract, verification });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntrypoint],
    cwd: repositoryRoot,
    env: { ...process.env },
    stderr: "pipe",
  });
  const client = new Client({ name: "insight-zap1-receiver-v1", version: "0.1.0" });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "zap1_attest_external_action", arguments: binding.zap1_tool_args });
    assert.notEqual(result.isError, true);
    const content = result.content.find((item) => item.type === "text")?.text;
    assert(content, "MCP tool returned no text content");
    const packet = JSON.parse(content);
    assert.equal(packet.attest_event_args.event_type, "EXTERNAL_ACTION_RECEIPT");
    assert.deepEqual(packet.hashes, binding.zap1_hashes);
    assert.equal(packet.external_action.intent_hash, binding.zap1_tool_args.intent_hash);
    assert.equal(packet.external_action.quote_hash, binding.zap1_tool_args.quote_hash);
    assert.equal(packet.receipt_stub.merkle_path.length, 0);
    assert(packet.next_steps.some((step) => step.includes("attest_event")));
    assert(packet.next_steps.some((step) => step.includes("zap1_prove_receipt")));
    return {
      pass: true,
      contract_source: provenance.zcash_mcp.critical_contract_source,
      event_type: packet.attest_event_args.event_type,
      hashes_match: true,
      state: "RECEIPT_REQUEST_BUILT_NOT_ATTESTED_NOT_ANCHORED",
    };
  } finally {
    await transport.close().catch(() => {});
  }
}
