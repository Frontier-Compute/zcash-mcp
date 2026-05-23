// Live E2E test for zcash-mcp over real MCP stdio.
// Run: ZEBRA_RPC_URL=http://127.0.0.1:8232 ZAP1_API_URL=http://127.0.0.1:3080 ZAP1_API_KEY=<key> node test/e2e.mjs

import assert from "node:assert/strict";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { parseJsonTextResult } from "../scripts/test-helpers.mjs";

const ZEBRA_RPC_URL = process.env.ZEBRA_RPC_URL || "http://127.0.0.1:8232";
const ZAP1_API_URL = process.env.ZAP1_API_URL || "http://127.0.0.1:3080";
const ZAP1_API_KEY = process.env.ZAP1_API_KEY || "";
const ZAP1_AGENT_ID = process.env.ZAP1_AGENT_ID || "00zeven";
const ANCHOR_TXID = "7d0e9e6d8c150c34a0b2921299db506886644462829a1d12848d810b7bb01907";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");
const serverEntry = path.join(repoRoot, "dist", "index.js");

let passed = 0;
let failed = 0;

function logResult(status, name, message = "") {
  const suffix = message ? ` ${message}` : "";
  console.log(`  ${status}: ${name}${suffix}`);
}

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    logResult("PASS", name);
  } catch (error) {
    failed += 1;
    const message = error instanceof Error ? error.message : String(error);
    logResult("FAIL", name, `- ${message}`);
  }
}

async function main() {
  console.log("zcash-mcp live E2E");
  console.log(`  Zebra: ${ZEBRA_RPC_URL}`);
  console.log(`  ZAP1: ${ZAP1_API_URL}`);
  console.log(`  API Key: ${ZAP1_API_KEY ? "SET" : "NONE"}`);
  console.log(`  Agent ID: ${ZAP1_AGENT_ID}`);
  console.log("");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    cwd: repoRoot,
    env: {
      ...process.env,
      ZEBRA_RPC_URL,
      ZAP1_API_URL,
      ...(ZAP1_API_KEY ? { ZAP1_API_KEY } : {}),
    },
    stderr: "pipe",
  });

  let stderr = "";
  if (transport.stderr && typeof transport.stderr.on === "function") {
    if (typeof transport.stderr.setEncoding === "function") {
      transport.stderr.setEncoding("utf8");
    }
    transport.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
  }

  const client = new Client({
    name: "zcash-mcp-live-e2e",
    version: "0.2.0",
  });

  const callJson = async (name, args = {}) => {
    const result = await client.callTool({ name, arguments: args });
    assert(!result.isError, `${name} returned MCP error`);
    return parseJsonTextResult(result);
  };

  try {
    await client.connect(transport);

    const eventsResult = await callJson("get_events", { limit: 5 });
    assert(Array.isArray(eventsResult.events), "get_events did not return an events array");
    assert(eventsResult.events.length > 0, "get_events returned no events");
    const latestEvent = eventsResult.events[0];
    const eventWalletHash = latestEvent.wallet_hash;
    const eventLeafHash = latestEvent.leaf_hash;
    assert(typeof eventWalletHash === "string" && eventWalletHash.length > 0, "event wallet_hash missing");
    assert(typeof eventLeafHash === "string" && eventLeafHash.length === 64, "event leaf_hash missing");

    await test("get_block_height", async () => {
      const result = await callJson("get_block_height");
      assert(typeof result.height === "number", "height missing");
      assert(result.height > 3290000, `height ${result.height} too low`);
      console.log(`    chain height: ${result.height}`);
    });

    await test("lookup_transaction", async () => {
      const result = await callJson("lookup_transaction", { txid: ANCHOR_TXID, verbose: true });
      assert.equal(result.txid, ANCHOR_TXID, "txid mismatch");
      console.log(`    tx height: ${result.height || "unconfirmed"}`);
    });

    await test("get_stats", async () => {
      const result = await callJson("get_stats");
      assert(Array.isArray(result.event_types), "event_types not array");
      assert(result.event_types.length >= 18, `only ${result.event_types.length} event types`);
      console.log(`    ${result.event_types.length} event types`);
    });

    await test("get_events", async () => {
      assert(eventsResult.events.length > 0, "no events returned");
      console.log(`    ${eventsResult.events.length} events, latest ${eventLeafHash.slice(0, 16)}...`);
    });

    await test("verify_proof", async () => {
      const result = await callJson("verify_proof", { leaf_hash: eventLeafHash });
      assert(result.valid !== undefined, "missing valid field");
      console.log(`    leaf ${eventLeafHash.slice(0, 16)}... valid=${result.valid}`);
    });

    await test("attest_event", async () => {
      if (!ZAP1_API_KEY) {
        console.log("    SKIP (no API key)");
        return;
      }

      const walletHash = `mcp_e2e_${Date.now()}`;
      const result = await callJson("attest_event", {
        wallet_hash: walletHash,
        event_type: "STAKING_DEPOSIT",
        serial_number: "mcp-live",
        action_type: "integration-test",
      });
      assert(typeof result.leaf_hash === "string" && result.leaf_hash.length === 64, "leaf_hash missing");
      assert(result.status === "created", `unexpected status ${result.status}`);
      console.log(`    created leaf: ${result.leaf_hash.slice(0, 16)}... for ${walletHash}`);
    });

    await test("decode_memo", async () => {
      const result = await callJson("decode_memo", {
        memo: Buffer.from("hello world", "utf8").toString("hex"),
      });
      assert.equal(result.format, "text", "expected plain text memo");
      assert.equal(result.text, "hello world", "unexpected decoded memo");
      console.log(`    decoded: ${result.format}`);
    });

    await test("get_anchor_status", async () => {
      const result = await callJson("get_anchor_status");
      assert(result.anchor_threshold !== undefined, "missing anchor_threshold");
      assert(result.leaf_count !== undefined, "missing leaf_count");
      console.log(
        `    leaves=${result.leaf_count} unanchored=${result.unanchored_leaves} threshold=${result.anchor_threshold}`
      );
    });

    await test("get_anchor_history", async () => {
      const result = await callJson("get_anchor_history");
      assert(Array.isArray(result.anchors), "missing anchors");
      assert(result.total > 0, "no anchors recorded");
      console.log(`    ${result.total} anchors, last at height ${result.anchors[0]?.height}`);
    });

    await test("get_agent_status", async () => {
      const result = await callJson("get_agent_status", { agent_id: ZAP1_AGENT_ID });
      const serialized = JSON.stringify(result);
      assert(serialized.includes(ZAP1_AGENT_ID), "agent payload did not reference requested agent");
      console.log(`    agent ${ZAP1_AGENT_ID}`);
    });
  } catch (error) {
    failed += 1;
    const message = error instanceof Error ? error.message : String(error);
    const suffix = stderr.trim() ? `\nserver stderr:\n${stderr.trim()}` : "";
    logResult("FAIL", "connect", `- ${message}${suffix}`);
  } finally {
    await transport.close().catch(() => {});
  }

  console.log(`\n${passed} passed, ${failed} failed out of ${passed + failed}`);
  process.exit(failed > 0 ? 1 : 0);
}

await main();
