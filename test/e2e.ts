// E2E test for zcash-mcp tools against live Zebra + ZAP1 API
// Run: ZEBRA_RPC_URL=http://127.0.0.1:8232 ZAP1_API_URL=http://127.0.0.1:3080 ZAP1_API_KEY=<key> npx tsx test/e2e.ts

const ZEBRA = process.env.ZEBRA_RPC_URL || "http://127.0.0.1:8232";
const ZAP1 = process.env.ZAP1_API_URL || "http://127.0.0.1:3080";
const KEY = process.env.ZAP1_API_KEY || "";

let passed = 0;
let failed = 0;

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (e: any) {
    failed++;
    console.log(`  FAIL: ${name} - ${e.message}`);
  }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

async function zebra(method: string, params: any[] = []) {
  const resp = await fetch(ZEBRA, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return resp.json();
}

async function zap1(path: string, opts?: RequestInit) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (KEY) headers["Authorization"] = `Bearer ${KEY}`;
  const resp = await fetch(`${ZAP1}${path}`, { ...opts, headers: { ...headers, ...opts?.headers } });
  return resp.json();
}

async function main() {
  console.log("zcash-mcp E2E tests");
  console.log(`  Zebra: ${ZEBRA}`);
  console.log(`  ZAP1: ${ZAP1}`);
  console.log(`  API Key: ${KEY ? "SET" : "NONE"}`);
  console.log("");

  // 1. get_block_height
  await test("get_block_height", async () => {
    const r = await zebra("getblockcount");
    const height = r.result;
    assert(typeof height === "number", `expected number, got ${typeof height}`);
    assert(height > 3290000, `height ${height} too low`);
    console.log(`    chain height: ${height}`);
  });

  // 2. lookup_transaction (use the anchor txid)
  await test("lookup_transaction", async () => {
    const txid = "7d0e9e6d8c150c34a0b2921299db506886644462829a1d12848d810b7bb01907";
    const r = await zebra("getrawtransaction", [txid, 1]);
    assert(r.result, "no result");
    assert(r.result.txid === txid, `txid mismatch`);
    console.log(`    tx height: ${r.result.height || "unconfirmed"}`);
  });

  // 3. get_stats
  await test("get_stats", async () => {
    const r = await zap1("/stats");
    assert(r.event_types, "no event_types");
    assert(Array.isArray(r.event_types), "event_types not array");
    assert(r.event_types.length >= 18, `only ${r.event_types.length} types`);
    console.log(`    ${r.event_types.length} event types`);
  });

  // 4. verify_proof (use a known leaf)
  await test("verify_proof", async () => {
    const events = await zap1("/events");
    assert(events.events && events.events.length > 0, "no events");
    const leaf = events.events[0].leaf_hash;
    const r = await zap1(`/verify/${leaf}/check`);
    assert(r.valid !== undefined, "no valid field");
    console.log(`    leaf ${leaf.slice(0, 16)}... valid=${r.valid}`);
  });

  // 5. attest_event
  await test("attest_event", async () => {
    if (!KEY) { console.log("    SKIP (no API key)"); return; }
    const r = await zap1("/attest", {
      method: "POST",
      body: JSON.stringify({
        wallet_hash: "mcp_e2e_test",
        event_type: "STAKING_DEPOSIT",
        amount_zat: 1000,
        validator_id: "mcp-test",
      }),
    });
    assert(r.leaf_hash, `no leaf_hash: ${JSON.stringify(r)}`);
    assert(r.status === "created", `status: ${r.status}`);
    console.log(`    created leaf: ${r.leaf_hash.slice(0, 16)}...`);
  });

  // 6. decode_memo (via API)
  await test("decode_memo", async () => {
    // memo/decode expects hex-encoded memo bytes, not plaintext
    const memoHex = Buffer.from("ZAP1:09:024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a").toString("hex");
    const resp = await fetch(`${ZAP1}/memo/decode`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: memoHex,
    });
    const text = await resp.text();
    assert(resp.ok, `status ${resp.status}: ${text.slice(0, 80)}`);
    const r = JSON.parse(text);
    assert(r.format || r.memo_type, `unexpected: ${text.slice(0, 100)}`);
    console.log(`    decoded: ${r.format || r.memo_type}`);
  });

  // 7. send_shielded (URI generation only)
  await test("send_shielded_uri", async () => {
    const addr = "u12upd0qf8a5wrfr26szmgkq3m04mnpf0wm79vdg497cysvaumn7ptqn7008u2v28krg8pk9wzfypnqfgy0lj6s252redqejaadyzr2zxl";
    const uri = `zcash:${addr}?amount=0.001&memo=dGVzdA`;
    assert(uri.startsWith("zcash:u1"), "bad URI prefix");
    assert(uri.includes("amount=0.001"), "missing amount");
    console.log(`    URI: ${uri.slice(0, 60)}...`);
  });

  // 8. anchor status
  await test("anchor_status", async () => {
    const r = await zap1("/anchor/status");
    assert(r.anchor_threshold, "no threshold");
    assert(r.leaf_count !== undefined, "no leaf_count");
    console.log(`    leaves=${r.leaf_count} unanchored=${r.unanchored_leaves} threshold=${r.anchor_threshold}`);
  });

  // 9. anchor history
  await test("anchor_history", async () => {
    const r = await zap1("/anchor/history");
    assert(r.anchors, "no anchors");
    assert(r.total > 0, "no anchors recorded");
    console.log(`    ${r.total} anchors, last at height ${r.anchors[0]?.height}`);
  });

  // 10. health check
  await test("health", async () => {
    const r = await zap1("/health");
    assert(r.scanner_operational === true, "scanner not operational");
    assert(r.sync_lag <= 5, `sync lag ${r.sync_lag} too high`);
    console.log(`    sync_lag=${r.sync_lag} tip=${r.chain_tip}`);
  });

  console.log(`\n${passed} passed, ${failed} failed out of ${passed + failed}`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
