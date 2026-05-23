import assert from "node:assert/strict";

export const EXPECTED_TOOL_NAMES = [
  "attest_event",
  "decode_memo",
  "get_agent_status",
  "get_anchor_history",
  "get_anchor_status",
  "get_balance",
  "get_block_height",
  "get_events",
  "get_stats",
  "lookup_transaction",
  "send_shielded",
  "verify_proof",
  "zcash_create_invoice",
  "zcash_identity_register",
  "zcash_prove_payment",
  "zcash_reputation_score",
  "zcash_watch_payment",
  "zcash_crosschain_swap",
  "zcash_capability_manifest",
  "zcash_conformance_check",
  "zcash_receipt_template",
  "zcash_create_wallet",
  "zcash_sign_mpc",
  "zcash_shield",
  "zcash_verify_evm",
].sort();

export const SAMPLE_ADDRESS =
  "u12upd0qf8a5wrfr26szmgkq3m04mnpf0wm79vdg497cysvaumn7ptqn7008u2v28krg8pk9wzfypnqfgy0lj6s252redqejaadyzr2zxl";

export function assertToolRegistration(tools) {
  const actual = tools.map((tool) => tool.name).sort();
  assert.deepEqual(actual, EXPECTED_TOOL_NAMES, "registered MCP tools drifted");
}

export function parseJsonTextResult(result) {
  const text = result.content
    ?.filter((item) => item.type === "text")
    .map((item) => item.text)
    .join("\n");

  assert(text, "tool result did not include text content");
  return JSON.parse(text);
}

export function assertSendShieldedResult(result) {
  assert.equal(result.address, SAMPLE_ADDRESS, "send_shielded echoed wrong address");
  assert.match(result.uri, /^zcash:/, "send_shielded returned a non-zcash URI");
  assert.match(result.uri, /amount=0\.01/, "send_shielded dropped amount");
  assert.match(result.uri, /memo=/, "send_shielded dropped memo");
  assert.match(result.uri, /label=zcash%20mcp/, "send_shielded dropped encoded label");
}

export function assertDecodeMemoResult(result) {
  assert.equal(result.format, "text", "decode_memo should detect plain UTF-8 text");
  assert.equal(result.text, "hello world", "decode_memo returned unexpected payload");
}
