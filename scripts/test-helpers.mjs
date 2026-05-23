import assert from "node:assert/strict";

export const EXPECTED_TOOL_NAMES = [
  "attest_event",
  "decode_memo",
  "get_agent_status",
  "get_anchor_history",
  "get_anchor_status",
  "get_block_height",
  "get_events",
  "get_stats",
  "lookup_transaction",
  "verify_proof",
  "zap1_create_receipt_invoice",
  "zcash_identity_register",
  "zap1_prove_receipt",
  "zcash_reputation_score",
  "zap1_watch_receipt_invoice",
  "zcash_capability_manifest",
  "zcash_conformance_check",
  "zcash_receipt_template",
  "zap1_verify_evm",
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

export function assertDecodeMemoResult(result) {
  assert.equal(result.format, "text", "decode_memo should detect plain UTF-8 text");
  assert.equal(result.text, "hello world", "decode_memo returned unexpected payload");
}
