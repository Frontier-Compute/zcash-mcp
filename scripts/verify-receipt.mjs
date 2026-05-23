import fs from "node:fs";
import process from "node:process";

const HEX_64 = /^[0-9a-fA-F]{64}$/;

function fail(message) {
  console.error(message);
  process.exit(1);
}

function assertHex64(receipt, field) {
  if (typeof receipt[field] !== "string" || !HEX_64.test(receipt[field])) {
    fail(`${field} must be 64-char hex`);
  }
}

const file = process.argv[2];
if (!file) {
  fail("usage: node scripts/verify-receipt.mjs <receipt.json>");
}

const receipt = JSON.parse(fs.readFileSync(file, "utf8"));

if (receipt.schema_version !== "zap1-receipt-v1") {
  fail("schema_version must be zap1-receipt-v1");
}

if (typeof receipt.event_type !== "string" || receipt.event_type.length === 0 || receipt.event_type.length > 64) {
  fail("event_type must be 1-64 chars");
}

for (const field of ["subject_hash", "claim_hash", "evidence_hash", "leaf_hash", "merkle_root"]) {
  assertHex64(receipt, field);
}

if (!Array.isArray(receipt.merkle_path)) {
  fail("merkle_path must be an array");
}

for (const [index, entry] of receipt.merkle_path.entries()) {
  if (typeof entry !== "string" || !HEX_64.test(entry)) {
    fail(`merkle_path[${index}] must be 64-char hex`);
  }
}

if (receipt.anchor_txid !== undefined && !HEX_64.test(receipt.anchor_txid)) {
  fail("anchor_txid must be 64-char hex when present");
}

if (
  receipt.anchor_height !== undefined &&
  (!Number.isInteger(receipt.anchor_height) || receipt.anchor_height < 0)
) {
  fail("anchor_height must be a nonnegative integer when present");
}

console.log(
  JSON.stringify(
    {
      valid: true,
      status: receipt.anchor_txid || receipt.anchor_height !== undefined ? "anchored" : "pending",
      schema_version: "zap1-receipt-v1",
      rule: "Observe state, bound the claim, hash evidence, issue a receipt, verify later.",
    },
    null,
    2
  )
);
