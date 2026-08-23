import assert from "node:assert/strict";

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const RAW_IDENTITY_KEYS = new Set(["action_instance_id", "receiver_id", "nonce", "commitment_salt_hex"]);

function object(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), label + " must be an object");
  return value;
}

function exactKeys(value, keys, label) {
  const actual = Object.keys(object(value, label)).sort();
  assert.deepEqual(actual, [...keys].sort(), label + " fields changed");
}

function hash(value, label) {
  assert.equal(typeof value, "string", label + " must be a string");
  assert.match(value, HEX_64, label + " must be 64-char hex");
  return value.toLowerCase();
}

function assertNoRawIdentityKeys(value, path = "binding") {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert(!RAW_IDENTITY_KEYS.has(key), path + "." + key + " discloses a raw action-instance field");
    assertNoRawIdentityKeys(child, path + "." + key);
  }
}

function validateBinding(binding) {
  object(binding, "binding");
  assert.equal(binding.schema, "zap1-insight-adapter-binding-v2");
  const hashes = object(binding.zap1_hashes, "binding.zap1_hashes");
  const external = object(binding.zap1_external_action_args, "binding.zap1_external_action_args");
  const witness = object(binding.zap1_agent_action_args, "binding.zap1_agent_action_args");
  const subjectHash = hash(hashes.subject_hash, "subject_hash");
  const claimHash = hash(hashes.claim_hash, "claim_hash");
  const evidenceHash = hash(hashes.evidence_hash, "evidence_hash");

  assert.equal(external.status, "verification_completed");
  assert.equal(external.action_type, "price_integrity_receipt_verified");
  assert.equal(hash(external.agent_id, "external agent_id"), subjectHash);
  assert.equal(hash(external.subject_hash, "external subject_hash"), subjectHash);
  assert.equal(hash(external.claim_hash, "external claim_hash"), claimHash);
  assert.equal(hash(external.evidence_hash, "external evidence_hash"), evidenceHash);
  assert.notEqual(hash(external.request_hash, "request_hash"), hash(external.intent_hash, "intent_hash"), "request_hash and intent_hash must be distinct commitments");
  hash(external.action_instance_commitment, "action_instance_commitment");
  assert.equal(Object.hasOwn(external, "quote_hash"), false, "quote_hash must be omitted when there is no economic quote");

  assert.equal(hash(witness.agent_id, "witness agent_id"), subjectHash);
  assert.equal(witness.action_type, external.action_type);
  assert.equal(hash(witness.input_hash, "witness input_hash"), claimHash);
  assert.equal(hash(witness.output_hash, "witness output_hash"), evidenceHash);
  assertNoRawIdentityKeys(binding);

  return { hashes: { subjectHash, claimHash, evidenceHash }, external, witness };
}

export function assembleZap1ReceiptV2({ binding, proofBundle }) {
  const validated = validateBinding(binding);
  exactKeys(
    proofBundle,
    ["protocol", "version", "leaf", "proof", "root", "anchor", "verify_command"],
    "proof bundle",
  );
  assert.equal(proofBundle.protocol, "ZAP1");
  assert.equal(proofBundle.version, "2");

  exactKeys(
    proofBundle.leaf,
    ["hash", "event_type", "created_at", "event_type_authentication", "preimage_disclosure"],
    "proof bundle leaf",
  );
  const leafHash = hash(proofBundle.leaf.hash, "proof bundle leaf.hash");
  assert.equal(proofBundle.leaf.event_type, "AGENT_ACTION");
  assert.equal(
    proofBundle.leaf.event_type_authentication,
    "unverified_server_metadata_without_disclosed_witness",
  );
  assert.equal(proofBundle.leaf.preimage_disclosure, "withheld from the public proof bundle");
  assert.equal(typeof proofBundle.leaf.created_at, "string");

  assert(Array.isArray(proofBundle.proof), "proof bundle proof must be an array");
  assert(proofBundle.proof.length <= 64, "proof bundle proof exceeds 64 siblings");
  const proof = proofBundle.proof.map((entry, index) => {
    const label = "proof[" + index + "]";
    exactKeys(entry, ["hash", "position"], label);
    assert(["left", "right"].includes(entry.position), label + ".position is invalid");
    return { hash: hash(entry.hash, label + ".hash"), position: entry.position };
  });

  exactKeys(
    proofBundle.root,
    ["hash", "leaf_count", "scheme", "created_at", "legacy_allowed", "legacy_max_anchor_height"],
    "proof bundle root",
  );
  const rootHash = hash(proofBundle.root.hash, "proof bundle root.hash");
  assert(Number.isSafeInteger(proofBundle.root.leaf_count) && proofBundle.root.leaf_count > 0, "root.leaf_count must be a positive safe integer");
  assert.equal(proofBundle.root.scheme, "ZAP1_COUNT_BOUND_V2");
  assert.equal(typeof proofBundle.root.created_at, "string");
  assert.equal(proofBundle.root.legacy_allowed, false);
  assert(Number.isSafeInteger(proofBundle.root.legacy_max_anchor_height) && proofBundle.root.legacy_max_anchor_height >= 0);
  assert.equal(typeof proofBundle.verify_command, "string");
  assert(proofBundle.verify_command.length > 0, "verify_command must be non-empty");

  exactKeys(proofBundle.anchor, ["txid", "height"], "proof bundle anchor");
  const anchorIsNull = proofBundle.anchor.txid === null && proofBundle.anchor.height === null;
  const anchorIsComplete =
    typeof proofBundle.anchor.txid === "string" &&
    HEX_64.test(proofBundle.anchor.txid) &&
    Number.isSafeInteger(proofBundle.anchor.height) &&
    proofBundle.anchor.height > 0;
  assert(anchorIsNull || anchorIsComplete, "anchor must be either fully null or a complete txid/height pair");

  const receipt = {
    schema_version: "zap1-receipt-v2",
    event_type: "AGENT_ACTION",
    profile: "public_hash_only",
    subject_hash: validated.hashes.subjectHash,
    claim_hash: validated.hashes.claimHash,
    evidence_hash: validated.hashes.evidenceHash,
    leaf: {
      hash: leafHash,
      event_type: "AGENT_ACTION",
      agent_id: validated.witness.agent_id.toLowerCase(),
      action_type: validated.witness.action_type,
      input_hash: validated.witness.input_hash.toLowerCase(),
      output_hash: validated.witness.output_hash.toLowerCase(),
    },
    proof,
    root: {
      hash: rootHash,
      leaf_count: proofBundle.root.leaf_count,
      scheme: "ZAP1_COUNT_BOUND_V2",
    },
    status: validated.external.status,
    disclosed_fields: [...validated.external.disclosed_fields],
    redaction_policy: validated.external.redaction_policy,
  };
  if (anchorIsComplete) {
    receipt.anchor = {
      txid: proofBundle.anchor.txid.toLowerCase(),
      height: proofBundle.anchor.height,
    };
  }
  return receipt;
}
