import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { verifyCapturedSampleDiagnostic } from "./sample-diagnostic.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const v1 = path.resolve(here, "../insight-zap1-receiver-v1");
const fixtureRoot = path.join(here, "fixtures");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const [
  registryRaw,
  sampleRaw,
  actionInstanceRaw,
  unitContractRaw,
  fixtureManifestRaw,
] = await Promise.all([
  readFile(path.join(fixtureRoot, "registry-v3-20260903.body.json")),
  readFile(path.join(fixtureRoot, "sample-v3-20260903.body.json")),
  readFile(path.join(v1, "ACTION-INSTANCE.json")),
  readFile(path.join(v1, "UNIT-CONTRACT.json")),
  readFile(path.join(fixtureRoot, "FIXTURE-MANIFEST.json")),
]);

const fixtureManifest = JSON.parse(fixtureManifestRaw);
assert.equal(registryRaw.byteLength, fixtureManifest.public_v3_snapshot.registry_body_bytes);
assert.equal(sha256(registryRaw), fixtureManifest.public_v3_snapshot.registry_body_sha256);
assert.equal(sampleRaw.byteLength, fixtureManifest.public_v3_snapshot.sample_body_bytes);
assert.equal(sha256(sampleRaw), fixtureManifest.public_v3_snapshot.sample_body_sha256);

const actionInstance = JSON.parse(actionInstanceRaw);
const unitContract = JSON.parse(unitContractRaw);
const sample = JSON.parse(sampleRaw);
const checkedAt = Number(sample.data.attestation.data.checkedAt);
const verified = verifyCapturedSampleDiagnostic({
  registryRaw,
  sampleRaw,
  actionInstance,
  unitContract,
  atSeconds: checkedAt + 1,
});

assert.equal(verified.decision, "UNKNOWN_BLOCKED");
assert.equal(verified.code, "SYNTHETIC_SAMPLE_ONLY", JSON.stringify(verified.verification?.failures));
assert.equal(verified.diagnostic_valid, true);
assert.equal(verified.signature_state, "VERIFIED");
assert.equal(verified.cryptographic_signature_state, "CRYPTOGRAPHIC_SIGNATURE_VALID");
assert.equal(verified.verification.native.uid, sample.data.attestation.uid);
assert.equal(verified.verification.native.recoveredSigner, sample.data.attestation.attester);
assert.equal(verified.verification.native.schemaVersion, 3);
assert.equal(verified.verification.native.domainVersion, "3");
assert.equal(verified.observation_state, "NOT_ACCEPTED");
assert.equal(verified.replay_state, "NOT_COMMITTED");
assert.equal(verified.current_action_eligible, false);
assert.equal(verified.action_authorized, false);
assert.equal(verified.binding, null);
assert.equal(verified.zap1_external_action_args, null);
assert.equal(verified.zap1_agent_action_args, null);

const tamperedSample = structuredClone(sample);
tamperedSample.data.attestation.signature =
  tamperedSample.data.attestation.signature.slice(0, -1) +
  (tamperedSample.data.attestation.signature.endsWith("0") ? "1" : "0");
const tampered = verifyCapturedSampleDiagnostic({
  registryRaw,
  sampleRaw: Buffer.from(JSON.stringify(tamperedSample)),
  actionInstance,
  unitContract,
  atSeconds: checkedAt + 1,
});
assert.equal(tampered.decision, "UNKNOWN_BLOCKED");
assert.equal(tampered.code, "SAMPLE_DIAGNOSTIC_VERIFICATION_FAILED");
assert.equal(tampered.diagnostic_valid, false);
assert.equal(tampered.observation_state, "NOT_ACCEPTED");
assert.equal(tampered.replay_state, "NOT_COMMITTED");

const rolelessRegistry = JSON.parse(registryRaw);
rolelessRegistry.public_keys.find(
  (entry) => entry.public_key === sample.data.attestation.attester,
).role = "attester";
const roleless = verifyCapturedSampleDiagnostic({
  registryRaw: Buffer.from(JSON.stringify(rolelessRegistry)),
  sampleRaw,
  actionInstance,
  unitContract,
  atSeconds: checkedAt + 1,
});
assert.equal(roleless.decision, "UNKNOWN_BLOCKED");
assert.equal(roleless.code, "SAMPLE_SIGNER_ROLE_UNRESOLVED");
assert.equal(roleless.diagnostic_valid, false);
assert.equal(roleless.action_authorized, false);

console.log(JSON.stringify({
  suite: "insight-v3-sample-diagnostic",
  pass: true,
  fixture_registry_sha256: sha256(registryRaw),
  fixture_sample_sha256: sha256(sampleRaw),
  schema_version: verified.verification.native.schemaVersion,
  domain_version: verified.verification.native.domainVersion,
  signature_state: verified.signature_state,
  decision: verified.decision,
  code: verified.code,
  observation_state: verified.observation_state,
  replay_state: verified.replay_state,
  action_authorized: verified.action_authorized,
}, null, 2));
