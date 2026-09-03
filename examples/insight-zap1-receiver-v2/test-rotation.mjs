import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";
import { TypedDataEncoder, Wallet } from "ethers";

import {
  ORACLE_SAFETY_DOMAIN_V2,
  ORACLE_SAFETY_DOMAIN_V3,
  ORACLE_SAFETY_TYPES_V2,
  ORACLE_SAFETY_TYPES_V3,
  ROTATION_CANDIDATE_SIGNING_KEYS,
  verifyOracleSafetyCheckAdmittedHistorical,
  verifyOracleSafetyCheckAdmittedHistoricalV2,
  verifyOracleSafetyCheckV2,
  verifyOracleSafetyCheckRotationV2,
} from "../insight-zap1-receiver-v1/adapter.mjs";
import {
  TRUST_BUNDLE_V2,
  TRUST_BUNDLE_V2_SHA256,
  evaluatePinnedKeyLifecycle,
  gateRegistryStatusFreshness,
  verifyCurrentObservation,
  verifyHistoricalObservation,
} from "./rotation-adapter.mjs";
import { runLiveCheck } from "./live-check.mjs";
import { registryFreshnessFromHeaders } from "./http-freshness.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const v1 = path.resolve(here, "../insight-zap1-receiver-v1");
const readJson = async (base, ...parts) => JSON.parse(await readFile(path.join(base, ...parts), "utf8"));
const codes = (result) => new Set((result.verification?.failures ?? result.failures ?? []).map((failure) => failure.code));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function percentile(values, fraction) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * fraction) - 1)];
}

export async function runRotationTests() {
  const [
    unitContract,
    actionInstance,
    sampleB64,
    registryB64,
    fixtureManifest,
    publicV3RegistryRaw,
    publicV3SampleRaw,
  ] = await Promise.all([
    readJson(v1, "UNIT-CONTRACT.json"),
    readJson(v1, "ACTION-INSTANCE.json"),
    readFile(path.join(here, "fixtures", "sample-new-key-20260831.body.b64"), "utf8"),
    readFile(path.join(here, "fixtures", "registry-20260831.body.b64"), "utf8"),
    readJson(here, "fixtures", "FIXTURE-MANIFEST.json"),
    readFile(path.join(here, "fixtures", "registry-v3-20260903.body.json")),
    readFile(path.join(here, "fixtures", "sample-v3-20260903.body.json")),
  ]);
  const sampleRaw = Buffer.from(sampleB64.replace(/\s/g, ""), "base64");
  assert.equal(sampleRaw.length, fixtureManifest.original_successor_sample.body_bytes);
  assert.equal(sha256(sampleRaw), fixtureManifest.original_successor_sample.body_sha256);
  assert.equal(sha256(sampleRaw), "52aed6365667e3a6579c5aae75d1b6f9832592def2d4269fb4586cbf11995f12");
  const sample = JSON.parse(sampleRaw.toString("utf8"));
  const receipt = sample.data.attestation;
  const registryRaw = Buffer.from(registryB64.replace(/\s/g, ""), "base64");
  assert.equal(registryRaw.length, fixtureManifest.registry_snapshot.body_bytes);
  assert.equal(sha256(registryRaw), fixtureManifest.registry_snapshot.body_sha256);
  assert.equal(sha256(registryRaw), "42be76e202a6db2058b5778677bc08145b3acdd8bd94e4909c652ee0643cc6a4");
  const registry = JSON.parse(registryRaw.toString("utf8"));
  const atSeconds = Number(receipt.data.checkedAt) + 1;
  const common = { receipt, receiptRaw: sampleRaw, registry, registryRaw, actionInstance, unitContract };

  const legacyApiNewKeyAttempt = verifyOracleSafetyCheckV2({
    receipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: atSeconds,
  });
  assert.equal(legacyApiNewKeyAttempt.ok, false);
  assert(codes(legacyApiNewKeyAttempt).has("attester_not_pinned"));

  const historical = verifyHistoricalObservation({ ...common, atSeconds });
  assert.equal(historical.decision, "UNKNOWN_BLOCKED", JSON.stringify(historical.verification?.failures));
  assert.equal(historical.code, "ISSUER_KEY_CONTINUITY_UNRESOLVED");
  assert.equal(historical.signature_state, "VERIFIED");
  assert.equal(historical.cryptographic_signature_state, "CRYPTOGRAPHIC_SIGNATURE_VALID");
  assert.equal(historical.issuer_key_continuity_state, "ISSUER_KEY_CONTINUITY_UNKNOWN_BLOCKED");
  assert.equal(historical.observation_state, "NOT_ACCEPTED");
  assert.equal(historical.current_action_eligible, false);
  assert.equal(historical.action_state, "ACTION_AUTHORIZATION_BLOCKED");
  assert.equal(historical.binding, null);
  assert.equal(historical.zap1_external_action_args, null);
  assert.equal(historical.zap1_agent_action_args, null);
  assert.equal(historical.trust.key_id, "insight-oracle-safety-v2-202609");
  assert.equal(historical.trust.signer, "0x6506F789Edd43338A416f59822A63F309f97E8ce");
  assert.equal(historical.trust.issuer_succession_proof, "UNRESOLVED");
  assert.equal(historical.receipt.transport_source, "JSON_WRAPPER_DATA_ATTESTATION");
  assert.equal(historical.receipt.transport_sha256, sha256(sampleRaw));
  assert.match(historical.evidence.hash, /^[0-9a-f]{64}$/);
  assert.match(TRUST_BUNDLE_V2_SHA256, /^[0-9a-f]{64}$/);
  assert.equal(TRUST_BUNDLE_V2.admission.production_action_authorized, false);

  const v3Signer = new Wallet(`0x${"22".repeat(32)}`);
  const v3Receipt = structuredClone(receipt);
  v3Receipt.schemaVersion = 3;
  v3Receipt.attester = v3Signer.address;
  v3Receipt.data.schemaVersion = 3;
  v3Receipt.data.requiredSourceGroupCount = 2;
  v3Receipt.eip712.domain = structuredClone(ORACLE_SAFETY_DOMAIN_V3);
  v3Receipt.eip712.types = structuredClone(ORACLE_SAFETY_TYPES_V3);
  v3Receipt.uid = TypedDataEncoder.hash(ORACLE_SAFETY_DOMAIN_V3, ORACLE_SAFETY_TYPES_V3, v3Receipt.data);
  v3Receipt.signature = await v3Signer.signTypedData(ORACLE_SAFETY_DOMAIN_V3, ORACLE_SAFETY_TYPES_V3, v3Receipt.data);
  const v3Registry = structuredClone(registry);
  v3Registry.schemas.OracleSafetyCheckV2 = {
    ...structuredClone(v3Registry.schemas.OracleSafetyCheck),
    retiredForSigning: true,
  };
  v3Registry.schemas.OracleSafetyCheck = {
    schemaVersion: 3,
    eip712: {
      domain: structuredClone(ORACLE_SAFETY_DOMAIN_V3),
      types: structuredClone(ORACLE_SAFETY_TYPES_V3),
      primaryType: "OracleSafetyCheck",
    },
  };
  v3Registry.public_keys.push({
    key_id: "synthetic-v3-test-key",
    public_key: v3Signer.address,
    algorithm: "EIP-712/secp256k1",
    validFrom: "2026-08-26T17:35:36.000Z",
    validUntil: null,
    revoked: false,
  });
  const v3AdmittedKeys = [{
    admissionClass: "CURRENT_ADMITTED_KEY",
    algorithm: "EIP-712/secp256k1",
    keyId: "synthetic-v3-test-key",
    signer: v3Signer.address,
    validFrom: "2026-08-26T17:35:36.000Z",
    validUntil: null,
  }];
  const v3Verification = verifyOracleSafetyCheckAdmittedHistorical({
    receipt: v3Receipt,
    registry: v3Registry,
    actionInstance,
    unitContract,
    admittedKeys: v3AdmittedKeys,
    atSeconds,
  });
  assert.equal(v3Verification.ok, true, JSON.stringify(v3Verification.failures));
  assert.equal(v3Verification.decision, "ACCEPTED_HISTORICAL_ONLY");
  assert.equal(v3Verification.native.schemaVersion, 3);
  assert.equal(v3Verification.native.domainVersion, "3");
  assert.equal(v3Verification.native.primaryType, "OracleSafetyCheck");
  const v3ThroughV2Api = verifyOracleSafetyCheckAdmittedHistoricalV2({
    receipt: v3Receipt,
    registry: v3Registry,
    actionInstance,
    unitContract,
    admittedKeys: v3AdmittedKeys,
    atSeconds,
  });
  assert.equal(v3ThroughV2Api.ok, false);
  assert(codes(v3ThroughV2Api).has("schema_version_mismatch"));

  const historicalV2ThroughAlias = verifyOracleSafetyCheckAdmittedHistorical({
    receipt,
    registry: v3Registry,
    actionInstance,
    unitContract,
    admittedKeys: [{
      admissionClass: "CURRENT_ADMITTED_KEY",
      algorithm: ROTATION_CANDIDATE_SIGNING_KEYS[1].algorithm,
      keyId: ROTATION_CANDIDATE_SIGNING_KEYS[1].keyId,
      signer: ROTATION_CANDIDATE_SIGNING_KEYS[1].signer,
      validFrom: ROTATION_CANDIDATE_SIGNING_KEYS[1].validFrom,
      validUntil: ROTATION_CANDIDATE_SIGNING_KEYS[1].validUntil,
    }],
    atSeconds,
  });
  assert.equal(historicalV2ThroughAlias.ok, true, JSON.stringify(historicalV2ThroughAlias.failures));
  assert.equal(historicalV2ThroughAlias.native.schemaVersion, 2);

  const weakV3Threshold = structuredClone(v3Receipt);
  weakV3Threshold.data.requiredSourceGroupCount = 1;
  weakV3Threshold.uid = TypedDataEncoder.hash(ORACLE_SAFETY_DOMAIN_V3, ORACLE_SAFETY_TYPES_V3, weakV3Threshold.data);
  weakV3Threshold.signature = await v3Signer.signTypedData(ORACLE_SAFETY_DOMAIN_V3, ORACLE_SAFETY_TYPES_V3, weakV3Threshold.data);
  const weakV3ThresholdResult = verifyOracleSafetyCheckAdmittedHistorical({
    receipt: weakV3Threshold,
    registry: v3Registry,
    actionInstance,
    unitContract,
    admittedKeys: v3AdmittedKeys,
    atSeconds,
  });
  assert.equal(weakV3ThresholdResult.ok, false);
  assert(codes(weakV3ThresholdResult).has("required_source_group_count_mismatch"));

  const attackerReceipt = structuredClone(receipt);
  const attacker = new Wallet(`0x${"11".repeat(32)}`);
  attackerReceipt.signature = await attacker.signTypedData(
    ORACLE_SAFETY_DOMAIN_V2,
    ORACLE_SAFETY_TYPES_V2,
    attackerReceipt.data,
  );
  const attackerSignatureResult = verifyHistoricalObservation({
    ...common,
    receipt: attackerReceipt,
    receiptRaw: Buffer.from(JSON.stringify(attackerReceipt)),
    atSeconds,
  });
  assert.equal(attackerSignatureResult.decision, "REJECTED");
  assert(codes(attackerSignatureResult).has("signature_signer_mismatch"));
  assert.equal(attackerSignatureResult.signature_state, "NOT_VERIFIED");
  assert.equal(attackerSignatureResult.cryptographic_signature_state, "INVALID_OR_NOT_VERIFIED");
  assert.equal(attackerSignatureResult.recovered_signer_matches_selected_key, false);

  const mutatedWrapper = structuredClone(sample);
  mutatedWrapper.meta.requestId = "same-signed-receipt-different-envelope";
  const mutatedWrapperRaw = Buffer.from(JSON.stringify(mutatedWrapper), "utf8");
  const wrapperMutation = verifyHistoricalObservation({ ...common, receiptRaw: mutatedWrapperRaw, atSeconds });
  assert.equal(wrapperMutation.decision, "UNKNOWN_BLOCKED");
  assert.notEqual(wrapperMutation.receipt.transport_sha256, historical.receipt.transport_sha256);
  assert.notEqual(wrapperMutation.evidence.hash, historical.evidence.hash);

  const currentTimeInjection = verifyCurrentObservation({ ...common, nowSeconds: atSeconds });
  assert.equal(currentTimeInjection.decision, "REJECTED");
  assert.equal(currentTimeInjection.code, "CALLER_TIME_OR_FIELD_REJECTED");
  assert.equal(currentTimeInjection.binding, null);

  const newKey = ROTATION_CANDIDATE_SIGNING_KEYS[1];
  const newActivation = Date.parse(newKey.validFrom) / 1000;
  assert.equal(evaluatePinnedKeyLifecycle(newKey, newActivation - 1).code, "KEY_NOT_YET_VALID");
  assert.equal(evaluatePinnedKeyLifecycle(newKey, newActivation).code, "KEY_ACTIVE");
  const oldKey = ROTATION_CANDIDATE_SIGNING_KEYS[0];
  const oldExpiry = Date.parse(oldKey.validUntil) / 1000;
  assert.equal(evaluatePinnedKeyLifecycle(oldKey, oldExpiry - 1).code, "KEY_ACTIVE");
  assert.equal(evaluatePinnedKeyLifecycle(oldKey, oldExpiry).code, "KEY_EXPIRED");

  for (const mutate of [
    (changed) => { changed.public_keys[1].revoked = true; },
    (changed) => { changed.revoked_keys = [newKey.keyId]; },
  ]) {
    const changed = structuredClone(registry);
    mutate(changed);
    const rejected = verifyHistoricalObservation({ ...common, registry: changed, registryRaw: Buffer.from(JSON.stringify(changed)), atSeconds });
    assert.equal(rejected.decision, "REJECTED");
    assert(codes(rejected).has("registry_key_revoked"));
    assert.equal(rejected.binding, null);
  }

  const lifecycleDrift = structuredClone(registry);
  lifecycleDrift.public_keys[1].validFrom = "2026-08-27T17:35:36.000Z";
  const lifecycleDriftResult = verifyHistoricalObservation({
    ...common,
    registry: lifecycleDrift,
    registryRaw: Buffer.from(JSON.stringify(lifecycleDrift)),
    atSeconds,
  });
  assert.equal(lifecycleDriftResult.decision, "REJECTED");
  assert(codes(lifecycleDriftResult).has("registry_key_lifecycle_mismatch"));

  const duplicateId = structuredClone(registry);
  duplicateId.public_keys.push({ ...duplicateId.public_keys[1], public_key: oldKey.signer });
  const duplicateIdResult = verifyHistoricalObservation({
    ...common,
    registry: duplicateId,
    registryRaw: Buffer.from(JSON.stringify(duplicateId)),
    atSeconds,
  });
  assert(codes(duplicateIdResult).has("registry_key_ambiguous"));

  const duplicateSigner = structuredClone(registry);
  duplicateSigner.public_keys.push({ ...duplicateSigner.public_keys[1], key_id: "untrusted-duplicate-signer" });
  const duplicateSignerResult = verifyHistoricalObservation({
    ...common,
    registry: duplicateSigner,
    registryRaw: Buffer.from(JSON.stringify(duplicateSigner)),
    atSeconds,
  });
  assert(codes(duplicateSignerResult).has("registry_signer_ambiguous"));

  const conflictingAddress = structuredClone(registry);
  conflictingAddress.public_keys[1].address = oldKey.signer;
  const conflictingAddressResult = verifyHistoricalObservation({
    ...common,
    registry: conflictingAddress,
    registryRaw: Buffer.from(JSON.stringify(conflictingAddress)),
    atSeconds,
  });
  assert(codes(conflictingAddressResult).has("registry_address_conflict"));

  const malformedRevocationList = structuredClone(registry);
  malformedRevocationList.revoked_keys = [newKey.keyId, newKey.keyId];
  const malformedRevocationResult = verifyHistoricalObservation({
    ...common,
    registry: malformedRevocationList,
    registryRaw: Buffer.from(JSON.stringify(malformedRevocationList)),
    atSeconds,
  });
  assert(codes(malformedRevocationResult).has("registry_revoked_keys_invalid"));

  for (const malformedStatus of ["true", 1, null]) {
    const changed = structuredClone(registry);
    changed.public_keys[1].revoked = malformedStatus;
    const result = verifyHistoricalObservation({
      ...common,
      registry: changed,
      registryRaw: Buffer.from(JSON.stringify(changed)),
      atSeconds,
    });
    assert.equal(result.decision, "UNKNOWN_BLOCKED");
    assert.equal(result.signature_state, "VERIFIED");
    assert(codes(result).has("registry_key_status_invalid"));
  }

  const unrelatedDuplicate = structuredClone(registry);
  unrelatedDuplicate.public_keys.push(
    { key_id: "unrelated-duplicate", public_key: "0x1111111111111111111111111111111111111111", algorithm: "ignored" },
    { key_id: "unrelated-duplicate", public_key: "0x2222222222222222222222222222222222222222", algorithm: "ignored" },
  );
  const unrelatedDuplicateResult = verifyHistoricalObservation({
    ...common,
    registry: unrelatedDuplicate,
    registryRaw: Buffer.from(JSON.stringify(unrelatedDuplicate)),
    atSeconds,
  });
  assert(codes(unrelatedDuplicateResult).has("registry_key_ambiguous"));

  const rawRevokedRegistry = structuredClone(registry);
  rawRevokedRegistry.public_keys[1].revoked = true;
  const callerUnrevokedRegistry = structuredClone(registry);
  let publicKeyReads = 0;
  const statefulRegistry = new Proxy(callerUnrevokedRegistry, {
    get(target, property, receiver) {
      if (property === "public_keys") {
        publicKeyReads += 1;
        return publicKeyReads === 1 ? rawRevokedRegistry.public_keys : target.public_keys;
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const proxyResult = verifyHistoricalObservation({
    ...common,
    registry: statefulRegistry,
    registryRaw: Buffer.from(JSON.stringify(rawRevokedRegistry)),
    atSeconds,
  });
  assert.equal(proxyResult.decision, "REJECTED");
  assert(codes(proxyResult).has("registry_key_revoked"));

  const stricterPolicy = verifyHistoricalObservation({
    ...common,
    policy: { maxReceiptAgeSeconds: 599 },
    atSeconds,
  });
  assert.equal(stricterPolicy.decision, "UNKNOWN_BLOCKED");
  assert.notEqual(stricterPolicy.evidence.effective_policy_sha256, historical.evidence.effective_policy_sha256);
  assert.notEqual(stricterPolicy.evidence.hash, historical.evidence.hash);

  const originalDateNow = Date.now;
  let deterministicCurrent;
  try {
    Date.now = () => atSeconds * 1000;
    deterministicCurrent = verifyCurrentObservation(common);
  } finally {
    Date.now = originalDateNow;
  }
  assert.equal(deterministicCurrent.decision, "UNKNOWN_BLOCKED");
  assert.equal(deterministicCurrent.code, "ISSUER_KEY_CONTINUITY_UNRESOLVED");
  assert.equal(deterministicCurrent.signature_state, "VERIFIED");

  const referenceSource = await readFile(path.join(here, "reference.ts"), "utf8");
  const runtimeSpecifier = JSON.stringify(pathToFileURL(path.join(here, "rotation-adapter.mjs")).href);
  const freshnessSpecifier = JSON.stringify(pathToFileURL(path.join(here, "http-freshness.mjs")).href);
  const sampleDiagnosticSpecifier = JSON.stringify(pathToFileURL(path.join(here, "sample-diagnostic.mjs")).href);
  const runnableReferenceSource = referenceSource
    .replace('"./rotation-adapter.mjs"', runtimeSpecifier)
    .replace('"./http-freshness.mjs"', freshnessSpecifier)
    .replace('"./sample-diagnostic.mjs"', sampleDiagnosticSpecifier);
  const transpiledReference = ts.transpileModule(runnableReferenceSource, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, strict: true },
    fileName: "reference.ts",
    reportDiagnostics: true,
  });
  assert.equal(transpiledReference.diagnostics?.length ?? 0, 0);
  const referenceModule = await import(`data:text/javascript;base64,${Buffer.from(transpiledReference.outputText).toString("base64")}`);
  const originalFetch = globalThis.fetch;
  const originalConsoleLog = console.log;
  const responseFor = (body, freshness = true) => new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "content-length": String(body.byteLength),
      ...(freshness ? { age: "0", "cache-control": "public, max-age=300", date: new Date(Date.now()).toUTCString() } : {}),
    },
  });
  try {
    const publicV3Sample = JSON.parse(publicV3SampleRaw);
    const publicV3AtSeconds = Number(publicV3Sample.data.attestation.data.checkedAt) + 1;
    Date.now = () => publicV3AtSeconds * 1000;
    globalThis.fetch = async (url, options) => {
      assert.equal(options.method, "GET");
      assert.equal(options.redirect, "error");
      assert.equal(options.cache, "no-store");
      assert.equal(options.headers["cache-control"], "no-cache");
      return String(url).includes("oracle-keys.json")
        ? responseFor(publicV3RegistryRaw)
        : responseFor(publicV3SampleRaw);
    };
    const referenceResult = await referenceModule.verifyPublicCurrentObservation({ actionInstance, unitContract });
    assert.equal(referenceResult.decision, "UNKNOWN_BLOCKED");
    assert.equal(referenceResult.code, "SYNTHETIC_SAMPLE_ONLY");
    assert.equal(referenceResult.diagnostic_valid, true);
    assert.equal(referenceResult.signature_state, "VERIFIED");
    assert.equal(referenceResult.transport_status.state, "WITHIN_LOCAL_FRESHNESS_BOUND");
    assert.equal(referenceResult.observation_state, "NOT_ACCEPTED");
    assert.equal(referenceResult.replay_state, "NOT_COMMITTED");
    assert.equal(referenceResult.current_action_eligible, false);
    assert.equal(referenceResult.action_authorized, false);
    assert.equal(referenceResult.trust, null);
    assert.equal(referenceResult.binding, null);
    assert.equal(referenceResult.zap1_external_action_args, null);
    assert.equal(referenceResult.zap1_agent_action_args, null);

    const tamperedPublicV3Sample = structuredClone(publicV3Sample);
    tamperedPublicV3Sample.data.attestation.signature =
      tamperedPublicV3Sample.data.attestation.signature.slice(0, -1) +
      (tamperedPublicV3Sample.data.attestation.signature.endsWith("0") ? "1" : "0");
    const tamperedPublicV3SampleRaw = Buffer.from(JSON.stringify(tamperedPublicV3Sample));
    globalThis.fetch = async (url) => String(url).includes("oracle-keys.json")
      ? responseFor(publicV3RegistryRaw)
      : responseFor(tamperedPublicV3SampleRaw);
    const tamperedReferenceResult = await referenceModule.verifyPublicCurrentObservation({ actionInstance, unitContract });
    assert.equal(tamperedReferenceResult.decision, "UNKNOWN_BLOCKED");
    assert.equal(tamperedReferenceResult.code, "SAMPLE_DIAGNOSTIC_VERIFICATION_FAILED");
    assert.equal(tamperedReferenceResult.diagnostic_valid, false);
    assert.equal(tamperedReferenceResult.signature_state, "NOT_VERIFIED");
    assert.equal(tamperedReferenceResult.observation_state, "NOT_ACCEPTED");
    assert.equal(tamperedReferenceResult.replay_state, "NOT_COMMITTED");
    assert.equal(tamperedReferenceResult.action_authorized, false);
    assert.equal(tamperedReferenceResult.binding, null);

    globalThis.fetch = async (url) => String(url).includes("oracle-keys.json")
      ? responseFor(publicV3RegistryRaw, false)
      : responseFor(publicV3SampleRaw);
    const missingFreshnessResult = await referenceModule.verifyPublicCurrentObservation({ actionInstance, unitContract });
    assert.equal(missingFreshnessResult.decision, "UNKNOWN_BLOCKED");
    assert.equal(missingFreshnessResult.code, "SYNTHETIC_SAMPLE_ONLY");
    assert.equal(missingFreshnessResult.registry_transport_blocker_code, "REGISTRY_STATUS_FRESHNESS_UNKNOWN");

    Date.now = () => atSeconds * 1000;
    globalThis.fetch = async (url) => String(url).includes("oracle-keys.json")
      ? responseFor(registryRaw)
      : responseFor(sampleRaw);
    console.log = () => {};
    const cliResult = await runLiveCheck({ jsonOnly: true });
    console.log = originalConsoleLog;
    assert.equal(cliResult.exitCode, 3);
    assert.equal(cliResult.output.code, "ISSUER_KEY_CONTINUITY_UNRESOLVED");
    assert.equal(cliResult.output.signature.state, "VERIFIED");
    assert.equal(cliResult.output.registry_transport_status.state, "WITHIN_LOCAL_FRESHNESS_BOUND");

    globalThis.fetch = async () => { throw new Error("synthetic dependency outage"); };
    const dependencyResult = await referenceModule.verifyPublicCurrentObservation({ actionInstance, unitContract });
    assert.equal(dependencyResult.decision, "UNKNOWN_BLOCKED");
    assert.equal(dependencyResult.code, "LIVE_DEPENDENCY_UNAVAILABLE");
    assert.equal(dependencyResult.binding, null);
  } finally {
    Date.now = originalDateNow;
    globalThis.fetch = originalFetch;
    console.log = originalConsoleLog;
  }

  const greenCurrent = {
    ...historical,
    decision: "OBSERVATION_ONLY",
    code: "CURRENT_SIGNATURE_VERIFIED",
    observation_state: "OBSERVATION_ONLY",
  };
  const observedAtSeconds = 2_000_000_000;
  const freshTransport = gateRegistryStatusFreshness(greenCurrent, {
    ageSeconds: 59,
    maxAgeSeconds: 60,
    observedAtSeconds,
    responseDateSeconds: observedAtSeconds - 59,
  });
  assert.equal(freshTransport.decision, "OBSERVATION_ONLY");
  assert.equal(freshTransport.transport_status.state, "WITHIN_LOCAL_FRESHNESS_BOUND");
  assert.notEqual(freshTransport.evidence.hash, greenCurrent.evidence.hash);
  for (const [status, expectedCode] of [
    [{ ageSeconds: null, maxAgeSeconds: 60, observedAtSeconds, responseDateSeconds: observedAtSeconds }, "REGISTRY_STATUS_FRESHNESS_UNKNOWN"],
    [{ ageSeconds: 60, maxAgeSeconds: 60, observedAtSeconds, responseDateSeconds: observedAtSeconds - 60 }, "REGISTRY_STATUS_STALE"],
    [{ ageSeconds: 1, maxAgeSeconds: 301, observedAtSeconds, responseDateSeconds: observedAtSeconds - 1 }, "REGISTRY_STATUS_CACHE_POLICY_UNACCEPTABLE"],
    [{ ageSeconds: 1, maxAgeSeconds: 60, observedAtSeconds, responseDateSeconds: observedAtSeconds - 1000 }, "REGISTRY_STATUS_TIME_INCONSISTENT"],
  ]) {
    const blocked = gateRegistryStatusFreshness(greenCurrent, status);
    assert.equal(blocked.decision, "UNKNOWN_BLOCKED");
    assert.equal(blocked.code, expectedCode);
    assert.equal(blocked.observation_state, "NOT_ACCEPTED");
  }
  const priorRejected = { ...greenCurrent, decision: "REJECTED", code: "REGISTRY_KEY_REVOKED", observation_state: "NOT_ACCEPTED" };
  const rejectedAfterStaleGate = gateRegistryStatusFreshness(priorRejected, {
    ageSeconds: 60,
    maxAgeSeconds: 60,
    observedAtSeconds,
    responseDateSeconds: observedAtSeconds - 60,
  });
  assert.equal(rejectedAfterStaleGate.decision, "REJECTED");
  assert.equal(rejectedAfterStaleGate.code, "REGISTRY_KEY_REVOKED");

  for (const headers of [
    new Headers({ age: "1.0", "cache-control": "public, max-age=60", date: new Date((observedAtSeconds - 1) * 1000).toUTCString() }),
    new Headers({ age: "1", "cache-control": "max-age=60, max-age=300", date: new Date((observedAtSeconds - 1) * 1000).toUTCString() }),
    new Headers({ age: "1", "cache-control": "public, max-age=-1", date: new Date((observedAtSeconds - 1) * 1000).toUTCString() }),
    new Headers({ age: "1", "cache-control": "public, max-age=60", date: "2033-05-18T03:32:19Z" }),
    new Headers({ age: "1", "cache-control": "public, max-age=60", date: "Mon, 31 Feb 2033 03:32:19 GMT" }),
  ]) {
    const parsed = registryFreshnessFromHeaders(headers, observedAtSeconds);
    const blocked = gateRegistryStatusFreshness(greenCurrent, parsed);
    assert.equal(blocked.decision, "UNKNOWN_BLOCKED");
    assert.equal(blocked.code, "REGISTRY_STATUS_FRESHNESS_UNKNOWN");
  }

  for (const field of ["tradeAmountUsd", "consensusPrice", "recommendedMaxPositionUsd"]) {
    const malformed = structuredClone(receipt);
    malformed.data[field] = "not-a-uint";
    let malformedResult;
    assert.doesNotThrow(() => {
      malformedResult = verifyOracleSafetyCheckRotationV2({
        receipt: malformed,
        registry,
        actionInstance,
        unitContract,
        nowSeconds: atSeconds,
      });
    });
    assert.equal(malformedResult.ok, false);
    assert.equal(malformedResult.native.display[field], null);
  }

  const rawMismatch = verifyHistoricalObservation({ ...common, registryRaw: Buffer.from(JSON.stringify({ ...registry, issuer: "https://unrelated.invalid" })), atSeconds });
  assert.equal(rawMismatch.code, "INPUT_CAPTURE_INVALID");
  assert.equal(rawMismatch.binding, null);
  const oversized = verifyHistoricalObservation({ ...common, receiptRaw: Buffer.alloc(131073, 0x20), atSeconds });
  assert.equal(oversized.code, "INPUT_CAPTURE_INVALID");
  const registryText = JSON.stringify(registry);
  const duplicateJsonKey = verifyHistoricalObservation({
    ...common,
    registryRaw: Buffer.from(`{"issuer":"https://attacker.invalid",${registryText.slice(1)}`),
    atSeconds,
  });
  assert.equal(duplicateJsonKey.code, "INPUT_CAPTURE_INVALID");
  assert.match(duplicateJsonKey.customer_message, /duplicate JSON object key issuer/);
  const excessiveDepth = verifyHistoricalObservation({
    ...common,
    receiptRaw: Buffer.from("[".repeat(66) + "0" + "]".repeat(66)),
    atSeconds,
  });
  assert.equal(excessiveDepth.code, "INPUT_CAPTURE_INVALID");
  assert.match(excessiveDepth.customer_message, /exceeds depth 64/);

  const sequentialDurations = [];
  for (let index = 0; index < 1000; index += 1) {
    const started = performance.now();
    const result = verifyHistoricalObservation({ ...common, atSeconds });
    sequentialDurations.push(performance.now() - started);
    assert.equal(result.decision, "UNKNOWN_BLOCKED");
    assert.equal(result.signature_state, "VERIFIED");
  }
  const p50 = percentile(sequentialDurations, 0.5);
  const p95 = percentile(sequentialDurations, 0.95);
  const p99 = percentile(sequentialDurations, 0.99);
  assert(p95 <= 50, `historical observation p95 ${p95.toFixed(3)}ms exceeds the 50ms reference-host gate`);

  const batchStarted = performance.now();
  const backToBackBatch = Array.from({ length: 32 }, () => verifyHistoricalObservation({ ...common, atSeconds }));
  const batchMs = performance.now() - batchStarted;
  assert(backToBackBatch.every((result) => result.decision === "UNKNOWN_BLOCKED" && result.signature_state === "VERIFIED"));

  return {
    pass: true,
    new_key_fixture: {
      uid: receipt.uid,
      signer: historical.trust.signer,
      key_id: historical.trust.key_id,
      sample_transport_sha256: historical.receipt.transport_sha256,
      registry_fixture_sha256: sha256(registryRaw),
    },
    states: {
      signature: historical.signature_state,
      cryptographic_signature: historical.cryptographic_signature_state,
      issuer_key_continuity: historical.issuer_key_continuity_state,
      observation: historical.observation_state,
      action: historical.action_state,
      issuer_succession_proof: historical.trust.issuer_succession_proof,
    },
    hostile: {
      v3_27_field_schema_dispatch: "PASS",
      v3_required_source_group_threshold: "PINNED_AT_2",
      retired_v2_alias_historical_verification: "PASS",
      v2_compatibility_api_rejects_v3: "PASS",
      half_open_lifecycle: "PASS",
      legacy_v1_api_new_key: "REJECTED",
      valid_signature_wrong_signer_label: "NOT_VERIFIED",
      revocation_sources: 2,
      duplicate_key_id: "REJECTED",
      duplicate_signer: "REJECTED",
      conflicting_registry_addresses: "REJECTED",
      malformed_revocation_list: "REJECTED",
      malformed_revocation_status_types: 3,
      unrelated_duplicate_key_id: "REJECTED",
      raw_object_toctou: "REJECTED_FROM_RAW_SNAPSHOT",
      registry_lifecycle_drift: "REJECTED",
      policy_hash_collision: "SEPARATED",
      freshness_missing: "UNKNOWN_BLOCKED",
      freshness_half_open_boundary: "UNKNOWN_BLOCKED",
      freshness_excessive_server_max_age: "UNKNOWN_BLOCKED",
      freshness_date_age_inconsistency: "UNKNOWN_BLOCKED",
      freshness_malformed_or_duplicate_headers: 5,
      rejection_precedence: "PRESERVED",
      malformed_uints_total: 3,
      exact_wrapper_bytes_bound: true,
      duplicate_json_keys: "REJECTED_BEFORE_PARSE",
      excessive_json_depth: "REJECTED_BEFORE_PARSE",
      caller_time_current_mode: "REJECTED",
      typescript_reference_execution: "PASS",
      typescript_reference_sample_role: "SYNTHETIC_SAMPLE_ONLY",
      typescript_reference_missing_freshness: "UNKNOWN_BLOCKED",
      typescript_reference_dependency_failure: "UNKNOWN_BLOCKED",
      cli_current_observation_execution: "PASS",
    },
    performance: {
      iterations: sequentialDurations.length,
      p50_ms: Number(p50.toFixed(3)),
      p95_ms: Number(p95.toFixed(3)),
      p99_ms: Number(p99.toFixed(3)),
      gate_p95_ms: 50,
      back_to_back_batch: 32,
      back_to_back_batch_ms: Number(batchMs.toFixed(3)),
    },
    trust_bundle_sha256: TRUST_BUNDLE_V2_SHA256,
    evidence_hash: historical.evidence.hash,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await runRotationTests(), null, 2));
}
