import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  createInMemoryReplayGuard,
  normalizeActionInstance,
  validateUnitContract,
  verifyAndBuildZap1ReceiverBinding as verifyAndBuildReceiverAtomic,
  verifyOracleSafetyCheckV2,
} from "./adapter.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const readJson = async (...parts) => JSON.parse(await readFile(path.join(here, ...parts), "utf8"));
const failureCodes = (result) => new Set(result.failures.map((failure) => failure.code));
const verifyAndBuildZap1ReceiverBinding = (args) => verifyAndBuildReceiverAtomic({
  ...args,
  replayGuard: createInMemoryReplayGuard(),
});

export async function runFrozenTests() {
  const [unitContract, actionInstance, fixtureManifest, registry, validReceipt, tamperedFixture, expiredFixture] = await Promise.all([
    readJson("UNIT-CONTRACT.json"),
    readJson("ACTION-INSTANCE.json"),
    readJson("fixtures", "FIXTURE-MANIFEST.json"),
    readJson("fixtures", "registry-20260821.json"),
    readJson("fixtures", "oracle-safety-valid-20260821.json"),
    readJson("fixtures", "oracle-safety-tampered-demo-20260821.json"),
    readJson("fixtures", "oracle-safety-expired-demo-20260821.json"),
  ]);
  const registryBodyB64 = await readFile(path.join(here, "fixtures", "registry-20260821.body.b64"), "utf8");
  const registryRaw = Buffer.from(registryBodyB64.replace(/\s/g, ""), "base64");
  const unitValidation = validateUnitContract(unitContract);
  assert.equal(unitValidation.ok, true, JSON.stringify(unitValidation.failures));
  const action = normalizeActionInstance(actionInstance, unitContract);
  assert.equal(action.nativeAction.tradeAmountUsd, "10000000000");
  assert.equal(actionInstance.receipt_uid, null);
  assert.equal(actionInstance.execution_authorized, false);

  const validMeta = fixtureManifest.vectors.find((vector) => vector.label === "FRESHLY_SIGNED_REPRESENTATIVE_DEMO_SNAPSHOT");
  assert.equal(validMeta.classification, "ISSUER_KEY_SIGNED_REPRESENTATIVE_DEMO_NOT_LIVE_PROVIDER_OBSERVATIONS");
  assert.equal(validMeta.provider_observations_provenance, "NOT_ESTABLISHED_BY_THIS_FIXTURE");
  const validResult = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(validResult.ok, true, JSON.stringify(validResult.verification.failures));
  const valid = validResult.verification;
  const binding = validResult.binding;
  assert.equal(valid.native.canonicalRequestHash, validReceipt.data.requestHash);
  assert.equal(valid.native.intendedActionHash, action.intendedActionHash);
  assert.equal(valid.native.actionInstanceCommitment, action.actionInstanceCommitment);
  assert.equal(valid.native.display.tradeAmountUsd, "10000.000000");
  assert.equal(valid.native.display.consensusPrice, "3000.12000000");
  assert.equal(valid.native.display.recommendedMaxPositionUsd, "10000.000000");

  for (const hash of Object.values(binding.zap1_hashes)) assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(binding.zap1_external_action_args.status, "verification_completed");
  assert.equal(binding.zap1_external_action_args.request_hash, validReceipt.data.requestHash.slice(2));
  assert.equal(binding.zap1_external_action_args.intent_hash, action.intendedActionHash);
  assert.equal(binding.zap1_external_action_args.action_instance_commitment, action.actionInstanceCommitment);
  assert.equal(Object.hasOwn(binding.zap1_external_action_args, "quote_hash"), false);
  assert.equal(binding.zap1_agent_action_args.agent_id, binding.zap1_hashes.subject_hash);
  assert.equal(binding.zap1_agent_action_args.input_hash, binding.zap1_hashes.claim_hash);
  assert.equal(binding.zap1_agent_action_args.output_hash, binding.zap1_hashes.evidence_hash);
  assert.equal(binding.native_verification.registry_sha256, fixtureManifest.registry.source_body_sha256);
  assert.notEqual(binding.zap1_external_action_args.request_hash, binding.zap1_external_action_args.intent_hash);
  const serializedBinding = JSON.stringify(binding);
  for (const privateValue of [
    actionInstance.action_instance_id,
    actionInstance.receiver_id,
    actionInstance.nonce,
    actionInstance.commitment_salt_hex,
  ]) {
    assert.equal(serializedBinding.includes(privateValue), false, "binding disclosed a raw action-instance value");
  }
  assert.equal(binding.proof_requirements.receipt_request_only, true);

  const registryCrlfBytes = Buffer.from(JSON.stringify(registry, null, 2).replace(/\n/g, "\r\n"), "utf8");
  const crlfRejected = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw: registryCrlfBytes,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(crlfRejected.ok, false);
  assert(failureCodes(crlfRejected.verification).has("registry_body_hash_mismatch"));
  const crlfRegistrySha256 = createHash("sha256").update(registryCrlfBytes).digest("hex");
  const crlfRepinAttempt = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw: registryCrlfBytes,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
    policy: { expectedRegistrySha256: crlfRegistrySha256 },
  });
  assert.equal(crlfRepinAttempt.ok, false);
  assert.equal(crlfRepinAttempt.binding, null);
  assert(failureCodes(crlfRepinAttempt.verification).has("verification_input_invalid"));

  const unrelatedRegistryRaw = Buffer.from(JSON.stringify({ ...registry, issuer: "https://unrelated.invalid" }), "utf8");
  const registryMismatch = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw: unrelatedRegistryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(registryMismatch.ok, false);
  assert.equal(registryMismatch.binding, null);
  assert(failureCodes(registryMismatch.verification).has("registry_raw_object_mismatch"));

  const extraWrapperField = { ...validReceipt, undeclared: true };
  const strictEnvelope = verifyAndBuildZap1ReceiverBinding({
    receipt: extraWrapperField,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(strictEnvelope.ok, false);
  assert.equal(strictEnvelope.binding, null);
  assert(failureCodes(strictEnvelope.verification).has("receipt_wrapper_fields_mismatch"));

  const oversizedRegistry = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw: Buffer.alloc(131_073, 0x20),
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(oversizedRegistry.ok, false);
  assert(failureCodes(oversizedRegistry.verification).has("registry_raw_invalid"));

  const stale = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validReceipt.data.validUntil + 1,
  });
  assert.equal(stale.ok, false);
  assert(failureCodes(stale).has("receipt_expired"));

  const expiryBoundary = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validReceipt.data.validUntil,
  });
  assert.equal(expiryBoundary.ok, false);
  assert.equal(expiryBoundary.binding, null);
  assert(failureCodes(expiryBoundary.verification).has("receipt_expired"));
  const futureBoundaryFailure = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validReceipt.data.checkedAt - 6,
  });
  assert.equal(futureBoundaryFailure.ok, false);
  assert(failureCodes(futureBoundaryFailure).has("receipt_from_future"));

  const lateAction = structuredClone(actionInstance);
  lateAction.created_at = new Date((validReceipt.data.checkedAt + 6) * 1000).toISOString();
  const lateActionResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance: lateAction,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(lateActionResult.ok, false);
  assert(failureCodes(lateActionResult).has("action_created_after_check"));

  const tamperedMeta = fixtureManifest.vectors.find((vector) => vector.label === "DELIBERATE_FAILURE_DEMO_TAMPERED");
  assert.equal(tamperedFixture.demo.mode, "tampered");
  assert.equal(tamperedFixture.demo.verdict, "BLOCK");
  const tampered = verifyOracleSafetyCheckV2({
    receipt: tamperedFixture.receipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: tamperedMeta.verification_time_seconds,
  });
  assert.equal(tampered.ok, false);
  for (const code of tamperedMeta.expected_failure_codes) assert(failureCodes(tampered).has(code), `missing ${code}`);

  const expiredMeta = fixtureManifest.vectors.find((vector) => vector.label === "DELIBERATE_FAILURE_DEMO_EXPIRED");
  assert.equal(expiredFixture.demo.mode, "expired");
  assert.equal(expiredFixture.demo.verdict, "BLOCK");
  const expired = verifyOracleSafetyCheckV2({
    receipt: expiredFixture.receipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: expiredMeta.verification_time_seconds,
  });
  assert.equal(expired.ok, false);
  for (const code of expiredMeta.expected_failure_codes) assert(failureCodes(expired).has(code), `missing ${code}`);

  const changedAmount = structuredClone(actionInstance);
  changedAmount.request.tradeAmountUsd = { display: "10000.000001", scale_decimals: 6, atoms: "10000000001" };
  const mismatch = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance: changedAmount,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(mismatch.ok, false);
  assert(failureCodes(mismatch).has("request_hash_mismatch"));
  assert(failureCodes(mismatch).has("tradeAmountUsd_mismatch"));

  const changedInstance = structuredClone(actionInstance);
  changedInstance.nonce = "reference-nonce-20260821-002";
  const changedInstanceResult = verifyAndBuildZap1ReceiverBinding({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance: changedInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(changedInstanceResult.ok, true, JSON.stringify(changedInstanceResult.verification.failures));
  const changedBinding = changedInstanceResult.binding;
  assert.equal(changedBinding.zap1_external_action_args.intent_hash, binding.zap1_external_action_args.intent_hash);
  assert.notEqual(changedBinding.zap1_external_action_args.action_instance_commitment, binding.zap1_external_action_args.action_instance_commitment);
  assert.notEqual(changedBinding.zap1_hashes.claim_hash, binding.zap1_hashes.claim_hash);
  assert.notEqual(changedBinding.zap1_hashes.evidence_hash, binding.zap1_hashes.evidence_hash);

  const changedReceipt = structuredClone(validReceipt);
  changedReceipt.data.tradeAmountUsd = "10000000001";
  const atomicMismatch = verifyAndBuildZap1ReceiverBinding({
    receipt: changedReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(atomicMismatch.ok, false);
  assert.equal(atomicMismatch.binding, null);
  assert(failureCodes(atomicMismatch.verification).has("uid_mismatch"));
  assert(failureCodes(atomicMismatch.verification).has("request_hash_mismatch") || failureCodes(atomicMismatch.verification).has("tradeAmountUsd_mismatch"));

  const wrongUnits = structuredClone(unitContract);
  wrongUnits.fields.tradeAmountUsd.scale_decimals = 8;
  const wrongUnitResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract: wrongUnits,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(wrongUnitResult.ok, false);
  assert(failureCodes(wrongUnitResult).has("trade_amount_scale_mismatch"));

  for (const hostilePolicy of [
    { expectedIssuer: "https://attacker.invalid" },
    { keyId: "attacker-key" },
    { expectedSigner: "0x0000000000000000000000000000000000000001" },
    { expectedRegistrySha256: "0".repeat(64) },
    { allowedVerdicts: ["PASS", "BLOCK"] },
    { expectedTtlSeconds: 3600 },
    { maxReceiptAgeSeconds: 601 },
    { maxOracleDataAgeSeconds: 31 },
    { minParticipants: 2 },
    { minSourceGroups: 1 },
    { maxDeviationBps: 101 },
    { maxManipulationRiskBps: 1001 },
    { minCrossProviderAgreementBps: 9899 },
    { maxStablecoinDepegBps: 101 },
    { clockSkewSeconds: 6 },
    { undeclaredPolicyField: true },
  ]) {
    const downgrade = verifyOracleSafetyCheckV2({
      receipt: validReceipt,
      registry,
      actionInstance,
      unitContract,
      nowSeconds: validMeta.historical_verification_time_seconds,
      policy: hostilePolicy,
    });
    assert.equal(downgrade.ok, false, "policy downgrade was accepted: " + JSON.stringify(hostilePolicy));
    assert(failureCodes(downgrade).has("verification_input_invalid"));
  }

  const stricterPolicy = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
    policy: {
      maxReceiptAgeSeconds: 60,
      maxOracleDataAgeSeconds: 20,
      minParticipants: 7,
      minSourceGroups: 7,
      maxDeviationBps: 80,
      maxManipulationRiskBps: 500,
      minCrossProviderAgreementBps: 9920,
      maxStablecoinDepegBps: 0,
      clockSkewSeconds: 0,
    },
  });
  assert.equal(stricterPolicy.ok, true, JSON.stringify(stricterPolicy.failures));

  for (const field of ["sourceAssetId", "destinationAssetId"]) {
    const crossChainAction = structuredClone(actionInstance);
    crossChainAction.request[field] = field === "sourceAssetId"
      ? "eip155:2/slip44:60"
      : "eip155:2/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const crossChainResult = verifyOracleSafetyCheckV2({
      receipt: validReceipt,
      registry,
      actionInstance: crossChainAction,
      unitContract,
      nowSeconds: validMeta.historical_verification_time_seconds,
    });
    assert.equal(crossChainResult.ok, false);
    assert(failureCodes(crossChainResult).has("action_instance_invalid"));
  }

  const duplicateKeyRegistry = structuredClone(registry);
  duplicateKeyRegistry.public_keys.push(structuredClone(duplicateKeyRegistry.public_keys[0]));
  const duplicateKeyResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry: duplicateKeyRegistry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(duplicateKeyResult.ok, false);
  assert(failureCodes(duplicateKeyResult).has("registry_key_ambiguous"));

  const wrongVerifyUrlReceipt = structuredClone(validReceipt);
  wrongVerifyUrlReceipt.verifyUrl = "https://attacker.invalid/verify";
  const wrongVerifyUrlResult = verifyOracleSafetyCheckV2({
    receipt: wrongVerifyUrlReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(wrongVerifyUrlResult.ok, false);
  assert(failureCodes(wrongVerifyUrlResult).has("receipt_verify_url_mismatch"));

  const wrongRequestSchemaRegistry = structuredClone(registry);
  wrongRequestSchemaRegistry.schemas.CanonicalPreTradeRequest.eip712.primaryType = "AttackerRequest";
  const wrongRequestSchemaResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry: wrongRequestSchemaRegistry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(wrongRequestSchemaResult.ok, false);
  assert(failureCodes(wrongRequestSchemaResult).has("registry_request_primary_type_mismatch"));

  const semanticMutations = [
    ["participantCount", "115792089237316195423570985008687907853269984665640564039457584007913129639935", "policy_values_invalid"],
    ["sourceGroupCount", "115792089237316195423570985008687907853269984665640564039457584007913129639935", "policy_values_invalid"],
    ["requiredParticipantCount", 4, "required_participant_count_mismatch"],
    ["sourceGroupCount", 8, "source_groups_exceed_participants"],
    ["maxDeviationBps", 10001, "max_deviation_out_of_range"],
    ["manipulationRiskBps", 10001, "manipulation_risk_out_of_range"],
    ["crossProviderAgreementBps", 10001, "provider_agreement_out_of_range"],
    ["maxStablecoinDepegBps", 10001, "stablecoin_depeg_out_of_range"],
    ["consensusPrice", 0, "consensus_price_zero"],
    ["tradeAmountUsd", 0, "trade_amount_zero"],
    ["recommendedMaxPositionUsd", 9999999999, "trade_exceeds_recommended_max"],
    ["evaluatedAssetIdsHash", "0x" + "00".repeat(32), "evaluated_assets_hash_mismatch"],
  ];
  for (const [field, value, expectedCode] of semanticMutations) {
    const changed = structuredClone(validReceipt);
    changed.data[field] = value;
    const result = verifyOracleSafetyCheckV2({
      receipt: changed,
      registry,
      actionInstance,
      unitContract,
      nowSeconds: validMeta.historical_verification_time_seconds,
    });
    assert.equal(result.ok, false);
    assert(failureCodes(result).has(expectedCode), "missing semantic failure " + expectedCode);
  }

  const missingReplayGuard = verifyAndBuildReceiverAtomic({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(missingReplayGuard.ok, false);
  assert.equal(missingReplayGuard.binding, null);
  assert(failureCodes(missingReplayGuard.verification).has("replay_guard_missing"));

  const sharedReplayGuard = createInMemoryReplayGuard();
  const replayArgs = {
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
    replayGuard: sharedReplayGuard,
  };
  const firstReservation = verifyAndBuildReceiverAtomic(replayArgs);
  const secondReservation = verifyAndBuildReceiverAtomic(replayArgs);
  assert.equal(firstReservation.ok, true);
  assert.equal(firstReservation.replay.status, "RESERVED");
  assert.equal(secondReservation.ok, false);
  assert.equal(secondReservation.binding, null);
  assert.equal(secondReservation.replay.key, firstReservation.replay.key);
  assert(failureCodes(secondReservation.verification).has("action_replay_rejected"));
  assert.equal(sharedReplayGuard.size, 1);

  const replayStoreFailure = verifyAndBuildReceiverAtomic({
    ...replayArgs,
    replayGuard: {
      reserve() {
        throw new Error("simulated durable replay store outage");
      },
    },
  });
  assert.equal(replayStoreFailure.ok, false);
  assert.equal(replayStoreFailure.binding, null);
  assert(failureCodes(replayStoreFailure.verification).has("replay_guard_failed"));

  const unknownActionField = structuredClone(actionInstance);
  unknownActionField.unbound_operator_note = "must not be silently ignored";
  const unknownActionResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance: unknownActionField,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(unknownActionResult.ok, false);
  assert(failureCodes(unknownActionResult).has("action_instance_invalid"));

  const sparsePolicy = [];
  sparsePolicy.length = 1;
  const sparseInputResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
    policy: sparsePolicy,
  });
  assert.equal(sparseInputResult.ok, false);
  assert(failureCodes(sparseInputResult).has("verification_input_invalid"));

  const cyclicRegistry = structuredClone(registry);
  cyclicRegistry.self = cyclicRegistry;
  const cyclicInputResult = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry: cyclicRegistry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(cyclicInputResult.ok, false);
  assert(failureCodes(cyclicInputResult).has("verification_input_invalid"));

  const oversizedReceipt = structuredClone(validReceipt);
  oversizedReceipt.attesterLabel = "x".repeat(131_073);
  const oversizedReceiptResult = verifyOracleSafetyCheckV2({
    receipt: oversizedReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(oversizedReceiptResult.ok, false);
  assert(failureCodes(oversizedReceiptResult).has("verification_input_invalid"));

  const stressIterations = 100;
  const stressStarted = performance.now();
  for (let index = 0; index < stressIterations; index += 1) {
    const stressResult = verifyAndBuildZap1ReceiverBinding({
      receipt: validReceipt,
      registry,
      registryRaw,
      actionInstance,
      unitContract,
      nowSeconds: validMeta.historical_verification_time_seconds,
    });
    assert.equal(stressResult.ok, true);
    assert.deepEqual(stressResult.binding.zap1_hashes, binding.zap1_hashes);
  }
  const stressDurationMs = performance.now() - stressStarted;
  assert(stressDurationMs < 30_000, "100 bounded verification iterations exceeded 30 seconds");

  return {
    pass: true,
    frozen_vectors: 3,
    independent_action_instance: actionInstance.action_instance_id,
    native_uid: valid.native.uid,
    recovered_signer: valid.native.recoveredSigner,
    unit_contract_hash: valid.unit_contract_hash,
    display: valid.native.display,
    zap1_hashes: binding.zap1_hashes,
    current_authorization: "REJECTED_EXPIRED",
    resilience: {
      iterations: stressIterations,
      duration_ms: Number(stressDurationMs.toFixed(3)),
      ceiling_ms: 30_000,
      replay_guard: "ONE_RESERVATION_THEN_FAIL_CLOSED",
      replay_store_failure: "FAIL_CLOSED",
      bounded_receipt_bytes: 131072,
      bounded_registry_bytes: 131072,
      canonical_json_edge_rejections: ["sparse_array", "cycle", "unknown_action_field"],
      policy_downgrades_rejected: 16,
      caip_chain_mismatches_rejected: 2,
      semantic_invariant_mutations_rejected: semanticMutations.length,
    },
    binding,
  };
}
