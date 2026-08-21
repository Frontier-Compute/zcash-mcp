import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildZap1ExternalReceiptBinding,
  normalizeActionInstance,
  validateUnitContract,
  verifyOracleSafetyCheckV2,
} from "./adapter.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const readJson = async (...parts) => JSON.parse(await readFile(path.join(here, ...parts), "utf8"));
const failureCodes = (result) => new Set(result.failures.map((failure) => failure.code));

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
  const registryRaw = (await readFile(path.join(here, "fixtures", "registry-20260821.json"), "utf8")).trimEnd();
  const unitValidation = validateUnitContract(unitContract);
  assert.equal(unitValidation.ok, true, JSON.stringify(unitValidation.failures));
  const action = normalizeActionInstance(actionInstance, unitContract);
  assert.equal(action.nativeAction.tradeAmountUsd, "10000000000");
  assert.equal(actionInstance.receipt_uid, null);
  assert.equal(actionInstance.execution_authorized, false);

  const validMeta = fixtureManifest.vectors.find((vector) => vector.label === "VALID_LIVE_SNAPSHOT");
  const valid = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(valid.ok, true, JSON.stringify(valid.failures));
  assert.equal(valid.native.canonicalRequestHash, validReceipt.data.requestHash);
  assert.equal(valid.native.actionInstanceHash, action.actionInstanceHash);
  assert.equal(valid.native.display.tradeAmountUsd, "10000.000000");
  assert.equal(valid.native.display.consensusPrice, "3000.12000000");
  assert.equal(valid.native.display.recommendedMaxPositionUsd, "10000.000000");

  const binding = buildZap1ExternalReceiptBinding({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    verification: valid,
  });
  for (const hash of Object.values(binding.zap1_hashes)) assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(binding.zap1_tool_args.intent_hash, action.actionInstanceHash);
  assert.equal(binding.zap1_tool_args.quote_hash, validReceipt.data.requestHash.slice(2));
  assert.equal(binding.proof_requirements.receipt_request_only, true);

  const stale = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds: validReceipt.data.validUntil + 1,
  });
  assert.equal(stale.ok, false);
  assert(failureCodes(stale).has("receipt_expired"));

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
  const changedInstanceVerification = verifyOracleSafetyCheckV2({
    receipt: validReceipt,
    registry,
    actionInstance: changedInstance,
    unitContract,
    nowSeconds: validMeta.historical_verification_time_seconds,
  });
  assert.equal(changedInstanceVerification.ok, true, JSON.stringify(changedInstanceVerification.failures));
  const changedBinding = buildZap1ExternalReceiptBinding({
    receipt: validReceipt,
    registry,
    registryRaw,
    actionInstance: changedInstance,
    unitContract,
    verification: changedInstanceVerification,
  });
  assert.notEqual(changedBinding.zap1_tool_args.intent_hash, binding.zap1_tool_args.intent_hash);
  assert.notEqual(changedBinding.zap1_hashes.claim_hash, binding.zap1_hashes.claim_hash);
  assert.notEqual(changedBinding.zap1_hashes.evidence_hash, binding.zap1_hashes.evidence_hash);

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
    binding,
  };
}
