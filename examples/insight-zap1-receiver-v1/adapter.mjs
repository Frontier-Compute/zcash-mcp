import { createHash } from "node:crypto";

import { TypedDataEncoder, getAddress, verifyTypedData } from "ethers";

export const RECEIVER_POLICY_VERSION = "insight-zap1-receiver-policy-v1";
export const EXPECTED_ISSUER = "https://www.oracleinsight.xyz";
export const EXPECTED_KEY_ID = "insight-oracle-safety-v2";

export const ORACLE_SAFETY_DOMAIN_V2 = Object.freeze({
  name: "Insight Oracle Safety",
  version: "2",
  chainId: 1,
});

export const ORACLE_SAFETY_TYPES_V2 = Object.freeze({
  OracleSafetyCheck: Object.freeze([
    { name: "verdict", type: "string" },
    { name: "sourceAssetId", type: "string" },
    { name: "destinationAssetId", type: "string" },
    { name: "subjectChainId", type: "uint256" },
    { name: "action", type: "string" },
    { name: "tradeAmountUsd", type: "uint256" },
    { name: "consensusPrice", type: "uint256" },
    { name: "maxDeviationBps", type: "uint256" },
    { name: "manipulationRiskBps", type: "uint256" },
    { name: "participantCount", type: "uint256" },
    { name: "requiredParticipantCount", type: "uint256" },
    { name: "coverageStatus", type: "string" },
    { name: "independenceStatus", type: "string" },
    { name: "sourceGroupCount", type: "uint256" },
    { name: "crossProviderAgreementBps", type: "uint256" },
    { name: "maxStablecoinDepegBps", type: "uint256" },
    { name: "maxDataAgeSeconds", type: "uint256" },
    { name: "recommendedMaxPositionUsd", type: "uint256" },
    { name: "reasonCodesHash", type: "bytes32" },
    { name: "requestHash", type: "bytes32" },
    { name: "evaluationScope", type: "string" },
    { name: "evaluatedAssetIdsHash", type: "bytes32" },
    { name: "providerObservationsHash", type: "bytes32" },
    { name: "validUntil", type: "uint256" },
    { name: "checkedAt", type: "uint256" },
    { name: "schemaVersion", type: "uint256" },
  ]),
});

export const CANONICAL_REQUEST_DOMAIN_V1 = Object.freeze({
  name: "Insight Canonical Pre-Trade Request",
  version: "1",
  chainId: 1,
});

export const CANONICAL_REQUEST_TYPES_V1 = Object.freeze({
  CanonicalPreTradeRequest: Object.freeze([
    { name: "subjectChainId", type: "uint256" },
    { name: "sourceAssetId", type: "string" },
    { name: "destinationAssetId", type: "string" },
    { name: "action", type: "string" },
    { name: "tradeAmountUsd", type: "uint256" },
  ]),
});

const HEX_32 = /^(?:0x)?[0-9a-fA-F]{64}$/;
const SIGNATURE_65 = /^0x[0-9a-fA-F]{130}$/;
const CAIP_19_EVM = /^eip155:[1-9][0-9]*\/(?:slip44:[1-9][0-9]*|erc20:0x[0-9a-fA-F]{40})$/;
const ALLOWED_ACTIONS = new Set(["swap", "borrow", "lend", "liquidate", "repay"]);

export function canonicalize(value) {
  if (typeof value === "bigint") return JSON.stringify(value.toString(10));
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && (!Number.isFinite(value) || !Number.isSafeInteger(value))) {
      throw new TypeError("canonical JSON numbers must be finite safe integers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .filter((key) => value[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

export function sha256Hex(value) {
  const input = typeof value === "string" ? value : canonicalize(value);
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function sha256HexBytes(hexValue) {
  if (typeof hexValue !== "string" || !/^0x[0-9a-fA-F]+$/.test(hexValue) || hexValue.length % 2 !== 0) {
    throw new TypeError("expected a 0x-prefixed hexadecimal byte string");
  }
  return createHash("sha256").update(Buffer.from(hexValue.slice(2), "hex")).digest("hex");
}

function normalizeHex32(value, prefixed = true) {
  if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("expected a 32-byte hexadecimal value");
  const bare = value.toLowerCase().replace(/^0x/, "");
  return prefixed ? `0x${bare}` : bare;
}

function normalizeUint(value, field) {
  try {
    const normalized = BigInt(value);
    if (normalized < 0n) throw new Error("negative");
    return normalized;
  } catch {
    throw new TypeError(`${field} must be an unsigned integer`);
  }
}

function requiredText(value, field, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new TypeError(`${field} must be a non-empty string of at most ${max} characters`);
  }
  return value;
}

export function decimalToAtoms(display, decimals) {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) throw new TypeError("invalid fixed-point decimals");
  if (typeof display !== "string" || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(display)) {
    throw new TypeError("fixed-point display must be a non-negative base-10 string");
  }
  const [whole, fraction = ""] = display.split(".");
  if (fraction.length > decimals) throw new TypeError(`fixed-point display exceeds ${decimals} decimals`);
  return BigInt(`${whole}${fraction.padEnd(decimals, "0")}` || "0");
}

export function atomsToDecimal(atoms, decimals) {
  const value = normalizeUint(atoms, "atoms").toString(10).padStart(decimals + 1, "0");
  if (decimals === 0) return value;
  return `${value.slice(0, -decimals)}.${value.slice(-decimals)}`;
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function safeAddress(value) {
  try {
    return getAddress(value);
  } catch {
    return null;
  }
}

export function validateUnitContract(unitContract) {
  const failures = [];
  const expect = (condition, code) => {
    if (!condition) failures.push(code);
  };
  expect(unitContract?.schema === "frontier-compute.insight-oracle-safety-v2-units.v1", "unit_schema_mismatch");
  expect(unitContract?.fields?.tradeAmountUsd?.scale_decimals === 6, "trade_amount_scale_mismatch");
  expect(unitContract?.fields?.tradeAmountUsd?.atoms_per_unit === "1000000", "trade_amount_atoms_mismatch");
  expect(unitContract?.fields?.recommendedMaxPositionUsd?.scale_decimals === 6, "position_scale_mismatch");
  expect(unitContract?.fields?.consensusPrice?.scale_decimals === 8, "price_scale_mismatch");
  expect(unitContract?.fields?.consensusPrice?.atoms_per_unit === "100000000", "price_atoms_mismatch");
  expect(unitContract?.source_commit === "8f84ecaa83f587b1b4a797926e1a509077c5f2f9", "unit_source_commit_mismatch");
  return { ok: failures.length === 0, failures, hash: sha256Hex(unitContract) };
}

export function normalizeActionInstance(actionInstance, unitContract) {
  const unitValidation = validateUnitContract(unitContract);
  if (!unitValidation.ok) throw new TypeError(`invalid unit contract: ${unitValidation.failures.join(",")}`);
  if (!actionInstance || typeof actionInstance !== "object") throw new TypeError("action instance is required");
  if (actionInstance.schema !== "frontier-compute.insight-action-instance.v1") throw new TypeError("action instance schema mismatch");
  if (actionInstance.receipt_uid !== null) throw new TypeError("independent action instance must not contain a receipt uid");
  if (actionInstance.execution_authorized !== false) throw new TypeError("reference action must explicitly deny execution authority");
  const actionInstanceId = requiredText(actionInstance.action_instance_id, "action_instance_id", 128);
  const receiverId = requiredText(actionInstance.receiver_id, "receiver_id", 128);
  const nonce = requiredText(actionInstance.nonce, "nonce", 128);
  const createdAtSeconds = Date.parse(actionInstance.created_at) / 1000;
  if (!Number.isFinite(createdAtSeconds)) throw new TypeError("action created_at must be an ISO timestamp");
  const request = actionInstance.request;
  if (!request || typeof request !== "object") throw new TypeError("action request is required");
  const subjectChainId = normalizeUint(request.subjectChainId, "subjectChainId");
  const sourceAssetId = requiredText(request.sourceAssetId, "sourceAssetId");
  const destinationAssetId = requiredText(request.destinationAssetId, "destinationAssetId");
  if (!CAIP_19_EVM.test(sourceAssetId) || !CAIP_19_EVM.test(destinationAssetId)) throw new TypeError("asset ids must use the supported EVM CAIP-19 form");
  const action = requiredText(request.action, "action", 32);
  if (!ALLOWED_ACTIONS.has(action)) throw new TypeError(`unsupported action ${action}`);
  const amount = request.tradeAmountUsd;
  if (!amount || typeof amount !== "object") throw new TypeError("tradeAmountUsd fixed-point object is required");
  const expectedDecimals = unitContract.fields.tradeAmountUsd.scale_decimals;
  if (amount.scale_decimals !== expectedDecimals) throw new TypeError("tradeAmountUsd scale does not match the unit contract");
  const displayAtoms = decimalToAtoms(amount.display, expectedDecimals);
  const declaredAtoms = normalizeUint(amount.atoms, "tradeAmountUsd.atoms");
  if (displayAtoms !== declaredAtoms) throw new TypeError("tradeAmountUsd display and atoms disagree");
  const nativeAction = {
    subjectChainId: subjectChainId.toString(10),
    sourceAssetId,
    destinationAssetId,
    action,
    tradeAmountUsd: declaredAtoms.toString(10),
  };
  const normalized = {
    schema: actionInstance.schema,
    action_instance_id: actionInstanceId,
    receiver_id: receiverId,
    created_at: actionInstance.created_at,
    nonce,
    purpose: requiredText(actionInstance.purpose, "purpose", 256),
    request: nativeAction,
    units: {
      tradeAmountUsd: { display: amount.display, scale_decimals: expectedDecimals, atoms: declaredAtoms.toString(10) },
    },
    execution_authorized: false,
  };
  return {
    normalized,
    nativeAction,
    typedAction: { ...nativeAction, subjectChainId, tradeAmountUsd: declaredAtoms },
    createdAtSeconds: Math.floor(createdAtSeconds),
    unitContractHash: unitValidation.hash,
    actionInstanceHash: sha256Hex({ domain: "zap1-insight-action-instance-v1", unit_contract_hash: unitValidation.hash, ...normalized }),
  };
}

export function verifyOracleSafetyCheckV2({ receipt, registry, actionInstance, unitContract, nowSeconds, policy = {} }) {
  const effectivePolicy = {
    expectedIssuer: policy.expectedIssuer ?? EXPECTED_ISSUER,
    keyId: policy.keyId ?? EXPECTED_KEY_ID,
    allowedVerdicts: policy.allowedVerdicts ?? ["PASS"],
    expectedTtlSeconds: policy.expectedTtlSeconds ?? 600,
    maxReceiptAgeSeconds: policy.maxReceiptAgeSeconds ?? 600,
    maxOracleDataAgeSeconds: policy.maxOracleDataAgeSeconds ?? 30,
    minParticipants: policy.minParticipants ?? 3,
    minSourceGroups: policy.minSourceGroups ?? 2,
    maxDeviationBps: policy.maxDeviationBps ?? 100,
    maxManipulationRiskBps: policy.maxManipulationRiskBps ?? 1000,
    minCrossProviderAgreementBps: policy.minCrossProviderAgreementBps ?? 9900,
    maxStablecoinDepegBps: policy.maxStablecoinDepegBps ?? 100,
    clockSkewSeconds: policy.clockSkewSeconds ?? 5,
  };
  const failures = [];
  const fail = (code, detail) => failures.push({ code, detail });
  if (!receipt || typeof receipt !== "object") fail("receipt_missing", "receipt must be an object");
  if (!registry || typeof registry !== "object") fail("registry_missing", "registry must be an object");
  if (!unitContract || typeof unitContract !== "object") fail("unit_contract_missing", "unit contract must be an object");
  if (failures.length) return { ok: false, failures, policy: effectivePolicy };

  let action;
  try {
    action = normalizeActionInstance(actionInstance, unitContract);
  } catch (error) {
    fail("action_instance_invalid", error.message);
  }
  const unitValidation = validateUnitContract(unitContract);
  for (const code of unitValidation.failures) fail(code, "unit contract differs from the pinned receiver contract");

  if (registry.issuer !== effectivePolicy.expectedIssuer) fail("registry_issuer_mismatch", `expected ${effectivePolicy.expectedIssuer}`);
  if (registry.attestation_enabled !== true) fail("registry_attestation_disabled", "registry does not enable attestations");
  const key = Array.isArray(registry.public_keys) ? registry.public_keys.find((candidate) => candidate?.key_id === effectivePolicy.keyId) : null;
  if (!key) fail("registry_key_missing", `missing key ${effectivePolicy.keyId}`);
  if (key && key.algorithm !== "EIP-712/secp256k1") fail("registry_algorithm_mismatch", `unexpected algorithm ${key.algorithm}`);
  const registryAddress = key ? safeAddress(key.public_key ?? key.address) : null;
  if (key && !registryAddress) fail("registry_address_invalid", "registry key is not an EVM address");

  if (receipt.schemaVersion !== 2 || receipt.data?.schemaVersion !== 2) fail("schema_version_mismatch", "wrapper and signed data must both be schema v2");
  if (!sameCanonical(receipt.eip712?.domain, ORACLE_SAFETY_DOMAIN_V2)) fail("typed_domain_mismatch", "v2 domain differs from the pinned contract");
  if (receipt.eip712?.primaryType !== "OracleSafetyCheck") fail("primary_type_mismatch", "primary type must be OracleSafetyCheck");
  if (!sameCanonical(receipt.eip712?.types, ORACLE_SAFETY_TYPES_V2)) fail("typed_fields_mismatch", "ordered 26-field v2 type differs");
  if (!sameCanonical(receipt.eip712?.canonicalRequestDomain, CANONICAL_REQUEST_DOMAIN_V1)) fail("request_domain_mismatch", "canonical request domain differs");
  if (receipt.eip712?.canonicalRequestPrimaryType !== "CanonicalPreTradeRequest") fail("request_primary_type_mismatch", "canonical request primary type differs");
  if (!sameCanonical(receipt.eip712?.canonicalRequestTypes, CANONICAL_REQUEST_TYPES_V1)) fail("request_fields_mismatch", "canonical request type differs");
  if (!SIGNATURE_65.test(receipt.signature ?? "")) fail("signature_format_invalid", "expected a 65-byte signature");

  const attester = safeAddress(receipt.attester);
  if (!attester) fail("attester_invalid", "receipt attester is not an EVM address");
  if (attester && registryAddress && attester !== registryAddress) fail("attester_registry_mismatch", "receipt attester does not match the registry key");

  let nativeDigest = null;
  let recoveredSigner = null;
  if (receipt.data && sameCanonical(receipt.eip712?.types, ORACLE_SAFETY_TYPES_V2)) {
    try {
      nativeDigest = TypedDataEncoder.hash(ORACLE_SAFETY_DOMAIN_V2, ORACLE_SAFETY_TYPES_V2, receipt.data);
      if (normalizeHex32(receipt.uid) !== nativeDigest.toLowerCase()) fail("uid_mismatch", "typed-data digest does not equal receipt uid");
    } catch (error) {
      fail("typed_data_hash_failed", error.message);
    }
    if (SIGNATURE_65.test(receipt.signature ?? "")) {
      try {
        recoveredSigner = verifyTypedData(ORACLE_SAFETY_DOMAIN_V2, ORACLE_SAFETY_TYPES_V2, receipt.data, receipt.signature);
        if (attester && recoveredSigner !== attester) fail("signature_signer_mismatch", "recovered signer does not equal receipt attester");
        if (registryAddress && recoveredSigner !== registryAddress) fail("signature_registry_mismatch", "recovered signer does not equal the registry key");
      } catch (error) {
        fail("signature_recovery_failed", error.message);
      }
    }
  }

  let canonicalRequestHash = null;
  if (action) {
    try {
      canonicalRequestHash = TypedDataEncoder.hash(CANONICAL_REQUEST_DOMAIN_V1, CANONICAL_REQUEST_TYPES_V1, action.typedAction);
      if (normalizeHex32(receipt.data?.requestHash) !== canonicalRequestHash.toLowerCase()) fail("request_hash_mismatch", "signed requestHash does not bind the independent action instance");
    } catch (error) {
      fail("request_hash_failed", error.message);
    }
    for (const field of ["sourceAssetId", "destinationAssetId", "action"]) {
      if (String(receipt.data?.[field]) !== action.nativeAction[field]) fail(`${field}_mismatch`, `signed ${field} differs from the action instance`);
    }
    for (const field of ["subjectChainId", "tradeAmountUsd"]) {
      try {
        if (normalizeUint(receipt.data?.[field], field).toString(10) !== action.nativeAction[field]) fail(`${field}_mismatch`, `signed ${field} differs from the action instance`);
      } catch (error) {
        fail(`${field}_invalid`, error.message);
      }
    }
  }

  let checkedAt = null;
  let validUntil = null;
  try {
    checkedAt = Number(normalizeUint(receipt.data?.checkedAt, "checkedAt"));
    validUntil = Number(normalizeUint(receipt.data?.validUntil, "validUntil"));
    if (!Number.isSafeInteger(checkedAt) || !Number.isSafeInteger(validUntil)) throw new Error("timestamps exceed safe integer range");
    if (!Number.isSafeInteger(nowSeconds)) throw new Error("explicit nowSeconds is required and must be a safe integer");
    if (Number(receipt.validUntil) !== validUntil) fail("wrapper_valid_until_mismatch", "wrapper validUntil differs from signed data");
    if (Number(receipt.validForSeconds) !== effectivePolicy.expectedTtlSeconds) fail("ttl_policy_mismatch", `expected ${effectivePolicy.expectedTtlSeconds} second TTL`);
    if (validUntil - checkedAt !== Number(receipt.validForSeconds)) fail("ttl_arithmetic_mismatch", "validUntil - checkedAt differs from validForSeconds");
    if (action && action.createdAtSeconds > checkedAt + effectivePolicy.clockSkewSeconds) fail("action_created_after_check", "action instance was created after the oracle check");
    if (nowSeconds + effectivePolicy.clockSkewSeconds < checkedAt) fail("receipt_from_future", "checkedAt exceeds allowed clock skew");
    if (nowSeconds > validUntil) fail("receipt_expired", "receipt is outside its validity window");
    if (nowSeconds - checkedAt > effectivePolicy.maxReceiptAgeSeconds) fail("receipt_too_old", "receipt exceeds maximum accepted age");
    const signedAt = Date.parse(receipt.signedAt) / 1000;
    if (!Number.isFinite(signedAt) || Math.abs(Math.floor(signedAt) - checkedAt) > 1) fail("signed_at_mismatch", "signedAt does not align with checkedAt");
  } catch (error) {
    fail("time_fields_invalid", error.message);
  }

  if (!effectivePolicy.allowedVerdicts.includes(receipt.data?.verdict)) fail("verdict_not_allowed", `verdict ${receipt.data?.verdict} is not allowed`);
  if (receipt.data?.coverageStatus !== "SUFFICIENT") fail("coverage_insufficient", "coverageStatus must be SUFFICIENT");
  if (receipt.data?.independenceStatus !== "ASSESSED") fail("independence_not_assessed", "independenceStatus must be ASSESSED");
  if (receipt.data?.evaluationScope !== "SOURCE_ASSET_ONLY") fail("evaluation_scope_mismatch", "expected SOURCE_ASSET_ONLY");
  for (const field of ["reasonCodesHash", "requestHash", "evaluatedAssetIdsHash", "providerObservationsHash"]) {
    if (!HEX_32.test(receipt.data?.[field] ?? "")) fail(`${field}_invalid`, `${field} must be bytes32`);
  }
  try {
    const participants = Number(normalizeUint(receipt.data?.participantCount, "participantCount"));
    const required = Number(normalizeUint(receipt.data?.requiredParticipantCount, "requiredParticipantCount"));
    const groups = Number(normalizeUint(receipt.data?.sourceGroupCount, "sourceGroupCount"));
    const dataAge = Number(normalizeUint(receipt.data?.maxDataAgeSeconds, "maxDataAgeSeconds"));
    const deviation = Number(normalizeUint(receipt.data?.maxDeviationBps, "maxDeviationBps"));
    const manipulation = Number(normalizeUint(receipt.data?.manipulationRiskBps, "manipulationRiskBps"));
    const agreement = Number(normalizeUint(receipt.data?.crossProviderAgreementBps, "crossProviderAgreementBps"));
    const depeg = Number(normalizeUint(receipt.data?.maxStablecoinDepegBps, "maxStablecoinDepegBps"));
    const recommended = normalizeUint(receipt.data?.recommendedMaxPositionUsd, "recommendedMaxPositionUsd");
    const trade = normalizeUint(receipt.data?.tradeAmountUsd, "tradeAmountUsd");
    if (participants < required || required < effectivePolicy.minParticipants) fail("quorum_insufficient", "participant quorum is below policy");
    if (groups < effectivePolicy.minSourceGroups) fail("source_groups_insufficient", "source-group independence is below policy");
    if (dataAge > effectivePolicy.maxOracleDataAgeSeconds) fail("oracle_data_too_old", "underlying oracle data age exceeds policy");
    if (deviation > effectivePolicy.maxDeviationBps) fail("deviation_too_high", "max deviation exceeds policy");
    if (manipulation > effectivePolicy.maxManipulationRiskBps) fail("manipulation_risk_too_high", "manipulation risk exceeds policy");
    if (agreement < effectivePolicy.minCrossProviderAgreementBps) fail("agreement_too_low", "cross-provider agreement is below policy");
    if (depeg > effectivePolicy.maxStablecoinDepegBps) fail("stablecoin_depeg_too_high", "stablecoin depeg exceeds policy");
    if (trade > recommended) fail("trade_exceeds_recommended_max", "trade amount exceeds recommended maximum position");
  } catch (error) {
    fail("policy_values_invalid", error.message);
  }

  const registrySchema = registry.schemas?.OracleSafetyCheck;
  if (registrySchema?.schemaVersion !== 2) fail("registry_schema_v2_missing", "registry does not publish OracleSafetyCheck v2");
  if (!sameCanonical(registrySchema?.eip712?.domain, ORACLE_SAFETY_DOMAIN_V2)) fail("registry_domain_mismatch", "registry v2 domain differs");
  if (!sameCanonical(registrySchema?.eip712?.types, ORACLE_SAFETY_TYPES_V2)) fail("registry_types_mismatch", "registry v2 type differs");
  if (registrySchema?.eip712?.primaryType !== "OracleSafetyCheck") fail("registry_primary_type_mismatch", "registry primary type differs");

  const priceDecimals = unitContract.fields.consensusPrice.scale_decimals;
  const usdDecimals = unitContract.fields.tradeAmountUsd.scale_decimals;
  return {
    ok: failures.length === 0,
    failures,
    policy: effectivePolicy,
    unit_contract_hash: unitValidation.hash,
    native: {
      uid: nativeDigest,
      recoveredSigner,
      canonicalRequestHash,
      checkedAt,
      validUntil,
      actionInstanceHash: action?.actionInstanceHash ?? null,
      intendedAction: action?.nativeAction ?? null,
      display: {
        tradeAmountUsd: atomsToDecimal(receipt.data?.tradeAmountUsd ?? 0, usdDecimals),
        consensusPrice: atomsToDecimal(receipt.data?.consensusPrice ?? 0, priceDecimals),
        recommendedMaxPositionUsd: atomsToDecimal(receipt.data?.recommendedMaxPositionUsd ?? 0, usdDecimals),
      },
      historicalClaimOnlyAfter: validUntil,
    },
  };
}

export function buildZap1ExternalReceiptBinding({ receipt, registry, registryRaw, actionInstance, unitContract, verification }) {
  if (!verification?.ok) throw new Error("native verification must pass before ZAP1 binding");
  const action = normalizeActionInstance(actionInstance, unitContract);
  const registrySha256 = sha256Hex(registryRaw ?? registry);
  const unitContractHash = validateUnitContract(unitContract).hash;
  const verifierPolicyHash = sha256Hex({ domain: "zap1-insight-verifier-policy-v1", version: RECEIVER_POLICY_VERSION, policy: verification.policy });
  const subjectHash = sha256Hex({
    domain: "zap1-insight-price-integrity-subject-v1",
    issuer: registry.issuer,
    key_id: EXPECTED_KEY_ID,
    schema_version: 2,
    unit_contract_hash: unitContractHash,
  });
  const claimHash = sha256Hex({
    domain: "zap1-insight-price-integrity-claim-v1",
    action_instance_hash: action.actionInstanceHash,
    native_uid: normalizeHex32(receipt.uid),
    native_request_hash: normalizeHex32(receipt.data.requestHash),
    native_verdict: receipt.data.verdict,
    checked_at: String(receipt.data.checkedAt),
    valid_until: String(receipt.data.validUntil),
    verifier_policy_hash: verifierPolicyHash,
  });
  const evidenceHash = sha256Hex({
    domain: "zap1-insight-price-integrity-evidence-v1",
    native_typed_data_digest: normalizeHex32(verification.native.uid),
    native_signature_sha256: sha256HexBytes(receipt.signature),
    registry_sha256: registrySha256,
    unit_contract_hash: unitContractHash,
    action_instance_hash: action.actionInstanceHash,
    verifier_policy_hash: verifierPolicyHash,
    verifier_result: "PASS",
    claim_hash: claimHash,
  });
  return {
    schema: "zap1-insight-adapter-binding-v1",
    native_verification: {
      status: "PASS_AT_RECORDED_CHECK_TIME",
      uid: normalizeHex32(receipt.uid),
      recovered_signer: verification.native.recoveredSigner,
      checked_at: verification.native.checkedAt,
      valid_until: verification.native.validUntil,
      action_instance_hash: action.actionInstanceHash,
      registry_sha256: registrySha256,
      unit_contract_hash: unitContractHash,
      verifier_policy_hash: verifierPolicyHash,
    },
    zap1_hashes: { subject_hash: subjectHash, claim_hash: claimHash, evidence_hash: evidenceHash },
    zap1_tool_args: {
      rail_id: "oracleinsight.xyz",
      action_type: "price_integrity_verification_completed",
      status: "rail_settled",
      intent_hash: action.actionInstanceHash,
      quote_hash: normalizeHex32(receipt.data.requestHash, false),
      disclosed_fields: ["rail_id", "action_type", "status", "intent_hash", "quote_hash"],
      redaction_policy: "hash_only",
      subject_hash: subjectHash,
      claim_hash: claimHash,
      evidence_hash: evidenceHash,
    },
    semantics: {
      rail_settled: "Only the independent native receipt-verification action completed; no trade, payment, ZAP1 attestation, or Zcash anchor settled.",
      durable_claim: "The frozen native receipt was valid for the independently supplied action instance under the recorded policy at checked_at.",
      current_authorization: "A current action requires a fresh native receipt and a new policy evaluation.",
    },
    proof_requirements: {
      receipt_request_only: true,
      attest_event_required: true,
      proof_bundle_version: "2",
      sibling_positions_required: true,
      leaf_count_required: true,
      zcash_anchor_confirmation_required: true,
      shape_check_is_not_cryptographic_verification: true,
    },
  };
}
