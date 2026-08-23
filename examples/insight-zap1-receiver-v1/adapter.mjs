import { createHash } from "node:crypto";

import { AbiCoder, TypedDataEncoder, getAddress, keccak256, verifyTypedData } from "ethers";

export const RECEIVER_POLICY_VERSION = "insight-zap1-receiver-policy-v1";
export const EXPECTED_ISSUER = "https://www.oracleinsight.xyz";
export const EXPECTED_KEY_ID = "insight-oracle-safety-v2";
export const EXPECTED_REGISTRY_SHA256 = "9e7bc705e32280d4997c3ed3d27b5c8794c80198d2eaeaa3310893e939a7deae";
export const EXPECTED_SIGNER = "0xa268676C85b927D64a4e2384636874f76D69e419";
export const EXPECTED_VERIFY_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/verify";

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
const HEX_64_LOWER = /^[0-9a-f]{64}$/;
const SIGNATURE_65 = /^0x[0-9a-fA-F]{130}$/;
const CAIP_19_EVM = /^eip155:[1-9][0-9]*\/(?:slip44:[1-9][0-9]*|erc20:0x[0-9a-fA-F]{40})$/;
const ALLOWED_ACTIONS = new Set(["swap", "borrow", "lend", "liquidate", "repay"]);
const MAX_RECEIPT_BYTES = 128 * 1024;
const MAX_REGISTRY_BYTES = 128 * 1024;
const MAX_CONTEXT_BYTES = 32 * 1024;

function canonicalizeInner(value, stack) {
  if (typeof value === "bigint") return JSON.stringify(value.toString(10));
  if (value === null || typeof value !== "object") {
    if (value === undefined || typeof value === "function" || typeof value === "symbol") {
      throw new TypeError("canonical JSON does not support undefined, functions, or symbols");
    }
    if (typeof value === "number" && (!Number.isFinite(value) || !Number.isSafeInteger(value))) {
      throw new TypeError("canonical JSON numbers must be finite safe integers");
    }
    return JSON.stringify(value);
  }
  if (stack.has(value)) throw new TypeError("canonical JSON must be acyclic");
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Object.keys(value);
      if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
        throw new TypeError("canonical JSON arrays must be dense and contain only indexed elements");
      }
      return "[" + value.map((entry) => canonicalizeInner(entry, stack)).join(",") + "]";
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("canonical JSON only supports plain objects");
    }
    const keys = Object.keys(value).sort();
    if (Reflect.ownKeys(value).length !== keys.length) {
      throw new TypeError("canonical JSON objects must not contain symbols or non-enumerable fields");
    }
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value")) {
        throw new TypeError("canonical JSON objects must not contain accessors");
      }
      if (descriptor.value === undefined) {
        throw new TypeError("canonical JSON field " + key + " is undefined");
      }
    }
    return "{" + keys
      .map((key) => JSON.stringify(key) + ":" + canonicalizeInner(value[key], stack))
      .join(",") + "}";
  } finally {
    stack.delete(value);
  }
}

export function canonicalize(value) {
  return canonicalizeInner(value, new Set());
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

function sha256RawBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeHex32(value, prefixed = true) {
  if (typeof value !== "string" || !HEX_32.test(value)) throw new TypeError("expected a 32-byte hexadecimal value");
  const bare = value.toLowerCase().replace(/^0x/, "");
  return prefixed ? `0x${bare}` : bare;
}

function normalizeUint(value, field) {
  if (typeof value === "number" && (!Number.isSafeInteger(value) || value < 0)) {
    throw new TypeError(`${field} must be a non-negative safe integer`);
  }
  if (typeof value === "string" && !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${field} must be a canonical unsigned integer string`);
  }
  if (!["number", "string", "bigint"].includes(typeof value)) {
    throw new TypeError(`${field} must be an unsigned integer`);
  }
  try {
    const normalized = BigInt(value);
    if (normalized < 0n) throw new Error("negative");
    return normalized;
  } catch {
    throw new TypeError(`${field} must be an unsigned integer`);
  }
}

function safeInteger(value, field, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(field + " must be a safe integer in " + minimum + ".." + maximum);
  }
  return value;
}

function safeUintNumber(value, field, maximum = Number.MAX_SAFE_INTEGER) {
  const normalized = normalizeUint(value, field);
  if (normalized > BigInt(maximum)) {
    throw new TypeError(field + " exceeds the supported receiver bound " + maximum);
  }
  return Number(normalized);
}

function hasExactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return sameCanonical(Object.keys(value).sort(), [...expected].sort());
}

function requiredText(value, field, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new TypeError(`${field} must be a non-empty string of at most ${max} characters`);
  }
  return value;
}

function normalizePolicy(policy = {}) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new TypeError("policy must be a plain object");
  }
  const allowed = new Set([
    "maxReceiptAgeSeconds",
    "maxOracleDataAgeSeconds",
    "minParticipants",
    "minSourceGroups",
    "maxDeviationBps",
    "maxManipulationRiskBps",
    "minCrossProviderAgreementBps",
    "maxStablecoinDepegBps",
    "clockSkewSeconds",
  ]);
  for (const key of Object.keys(policy)) {
    if (!allowed.has(key)) throw new TypeError("policy contains unsupported or trust-root field " + key);
  }
  return Object.freeze({
    expectedIssuer: EXPECTED_ISSUER,
    keyId: EXPECTED_KEY_ID,
    expectedSigner: EXPECTED_SIGNER,
    expectedVerifyUrl: EXPECTED_VERIFY_URL,
    expectedRegistrySha256: EXPECTED_REGISTRY_SHA256,
    allowedVerdicts: Object.freeze(["PASS"]),
    expectedTtlSeconds: 600,
    maxReceiptAgeSeconds: safeInteger(policy.maxReceiptAgeSeconds ?? 600, "maxReceiptAgeSeconds", 0, 600),
    maxOracleDataAgeSeconds: safeInteger(policy.maxOracleDataAgeSeconds ?? 30, "maxOracleDataAgeSeconds", 0, 30),
    minParticipants: safeInteger(policy.minParticipants ?? 3, "minParticipants", 3, 1000),
    minSourceGroups: safeInteger(policy.minSourceGroups ?? 2, "minSourceGroups", 2, 1000),
    maxDeviationBps: safeInteger(policy.maxDeviationBps ?? 100, "maxDeviationBps", 0, 100),
    maxManipulationRiskBps: safeInteger(policy.maxManipulationRiskBps ?? 1000, "maxManipulationRiskBps", 0, 1000),
    minCrossProviderAgreementBps: safeInteger(policy.minCrossProviderAgreementBps ?? 9900, "minCrossProviderAgreementBps", 9900, 10000),
    maxStablecoinDepegBps: safeInteger(policy.maxStablecoinDepegBps ?? 100, "maxStablecoinDepegBps", 0, 100),
    clockSkewSeconds: safeInteger(policy.clockSkewSeconds ?? 5, "clockSkewSeconds", 0, 5),
  });
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

function exactRegistryBytes(registryRaw) {
  if (!(registryRaw instanceof Uint8Array)) {
    throw new TypeError("registryRaw must be a Uint8Array containing the exact received bytes");
  }
  if (registryRaw.byteLength > MAX_REGISTRY_BYTES) throw new TypeError("registryRaw exceeds the 131072-byte receiver limit");
  return Buffer.from(registryRaw);
}

function boundedJson(value, field, maxBytes) {
  let encoded;
  try {
    encoded = canonicalize(value);
  } catch (error) {
    throw new TypeError(field + " must be canonical JSON: " + error.message);
  }
  const bytes = Buffer.byteLength(encoded, "utf8");
  if (bytes > maxBytes) throw new TypeError(field + " exceeds " + maxBytes + " bytes");
  return { encoded, bytes };
}

function safeAddress(value) {
  try {
    return getAddress(value);
  } catch {
    return null;
  }
}

function evaluatedSourceHash(sourceAssetId) {
  return keccak256(AbiCoder.defaultAbiCoder().encode(["string[]"], [[sourceAssetId]]));
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
  if (!hasExactKeys(actionInstance, [
    "schema",
    "action_instance_id",
    "receiver_id",
    "created_at",
    "nonce",
    "commitment_salt_hex",
    "purpose",
    "request",
    "receipt_uid",
    "execution_authorized",
  ])) throw new TypeError("action instance fields differ from the pinned contract");
  if (actionInstance.schema !== "frontier-compute.insight-action-instance.v1") throw new TypeError("action instance schema mismatch");
  if (actionInstance.receipt_uid !== null) throw new TypeError("independent action instance must not contain a receipt uid");
  if (actionInstance.execution_authorized !== false) throw new TypeError("reference action must explicitly deny execution authority");
  const actionInstanceId = requiredText(actionInstance.action_instance_id, "action_instance_id", 128);
  const receiverId = requiredText(actionInstance.receiver_id, "receiver_id", 128);
  const nonce = requiredText(actionInstance.nonce, "nonce", 128);
  const commitmentSalt = requiredText(actionInstance.commitment_salt_hex, "commitment_salt_hex", 64);
  if (!HEX_64_LOWER.test(commitmentSalt)) throw new TypeError("commitment_salt_hex must be 32 bytes of lowercase hexadecimal");
  const createdAtSeconds = Date.parse(actionInstance.created_at) / 1000;
  if (!Number.isFinite(createdAtSeconds)) throw new TypeError("action created_at must be an ISO timestamp");
  const request = actionInstance.request;
  if (!request || typeof request !== "object") throw new TypeError("action request is required");
  if (!hasExactKeys(request, ["subjectChainId", "sourceAssetId", "destinationAssetId", "action", "tradeAmountUsd"])) {
    throw new TypeError("action request fields differ from the pinned contract");
  }
  const subjectChainId = normalizeUint(request.subjectChainId, "subjectChainId");
  const sourceAssetId = requiredText(request.sourceAssetId, "sourceAssetId");
  const destinationAssetId = requiredText(request.destinationAssetId, "destinationAssetId");
  if (!CAIP_19_EVM.test(sourceAssetId) || !CAIP_19_EVM.test(destinationAssetId)) throw new TypeError("asset ids must use the supported EVM CAIP-19 form");
  const sourceAssetChainId = BigInt(sourceAssetId.slice("eip155:".length, sourceAssetId.indexOf("/")));
  const destinationAssetChainId = BigInt(destinationAssetId.slice("eip155:".length, destinationAssetId.indexOf("/")));
  if (sourceAssetChainId !== subjectChainId) throw new TypeError("source asset chain must equal subjectChainId");
  if (destinationAssetChainId !== subjectChainId) throw new TypeError("destination asset chain must equal subjectChainId");
  const action = requiredText(request.action, "action", 32);
  if (!ALLOWED_ACTIONS.has(action)) throw new TypeError(`unsupported action ${action}`);
  const amount = request.tradeAmountUsd;
  if (!amount || typeof amount !== "object") throw new TypeError("tradeAmountUsd fixed-point object is required");
  if (!hasExactKeys(amount, ["display", "scale_decimals", "atoms"])) {
    throw new TypeError("tradeAmountUsd fields differ from the pinned fixed-point contract");
  }
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
    commitment_salt_hex: commitmentSalt,
    purpose: requiredText(actionInstance.purpose, "purpose", 256),
    request: nativeAction,
    units: {
      tradeAmountUsd: { display: amount.display, scale_decimals: expectedDecimals, atoms: declaredAtoms.toString(10) },
    },
    execution_authorized: false,
  };
  const intendedActionHash = sha256Hex({
    domain: "zap1-insight-intended-action-v1",
    unit_contract_hash: unitValidation.hash,
    request: nativeAction,
  });
  const actionInstanceCommitment = sha256Hex({
    domain: "zap1-insight-action-instance-commitment-v1",
    action_instance_id: actionInstanceId,
    receiver_id: receiverId,
    nonce,
    commitment_salt_hex: commitmentSalt,
    intended_action_hash: intendedActionHash,
  });
  return {
    normalized,
    nativeAction,
    typedAction: { ...nativeAction, subjectChainId, tradeAmountUsd: declaredAtoms },
    createdAtSeconds: Math.floor(createdAtSeconds),
    unitContractHash: unitValidation.hash,
    intendedActionHash,
    actionInstanceCommitment,
  };
}

export function verifyOracleSafetyCheckV2({ receipt, registry, actionInstance, unitContract, nowSeconds, policy = {} }) {
  const failures = [];
  const fail = (code, detail) => failures.push({ code, detail });
  let effectivePolicy;
  try {
    effectivePolicy = normalizePolicy(policy);
  } catch (error) {
    fail("verification_input_invalid", error.message);
    return { ok: false, failures, policy: null };
  }
  if (!receipt || typeof receipt !== "object") fail("receipt_missing", "receipt must be an object");
  if (!registry || typeof registry !== "object") fail("registry_missing", "registry must be an object");
  if (!unitContract || typeof unitContract !== "object") fail("unit_contract_missing", "unit contract must be an object");
  if (failures.length) return { ok: false, failures, policy: effectivePolicy };
  try {
    if (!Number.isSafeInteger(nowSeconds)) throw new TypeError("explicit nowSeconds must be a safe integer");
    boundedJson(receipt, "receipt", MAX_RECEIPT_BYTES);
    boundedJson(registry, "registry", MAX_REGISTRY_BYTES);
    boundedJson(actionInstance, "actionInstance", MAX_CONTEXT_BYTES);
    boundedJson(unitContract, "unitContract", MAX_CONTEXT_BYTES);
    boundedJson(policy, "policy", MAX_CONTEXT_BYTES);
  } catch (error) {
    fail("verification_input_invalid", error.message);
    return { ok: false, failures, policy: effectivePolicy };
  }
  if (!hasExactKeys(receipt, ["uid", "schemaVersion", "attester", "attesterLabel", "signedAt", "validForSeconds", "validUntil", "signature", "verifyUrl", "data", "eip712"])) {
    fail("receipt_wrapper_fields_mismatch", "receipt wrapper fields differ from the pinned v2 envelope");
  }
  if (!hasExactKeys(receipt.data, ORACLE_SAFETY_TYPES_V2.OracleSafetyCheck.map((field) => field.name))) {
    fail("receipt_data_fields_mismatch", "signed receipt data fields differ from the pinned 26-field type");
  }
  if (!hasExactKeys(receipt.eip712, ["domain", "types", "primaryType", "canonicalRequestDomain", "canonicalRequestTypes", "canonicalRequestPrimaryType"])) {
    fail("receipt_eip712_fields_mismatch", "receipt EIP-712 metadata fields differ from the pinned envelope");
  }

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
  if (registry.verify !== effectivePolicy.expectedVerifyUrl) fail("registry_verify_url_mismatch", "registry verify URL differs from the pinned endpoint");
  if (receipt.verifyUrl !== effectivePolicy.expectedVerifyUrl) fail("receipt_verify_url_mismatch", "receipt verify URL differs from the pinned endpoint");
  const matchingKeys = Array.isArray(registry.public_keys)
    ? registry.public_keys.filter((candidate) => candidate?.key_id === effectivePolicy.keyId)
    : [];
  if (matchingKeys.length === 0) fail("registry_key_missing", `missing key ${effectivePolicy.keyId}`);
  if (matchingKeys.length > 1) fail("registry_key_ambiguous", `duplicate key ${effectivePolicy.keyId}`);
  const key = matchingKeys.length === 1 ? matchingKeys[0] : null;
  if (key && key.algorithm !== "EIP-712/secp256k1") fail("registry_algorithm_mismatch", `unexpected algorithm ${key.algorithm}`);
  const registryAddress = key ? safeAddress(key.public_key ?? key.address) : null;
  if (key && !registryAddress) fail("registry_address_invalid", "registry key is not an EVM address");
  if (registryAddress && registryAddress !== effectivePolicy.expectedSigner) fail("registry_signer_not_pinned", "registry signer differs from the pinned issuer key");

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
  if (attester && attester !== effectivePolicy.expectedSigner) fail("attester_not_pinned", "receipt attester differs from the pinned issuer signer");

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
        if (recoveredSigner !== effectivePolicy.expectedSigner) fail("signature_not_from_pinned_signer", "recovered signer differs from the pinned issuer signer");
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
    if (nowSeconds >= validUntil) fail("receipt_expired", "receipt is outside its validity window");
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
    const participants = safeUintNumber(receipt.data?.participantCount, "participantCount", 1000);
    const required = safeUintNumber(receipt.data?.requiredParticipantCount, "requiredParticipantCount", 1000);
    const groups = safeUintNumber(receipt.data?.sourceGroupCount, "sourceGroupCount", 1000);
    const dataAge = safeUintNumber(receipt.data?.maxDataAgeSeconds, "maxDataAgeSeconds");
    const deviation = safeUintNumber(receipt.data?.maxDeviationBps, "maxDeviationBps");
    const manipulation = safeUintNumber(receipt.data?.manipulationRiskBps, "manipulationRiskBps");
    const agreement = safeUintNumber(receipt.data?.crossProviderAgreementBps, "crossProviderAgreementBps");
    const depeg = safeUintNumber(receipt.data?.maxStablecoinDepegBps, "maxStablecoinDepegBps");
    const recommended = normalizeUint(receipt.data?.recommendedMaxPositionUsd, "recommendedMaxPositionUsd");
    const trade = normalizeUint(receipt.data?.tradeAmountUsd, "tradeAmountUsd");
    const consensusPrice = normalizeUint(receipt.data?.consensusPrice, "consensusPrice");
    if (required !== 3) fail("required_participant_count_mismatch", "signed requiredParticipantCount must equal 3");
    if (participants < Math.max(required, effectivePolicy.minParticipants)) fail("quorum_insufficient", "participant quorum is below policy");
    if (groups < effectivePolicy.minSourceGroups) fail("source_groups_insufficient", "source-group independence is below policy");
    if (groups > participants) fail("source_groups_exceed_participants", "source groups cannot exceed participants");
    if (dataAge > effectivePolicy.maxOracleDataAgeSeconds) fail("oracle_data_too_old", "underlying oracle data age exceeds policy");
    if (deviation > 10_000) fail("max_deviation_out_of_range", "maxDeviationBps exceeds 10000");
    if (manipulation > 10_000) fail("manipulation_risk_out_of_range", "manipulationRiskBps exceeds 10000");
    if (agreement > 10_000) fail("provider_agreement_out_of_range", "crossProviderAgreementBps exceeds 10000");
    if (depeg > 10_000) fail("stablecoin_depeg_out_of_range", "maxStablecoinDepegBps exceeds 10000");
    if (deviation > effectivePolicy.maxDeviationBps) fail("deviation_too_high", "max deviation exceeds policy");
    if (manipulation > effectivePolicy.maxManipulationRiskBps) fail("manipulation_risk_too_high", "manipulation risk exceeds policy");
    if (agreement < effectivePolicy.minCrossProviderAgreementBps) fail("agreement_too_low", "cross-provider agreement is below policy");
    if (depeg > effectivePolicy.maxStablecoinDepegBps) fail("stablecoin_depeg_too_high", "stablecoin depeg exceeds policy");
    if (consensusPrice === 0n) fail("consensus_price_zero", "consensus price must be positive");
    if (trade === 0n) fail("trade_amount_zero", "trade amount must be positive");
    if (trade > recommended) fail("trade_exceeds_recommended_max", "trade amount exceeds recommended maximum position");
  } catch (error) {
    fail("policy_values_invalid", error.message);
  }

  if (action) {
    try {
      if (normalizeHex32(receipt.data?.evaluatedAssetIdsHash) !== evaluatedSourceHash(action.nativeAction.sourceAssetId).toLowerCase()) {
        fail("evaluated_assets_hash_mismatch", "evaluatedAssetIdsHash does not bind exactly the source asset");
      }
    } catch (error) {
      fail("evaluated_assets_hash_invalid", error.message);
    }
  }

  const registrySchema = registry.schemas?.OracleSafetyCheck;
  if (registrySchema?.schemaVersion !== 2) fail("registry_schema_v2_missing", "registry does not publish OracleSafetyCheck v2");
  if (!sameCanonical(registrySchema?.eip712?.domain, ORACLE_SAFETY_DOMAIN_V2)) fail("registry_domain_mismatch", "registry v2 domain differs");
  if (!sameCanonical(registrySchema?.eip712?.types, ORACLE_SAFETY_TYPES_V2)) fail("registry_types_mismatch", "registry v2 type differs");
  if (registrySchema?.eip712?.primaryType !== "OracleSafetyCheck") fail("registry_primary_type_mismatch", "registry primary type differs");
  const registryRequestSchema = registry.schemas?.CanonicalPreTradeRequest;
  if (!sameCanonical(registryRequestSchema?.eip712?.domain, CANONICAL_REQUEST_DOMAIN_V1)) fail("registry_request_domain_mismatch", "registry canonical request domain differs");
  if (!sameCanonical(registryRequestSchema?.eip712?.types, CANONICAL_REQUEST_TYPES_V1)) fail("registry_request_types_mismatch", "registry canonical request type differs");
  if (registryRequestSchema?.eip712?.primaryType !== "CanonicalPreTradeRequest") fail("registry_request_primary_type_mismatch", "registry canonical request primary type differs");

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
      intendedActionHash: action?.intendedActionHash ?? null,
      actionInstanceCommitment: action?.actionInstanceCommitment ?? null,
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

function buildZap1ExternalReceiptBinding({ receipt, registry, registryRaw, actionInstance, unitContract, verification }) {
  if (!verification?.ok) throw new Error("native verification must pass before ZAP1 binding");
  const action = normalizeActionInstance(actionInstance, unitContract);
  const registrySha256 = sha256RawBytes(exactRegistryBytes(registryRaw));
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
    action_instance_commitment: action.actionInstanceCommitment,
    intended_action_hash: action.intendedActionHash,
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
    action_instance_commitment: action.actionInstanceCommitment,
    verifier_policy_hash: verifierPolicyHash,
    verifier_result: "PASS",
    claim_hash: claimHash,
  });
  return {
    schema: "zap1-insight-adapter-binding-v2",
    native_verification: {
      status: "PASS_AT_RECORDED_CHECK_TIME",
      uid: normalizeHex32(receipt.uid),
      recovered_signer: verification.native.recoveredSigner,
      checked_at: verification.native.checkedAt,
      valid_until: verification.native.validUntil,
      intended_action_hash: action.intendedActionHash,
      action_instance_commitment: action.actionInstanceCommitment,
      registry_sha256: registrySha256,
      unit_contract_hash: unitContractHash,
      verifier_policy_hash: verifierPolicyHash,
    },
    zap1_hashes: { subject_hash: subjectHash, claim_hash: claimHash, evidence_hash: evidenceHash },
    zap1_external_action_args: {
      rail_id: "oracleinsight.xyz",
      action_type: "price_integrity_receipt_verified",
      status: "verification_completed",
      agent_id: subjectHash,
      request_hash: normalizeHex32(receipt.data.requestHash, false),
      intent_hash: action.intendedActionHash,
      action_instance_commitment: action.actionInstanceCommitment,
      disclosed_fields: ["rail_id", "action_type", "status", "request_hash", "intent_hash", "action_instance_commitment"],
      redaction_policy: "hash_only",
      subject_hash: subjectHash,
      claim_hash: claimHash,
      evidence_hash: evidenceHash,
    },
    zap1_agent_action_args: {
      agent_id: subjectHash,
      action_type: "price_integrity_receipt_verified",
      input_hash: claimHash,
      output_hash: evidenceHash,
    },
    semantics: {
      verification_completed: "Only the independent native receipt-verification action completed; no trade, payment, rail settlement, ZAP1 attestation, or Zcash anchor completed.",
      durable_claim: "The frozen representative demo receipt signature was valid for the independently supplied action instance under the recorded policy at checked_at; live provider-observation provenance is not established.",
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

export function createInMemoryReplayGuard() {
  const reserved = new Set();
  return Object.freeze({
    reserve(replayKey) {
      if (typeof replayKey !== "string" || !HEX_64_LOWER.test(replayKey)) {
        throw new TypeError("replay key must be a lowercase SHA-256 digest");
      }
      if (reserved.has(replayKey)) return false;
      reserved.add(replayKey);
      return true;
    },
    has(replayKey) {
      return reserved.has(replayKey);
    },
    get size() {
      return reserved.size;
    },
  });
}

export function verifyAndBuildZap1ReceiverBinding({
  receipt,
  registry,
  registryRaw,
  actionInstance,
  unitContract,
  nowSeconds,
  policy = {},
  replayGuard,
}) {
  const verification = verifyOracleSafetyCheckV2({
    receipt,
    registry,
    actionInstance,
    unitContract,
    nowSeconds,
    policy,
  });
  if (!verification.ok) return { ok: false, verification, binding: null };
  let parsedRegistry;
  let registryBodySha256;
  try {
    const rawBytes = exactRegistryBytes(registryRaw);
    registryBodySha256 = sha256RawBytes(rawBytes);
    const rawText = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
    parsedRegistry = JSON.parse(rawText);
  } catch (error) {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [...verification.failures, { code: "registry_raw_invalid", detail: error.message }],
      },
      binding: null,
    };
  }
  if (!sameCanonical(parsedRegistry, registry)) {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [
          ...verification.failures,
          {
            code: "registry_raw_object_mismatch",
            detail: "captured registry bytes do not parse to the registry object used for verification",
          },
        ],
      },
      binding: null,
    };
  }
  if (!HEX_64_LOWER.test(verification.policy.expectedRegistrySha256) || registryBodySha256 !== verification.policy.expectedRegistrySha256) {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [
          ...verification.failures,
          {
            code: "registry_body_hash_mismatch",
            detail: "exact registry bytes differ from the receiver policy pin",
          },
        ],
      },
      binding: null,
    };
  }
  const binding = buildZap1ExternalReceiptBinding({
    receipt,
    registry,
    registryRaw,
    actionInstance,
    unitContract,
    verification,
  });
  if (!replayGuard || typeof replayGuard.reserve !== "function") {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [
          ...verification.failures,
          {
            code: "replay_guard_missing",
            detail: "an atomic replayGuard.reserve implementation is required",
          },
        ],
      },
      binding: null,
      replay: null,
    };
  }
  const replayKey = sha256Hex({
    domain: "zap1-insight-action-replay-v1",
    action_instance_commitment: binding.zap1_external_action_args.action_instance_commitment,
    intended_action_hash: binding.zap1_external_action_args.intent_hash,
  });
  let reserved;
  try {
    reserved = replayGuard.reserve(replayKey);
  } catch (error) {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [
          ...verification.failures,
          { code: "replay_guard_failed", detail: error.message },
        ],
      },
      binding: null,
      replay: null,
    };
  }
  if (reserved !== true) {
    return {
      ok: false,
      verification: {
        ...verification,
        ok: false,
        failures: [
          ...verification.failures,
          {
            code: "action_replay_rejected",
            detail: "the action instance was already reserved",
          },
        ],
      },
      binding: null,
      replay: { status: "REJECTED_ALREADY_RESERVED", key: replayKey },
    };
  }
  return {
    ok: true,
    verification,
    binding,
    replay: { status: "RESERVED", key: replayKey },
  };
}
