import { createHash } from "node:crypto";

import { AbiCoder, TypedDataEncoder, getAddress, keccak256, recoverAddress } from "ethers";

export const RECEIVER_POLICY_VERSION = "insight-zap1-receiver-policy-v1";
export const ROTATION_CORE_POLICY_VERSION = "insight-zap1-receiver-rotation-core-v2";
export const ROTATION_CORE_POLICY_VERSION_V3 = "insight-zap1-receiver-rotation-core-v3";
export const EXPECTED_ISSUER = "https://www.oracleinsight.xyz";
export const EXPECTED_KEY_ID = "insight-oracle-safety-v2";
export const EXPECTED_REGISTRY_SHA256 = "9e7bc705e32280d4997c3ed3d27b5c8794c80198d2eaeaa3310893e939a7deae";
export const EXPECTED_SIGNER = "0xa268676C85b927D64a4e2384636874f76D69e419";
export const EXPECTED_VERIFY_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/verify";

// The v1 atomic wrapper remains frozen to EXPECTED_REGISTRY_SHA256. V2 also
// imports these locally compiled candidate tuples. Inclusion here is neither
// issuer-succession evidence nor production admission.
export const ROTATION_CANDIDATE_SIGNING_KEYS = Object.freeze([
  Object.freeze({
    keyId: "insight-oracle-safety-v2",
    signer: "0xa268676C85b927D64a4e2384636874f76D69e419",
    algorithm: "EIP-712/secp256k1",
    validFrom: "2026-08-05",
    validUntil: "2026-09-02T17:35:36.000Z",
    admission: "FROZEN_2026_08_21_REGISTRY_AND_NATIVE_SIGNATURE",
  }),
  Object.freeze({
    keyId: "insight-oracle-safety-v2-202609",
    signer: "0x6506F789Edd43338A416f59822A63F309f97E8ce",
    algorithm: "EIP-712/secp256k1",
    validFrom: "2026-08-26T17:35:36.000Z",
    validUntil: null,
    admission: "CANDIDATE_NOT_ADMITTED_PUBLIC_REGISTRY_AND_NATIVE_SIGNATURE_ONLY",
  }),
]);

const LEGACY_SIGNING_KEYS = Object.freeze([ROTATION_CANDIDATE_SIGNING_KEYS[0]]);

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

export const ORACLE_SAFETY_DOMAIN_V3 = Object.freeze({
  name: "Insight Oracle Safety",
  version: "3",
  chainId: 1,
});

export const ORACLE_SAFETY_TYPES_V3 = Object.freeze({
  OracleSafetyCheck: Object.freeze([
    ...ORACLE_SAFETY_TYPES_V2.OracleSafetyCheck,
    { name: "requiredSourceGroupCount", type: "uint256" },
  ]),
});

export const EXPECTED_REQUIRED_SOURCE_GROUP_COUNT_V3 = 2;

function oracleSafetyContract(receipt) {
  if (receipt?.schemaVersion === 2 && receipt?.data?.schemaVersion === 2) {
    return {
      schemaVersion: 2,
      domainVersion: "2",
      domain: ORACLE_SAFETY_DOMAIN_V2,
      types: ORACLE_SAFETY_TYPES_V2,
      fieldCount: 26,
    };
  }
  if (receipt?.schemaVersion === 3 && receipt?.data?.schemaVersion === 3) {
    return {
      schemaVersion: 3,
      domainVersion: "3",
      domain: ORACLE_SAFETY_DOMAIN_V3,
      types: ORACLE_SAFETY_TYPES_V3,
      fieldCount: 27,
    };
  }
  return null;
}

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

function rotationPolicyView(policy, schemaVersion) {
  if (schemaVersion === 3) {
    return Object.freeze({
      schema: "frontier-compute.insight-rotation-policy.v3",
      coreVersion: ROTATION_CORE_POLICY_VERSION_V3,
      supportedReceiptSchemas: Object.freeze([2, 3]),
      expectedRequiredSourceGroupCountV3: EXPECTED_REQUIRED_SOURCE_GROUP_COUNT_V3,
      expectedIssuer: policy.expectedIssuer,
      expectedVerifyUrl: policy.expectedVerifyUrl,
      signingKeyAuthority: "LOCALLY_COMPILED_CANDIDATE_TUPLES",
      registryRole: "REQUIRED_STATUS_TELEMETRY_NOT_KEY_ADMISSION_AUTHORITY",
      allowedVerdicts: policy.allowedVerdicts,
      expectedTtlSeconds: policy.expectedTtlSeconds,
      maxReceiptAgeSeconds: policy.maxReceiptAgeSeconds,
      maxOracleDataAgeSeconds: policy.maxOracleDataAgeSeconds,
      minParticipants: policy.minParticipants,
      minSourceGroups: policy.minSourceGroups,
      maxDeviationBps: policy.maxDeviationBps,
      maxManipulationRiskBps: policy.maxManipulationRiskBps,
      minCrossProviderAgreementBps: policy.minCrossProviderAgreementBps,
      maxStablecoinDepegBps: policy.maxStablecoinDepegBps,
      clockSkewSeconds: policy.clockSkewSeconds,
    });
  }
  return Object.freeze({
    schema: "frontier-compute.insight-rotation-policy.v2",
    coreVersion: ROTATION_CORE_POLICY_VERSION,
    expectedIssuer: policy.expectedIssuer,
    expectedVerifyUrl: policy.expectedVerifyUrl,
    signingKeyAuthority: "LOCALLY_COMPILED_CANDIDATE_TUPLES",
    registryRole: "REQUIRED_STATUS_TELEMETRY_NOT_KEY_ADMISSION_AUTHORITY",
    allowedVerdicts: policy.allowedVerdicts,
    expectedTtlSeconds: policy.expectedTtlSeconds,
    maxReceiptAgeSeconds: policy.maxReceiptAgeSeconds,
    maxOracleDataAgeSeconds: policy.maxOracleDataAgeSeconds,
    minParticipants: policy.minParticipants,
    minSourceGroups: policy.minSourceGroups,
    maxDeviationBps: policy.maxDeviationBps,
    maxManipulationRiskBps: policy.maxManipulationRiskBps,
    minCrossProviderAgreementBps: policy.minCrossProviderAgreementBps,
    maxStablecoinDepegBps: policy.maxStablecoinDepegBps,
    clockSkewSeconds: policy.clockSkewSeconds,
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

function verifyOracleSafetyCheckWithSigningKeys(
  { receipt, registry, actionInstance, unitContract, nowSeconds, policy = {} },
  { signingKeys, rotationMode },
) {
  const failures = [];
  const fail = (code, detail) => failures.push({ code, detail });
  let effectivePolicy;
  try {
    effectivePolicy = normalizePolicy(policy);
  } catch (error) {
    fail("verification_input_invalid", error.message);
    return { ok: false, failures, policy: null };
  }
  const receiptContract = oracleSafetyContract(receipt);
  const reportedPolicy = rotationMode
    ? rotationPolicyView(effectivePolicy, receiptContract?.schemaVersion)
    : effectivePolicy;
  if (!receipt || typeof receipt !== "object") fail("receipt_missing", "receipt must be an object");
  if (!registry || typeof registry !== "object") fail("registry_missing", "registry must be an object");
  if (!unitContract || typeof unitContract !== "object") fail("unit_contract_missing", "unit contract must be an object");
  if (failures.length) return { ok: false, failures, policy: reportedPolicy };
  try {
    if (!Number.isSafeInteger(nowSeconds)) throw new TypeError("explicit nowSeconds must be a safe integer");
    boundedJson(receipt, "receipt", MAX_RECEIPT_BYTES);
    boundedJson(registry, "registry", MAX_REGISTRY_BYTES);
    boundedJson(actionInstance, "actionInstance", MAX_CONTEXT_BYTES);
    boundedJson(unitContract, "unitContract", MAX_CONTEXT_BYTES);
    boundedJson(policy, "policy", MAX_CONTEXT_BYTES);
  } catch (error) {
    fail("verification_input_invalid", error.message);
    return { ok: false, failures, policy: reportedPolicy };
  }
  if (!hasExactKeys(receipt, ["uid", "schemaVersion", "attester", "attesterLabel", "signedAt", "validForSeconds", "validUntil", "signature", "verifyUrl", "data", "eip712"])) {
    fail("receipt_wrapper_fields_mismatch", "receipt wrapper fields differ from the pinned OracleSafetyCheck envelope");
  }
  if (!receiptContract) {
    fail("schema_version_mismatch", "wrapper and signed data must agree on supported schema v2 or v3");
  } else if (!hasExactKeys(receipt.data, receiptContract.types.OracleSafetyCheck.map((field) => field.name))) {
    fail("receipt_data_fields_mismatch", `signed receipt data fields differ from the pinned ${receiptContract.fieldCount}-field v${receiptContract.schemaVersion} type`);
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
  const attester = safeAddress(receipt.attester);
  if (!attester) fail("attester_invalid", "receipt attester is not an EVM address");
  const trustedKey = attester
    ? signingKeys.find((candidate) => candidate.signer === attester) ?? null
    : null;
  if (attester && !trustedKey) fail("attester_not_pinned", "receipt attester is not present in the locally configured signing-key set");
  const publicKeys = Array.isArray(registry.public_keys) ? registry.public_keys : [];
  const duplicateKeyIds = new Set();
  const duplicateSigners = new Set();
  const seenKeyIds = new Set();
  const seenSigners = new Set();
  for (const candidate of publicKeys) {
    if (typeof candidate?.key_id === "string") {
      if (seenKeyIds.has(candidate.key_id)) duplicateKeyIds.add(candidate.key_id);
      seenKeyIds.add(candidate.key_id);
    }
    const signer = safeAddress(candidate?.public_key ?? candidate?.address);
    if (signer) {
      if (seenSigners.has(signer)) duplicateSigners.add(signer);
      seenSigners.add(signer);
    }
  }
  if (rotationMode && duplicateKeyIds.size > 0) fail("registry_key_ambiguous", `duplicate key ${[...duplicateKeyIds][0]}`);
  else if (trustedKey && duplicateKeyIds.has(trustedKey.keyId)) fail("registry_key_ambiguous", `duplicate key ${trustedKey.keyId}`);
  if (rotationMode && duplicateSigners.size > 0) fail("registry_signer_ambiguous", `duplicate signer ${[...duplicateSigners][0]}`);
  else if (trustedKey && duplicateSigners.has(trustedKey.signer)) fail("registry_signer_ambiguous", `duplicate signer ${trustedKey.signer}`);
  const matchingKeys = trustedKey
    ? publicKeys.filter((candidate) => candidate?.key_id === trustedKey.keyId)
    : [];
  if (trustedKey && matchingKeys.length === 0) fail("registry_key_missing", `missing key ${trustedKey.keyId}`);
  const key = matchingKeys.length === 1 ? matchingKeys[0] : null;
  if (key && key.algorithm !== trustedKey?.algorithm) fail("registry_algorithm_mismatch", `unexpected algorithm ${key.algorithm}`);
  const publicKeyAddress = key && Object.hasOwn(key, "public_key") ? safeAddress(key.public_key) : null;
  const legacyAddress = key && Object.hasOwn(key, "address") ? safeAddress(key.address) : null;
  if (key && Object.hasOwn(key, "public_key") && !publicKeyAddress) fail("registry_address_invalid", "registry public_key is not an EVM address");
  if (key && Object.hasOwn(key, "address") && !legacyAddress) fail("registry_address_invalid", "registry address is not an EVM address");
  if (publicKeyAddress && legacyAddress && publicKeyAddress !== legacyAddress) {
    fail("registry_address_conflict", "registry public_key and address identify different signers");
  }
  const registryAddress = publicKeyAddress ?? legacyAddress;
  if (key && !registryAddress) fail("registry_address_invalid", "registry key has no EVM address");
  if (registryAddress && registryAddress !== trustedKey?.signer) fail("registry_signer_not_pinned", "registry signer differs from the locally configured signing-key tuple");

  if (receiptContract && !sameCanonical(receipt.eip712?.domain, receiptContract.domain)) fail("typed_domain_mismatch", `v${receiptContract.schemaVersion} domain differs from the pinned contract`);
  if (receipt.eip712?.primaryType !== "OracleSafetyCheck") fail("primary_type_mismatch", "primary type must be OracleSafetyCheck");
  if (receiptContract && !sameCanonical(receipt.eip712?.types, receiptContract.types)) fail("typed_fields_mismatch", `ordered ${receiptContract.fieldCount}-field v${receiptContract.schemaVersion} type differs`);
  if (!sameCanonical(receipt.eip712?.canonicalRequestDomain, CANONICAL_REQUEST_DOMAIN_V1)) fail("request_domain_mismatch", "canonical request domain differs");
  if (receipt.eip712?.canonicalRequestPrimaryType !== "CanonicalPreTradeRequest") fail("request_primary_type_mismatch", "canonical request primary type differs");
  if (!sameCanonical(receipt.eip712?.canonicalRequestTypes, CANONICAL_REQUEST_TYPES_V1)) fail("request_fields_mismatch", "canonical request type differs");
  if (!SIGNATURE_65.test(receipt.signature ?? "")) fail("signature_format_invalid", "expected a 65-byte signature");

  if (attester && registryAddress && attester !== registryAddress) fail("attester_registry_mismatch", "receipt attester does not match the registry key");

  let nativeDigest = null;
  let recoveredSigner = null;
  if (receiptContract && receipt.data && sameCanonical(receipt.eip712?.types, receiptContract.types)) {
    try {
      nativeDigest = TypedDataEncoder.hash(receiptContract.domain, receiptContract.types, receipt.data);
      if (normalizeHex32(receipt.uid) !== nativeDigest.toLowerCase()) fail("uid_mismatch", "typed-data digest does not equal receipt uid");
    } catch (error) {
      fail("typed_data_hash_failed", error.message);
    }
    if (nativeDigest && SIGNATURE_65.test(receipt.signature ?? "")) {
      try {
        recoveredSigner = recoverAddress(nativeDigest, receipt.signature);
        if (attester && recoveredSigner !== attester) fail("signature_signer_mismatch", "recovered signer does not equal receipt attester");
        if (registryAddress && recoveredSigner !== registryAddress) fail("signature_registry_mismatch", "recovered signer does not equal the registry key");
        if (!signingKeys.some((candidate) => candidate.signer === recoveredSigner)) {
          fail("signature_not_from_pinned_signer", "recovered signer is not present in the locally configured signing-key set");
        }
        if (trustedKey && recoveredSigner !== trustedKey.signer) fail("signature_trust_tuple_mismatch", "recovered signer differs from the selected immutable tuple");
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
    if (rotationMode && trustedKey) {
      const keyValidFrom = Date.parse(trustedKey.validFrom) / 1000;
      const keyValidUntil = trustedKey.validUntil === null ? null : Date.parse(trustedKey.validUntil) / 1000;
      if (!Number.isFinite(keyValidFrom) || (keyValidUntil !== null && !Number.isFinite(keyValidUntil))) {
        fail("trust_bundle_lifecycle_invalid", "locally configured key lifecycle timestamps are invalid");
      } else {
        if (checkedAt < keyValidFrom) fail("key_not_yet_valid", "receipt checkedAt precedes the locally configured key activation time");
        if (keyValidUntil !== null && checkedAt >= keyValidUntil) fail("key_expired", "receipt checkedAt is outside the locally configured half-open key lifetime");
      }
      if (key && Object.hasOwn(key, "validFrom") && key.validFrom !== trustedKey.validFrom) {
        fail("registry_key_lifecycle_mismatch", "registry validFrom differs from the locally configured key tuple");
      }
      if (key && Object.hasOwn(key, "validUntil") && (key.validUntil ?? null) !== trustedKey.validUntil) {
        fail("registry_key_lifecycle_mismatch", "registry validUntil differs from the locally configured key tuple");
      }
      const revokedKeys = Array.isArray(registry.revoked_keys) ? registry.revoked_keys : [];
      if (Object.hasOwn(registry, "revoked_keys") && (
        !Array.isArray(registry.revoked_keys) ||
        revokedKeys.some((entry) => typeof entry !== "string" || entry.length === 0) ||
        new Set(revokedKeys).size !== revokedKeys.length
      )) {
        fail("registry_revoked_keys_invalid", "registry revoked_keys must be a unique array of non-empty key IDs");
      }
      if (key && Object.hasOwn(key, "revoked") && typeof key.revoked !== "boolean") {
        fail("registry_key_status_invalid", "registry key revoked must be exactly boolean");
      }
      if (key?.revoked === true || revokedKeys.includes(trustedKey.keyId)) {
        fail("registry_key_revoked", "the registry reports the selected locally configured key as revoked");
      }
    }
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
    let requiredSourceGroups = effectivePolicy.minSourceGroups;
    if (receiptContract?.schemaVersion === 3) {
      const signedRequiredSourceGroups = safeUintNumber(receipt.data?.requiredSourceGroupCount, "requiredSourceGroupCount", 1000);
      if (signedRequiredSourceGroups !== EXPECTED_REQUIRED_SOURCE_GROUP_COUNT_V3) {
        fail("required_source_group_count_mismatch", `signed requiredSourceGroupCount must equal ${EXPECTED_REQUIRED_SOURCE_GROUP_COUNT_V3}`);
      }
      requiredSourceGroups = Math.max(requiredSourceGroups, signedRequiredSourceGroups);
    }
    if (groups < requiredSourceGroups) fail("source_groups_insufficient", "source-group independence is below the signed and local policy thresholds");
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

  const registrySchema = receiptContract?.schemaVersion === 2 && registry.schemas?.OracleSafetyCheck?.schemaVersion !== 2
    ? registry.schemas?.OracleSafetyCheckV2
    : registry.schemas?.OracleSafetyCheck;
  if (receiptContract && registrySchema?.schemaVersion !== receiptContract.schemaVersion) {
    fail(`registry_schema_v${receiptContract.schemaVersion}_missing`, `registry does not publish OracleSafetyCheck v${receiptContract.schemaVersion}`);
  }
  if (receiptContract && !sameCanonical(registrySchema?.eip712?.domain, receiptContract.domain)) fail("registry_domain_mismatch", `registry v${receiptContract.schemaVersion} domain differs`);
  if (receiptContract && !sameCanonical(registrySchema?.eip712?.types, receiptContract.types)) fail("registry_types_mismatch", `registry v${receiptContract.schemaVersion} type differs`);
  if (registrySchema?.eip712?.primaryType !== "OracleSafetyCheck") fail("registry_primary_type_mismatch", "registry primary type differs");
  const registryRequestSchema = registry.schemas?.CanonicalPreTradeRequest;
  if (!sameCanonical(registryRequestSchema?.eip712?.domain, CANONICAL_REQUEST_DOMAIN_V1)) fail("registry_request_domain_mismatch", "registry canonical request domain differs");
  if (!sameCanonical(registryRequestSchema?.eip712?.types, CANONICAL_REQUEST_TYPES_V1)) fail("registry_request_types_mismatch", "registry canonical request type differs");
  if (registryRequestSchema?.eip712?.primaryType !== "CanonicalPreTradeRequest") fail("registry_request_primary_type_mismatch", "registry canonical request primary type differs");

  const priceDecimals = unitContract.fields.consensusPrice.scale_decimals;
  const usdDecimals = unitContract.fields.tradeAmountUsd.scale_decimals;
  const safeDisplay = (value, decimals) => {
    try {
      return atomsToDecimal(value, decimals);
    } catch {
      return null;
    }
  };
  const result = {
    ok: failures.length === 0,
    failures,
    policy: reportedPolicy,
    unit_contract_hash: unitValidation.hash,
    native: {
      uid: nativeDigest,
      schemaVersion: receiptContract?.schemaVersion ?? null,
      domainVersion: receiptContract?.domainVersion ?? null,
      primaryType: receiptContract ? "OracleSafetyCheck" : null,
      recoveredSigner,
      canonicalRequestHash,
      checkedAt,
      validUntil,
      intendedActionHash: action?.intendedActionHash ?? null,
      actionInstanceCommitment: action?.actionInstanceCommitment ?? null,
      intendedAction: action?.nativeAction ?? null,
      display: {
        tradeAmountUsd: safeDisplay(receipt.data?.tradeAmountUsd ?? 0, usdDecimals),
        consensusPrice: safeDisplay(receipt.data?.consensusPrice ?? 0, priceDecimals),
        recommendedMaxPositionUsd: safeDisplay(receipt.data?.recommendedMaxPositionUsd ?? 0, usdDecimals),
      },
      historicalClaimOnlyAfter: validUntil,
    },
  };
  if (!rotationMode) return result;
  return {
    ...result,
    verification_scope: "OFF_CHAIN_RECEIPT_OBSERVATION",
    current_action_eligible: false,
    action_authorization_blocker: "the receipt schema does not sign production purpose, environment, receiver challenge, or unique action nonce",
    native: {
      ...result.native,
      selectedKey: trustedKey ? {
        keyId: trustedKey.keyId,
        signer: trustedKey.signer,
        algorithm: trustedKey.algorithm,
        validFrom: trustedKey.validFrom,
        validUntil: trustedKey.validUntil,
        admission: trustedKey.admission,
      } : null,
    },
  };
}

export function verifyOracleSafetyCheckV2(args) {
  const verification = verifyOracleSafetyCheckWithSigningKeys(args, { signingKeys: LEGACY_SIGNING_KEYS, rotationMode: false });
  if (args?.receipt?.schemaVersion !== 2 || args?.receipt?.data?.schemaVersion !== 2) {
    return {
      ...verification,
      ok: false,
      failures: [{ code: "schema_version_mismatch", detail: "the V2 compatibility API accepts schema v2 only" }, ...verification.failures],
    };
  }
  return verification;
}

export function verifyOracleSafetyCheckRotationV2(args) {
  const verification = verifyOracleSafetyCheckWithSigningKeys(args, { signingKeys: ROTATION_CANDIDATE_SIGNING_KEYS, rotationMode: true });
  if (args?.receipt?.schemaVersion !== 2 || args?.receipt?.data?.schemaVersion !== 2) {
    return {
      ...verification,
      ok: false,
      failures: [{ code: "schema_version_mismatch", detail: "the V2 compatibility API accepts schema v2 only" }, ...verification.failures],
    };
  }
  return verification;
}

export function verifyOracleSafetyCheckRotation(args) {
  return verifyOracleSafetyCheckWithSigningKeys(args, { signingKeys: ROTATION_CANDIDATE_SIGNING_KEYS, rotationMode: true });
}

function admittedHistoricalSigningKeys(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new TypeError("admittedKeys must be a bounded non-empty array");
  }
  const snapshot = JSON.parse(canonicalize(value));
  const ids = new Set();
  const signers = new Set();
  return Object.freeze(snapshot.map((entry) => {
    if (!hasExactKeys(entry, ["admissionClass", "algorithm", "keyId", "signer", "validFrom", "validUntil"])) {
      throw new TypeError("admitted key fields differ from the closed historical contract");
    }
    if (entry.admissionClass !== "CURRENT_ADMITTED_KEY" && entry.admissionClass !== "HISTORICAL_ADMITTED_KEY") {
      throw new TypeError("admitted key has no explicit admitted-history class");
    }
    if (typeof entry.keyId !== "string" || entry.keyId.length === 0 || entry.algorithm !== "EIP-712/secp256k1") {
      throw new TypeError("admitted key identity or algorithm is invalid");
    }
    const signer = safeAddress(entry.signer);
    if (!signer || signer !== entry.signer) throw new TypeError("admitted key signer must be checksummed");
    const validFrom = Date.parse(entry.validFrom) / 1000;
    const validUntil = entry.validUntil === null ? null : Date.parse(entry.validUntil) / 1000;
    if (!Number.isSafeInteger(validFrom) || (validUntil !== null && (!Number.isSafeInteger(validUntil) || validUntil <= validFrom))) {
      throw new TypeError("admitted key lifetime is invalid");
    }
    if (ids.has(entry.keyId) || signers.has(signer)) throw new TypeError("admitted key history is ambiguous");
    ids.add(entry.keyId); signers.add(signer);
    return Object.freeze({
      keyId: entry.keyId, signer, algorithm: entry.algorithm, validFrom: entry.validFrom, validUntil: entry.validUntil, admission: entry.admissionClass,
    });
  }));
}

/**
 * Inspection-only verifier. It accepts signer tuples only from a closed
 * caller-supplied admitted trust history, never from policy or the registry.
 */
export function verifyOracleSafetyCheckAdmittedHistorical(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) throw new TypeError("historical arguments must be an object");
  if (!Number.isSafeInteger(args.atSeconds) || args.atSeconds < 0) {
    throw new TypeError("historical inspection requires explicit safe-integer atSeconds");
  }
  const signingKeys = admittedHistoricalSigningKeys(args.admittedKeys);
  const verification = verifyOracleSafetyCheckWithSigningKeys({
    receipt: args.receipt, registry: args.registry, actionInstance: args.actionInstance, unitContract: args.unitContract,
    nowSeconds: args.atSeconds, policy: args.policy ?? {},
  }, { signingKeys, rotationMode: true });
  return Object.freeze({
    ...verification,
    decision: verification.ok ? "ACCEPTED_HISTORICAL_ONLY" : "REJECTED_HISTORICAL_ONLY",
    admission_class: verification.ok ? "HISTORICAL_ADMITTED_KEY" : null,
    evaluated_at_seconds: args.atSeconds,
    current_action_eligible: false,
    action_authorized: false,
  });
}

export function verifyOracleSafetyCheckAdmittedHistoricalV2(args) {
  const verification = verifyOracleSafetyCheckAdmittedHistorical(args);
  if (args?.receipt?.schemaVersion !== 2 || args?.receipt?.data?.schemaVersion !== 2) {
    return Object.freeze({
      ...verification,
      ok: false,
      failures: [{ code: "schema_version_mismatch", detail: "the V2 compatibility API accepts schema v2 only" }, ...verification.failures],
      decision: "REJECTED_HISTORICAL_ONLY",
      admission_class: null,
    });
  }
  return verification;
}

function sampleDiagnosticResult({
  code,
  detail,
  atSeconds,
  verification = null,
}) {
  const diagnosticValid = verification?.ok === true;
  return Object.freeze({
    schema: "frontier-compute.insight-sample-diagnostic-result.v1",
    decision: "UNKNOWN_BLOCKED",
    code,
    diagnostic_valid: diagnosticValid,
    signature_state: diagnosticValid ? "VERIFIED" : "NOT_VERIFIED",
    cryptographic_signature_state: diagnosticValid
      ? "CRYPTOGRAPHIC_SIGNATURE_VALID"
      : "INVALID_OR_NOT_VERIFIED",
    observation_state: "NOT_ACCEPTED",
    replay_state: "NOT_COMMITTED",
    current_action_eligible: false,
    action_state: "ACTION_AUTHORIZATION_BLOCKED",
    action_authorized: false,
    binding: null,
    zap1_external_action_args: null,
    zap1_agent_action_args: null,
    evaluated_at_seconds: atSeconds,
    detail,
    verification,
  });
}

/**
 * Verifies a registry-declared sample signer only as synthetic diagnostic
 * material. Registry membership is deliberately not promoted into admitted
 * trust, and this API can never emit an observation or action binding.
 */
export function verifyOracleSafetyCheckSampleDiagnostic(args) {
  const atSeconds = args?.atSeconds;
  if (!Number.isSafeInteger(atSeconds) || atSeconds < 0) {
    return sampleDiagnosticResult({
      code: "SAMPLE_DIAGNOSTIC_INPUT_INVALID",
      detail: "sample diagnostics require an explicit safe-integer atSeconds",
      atSeconds: null,
    });
  }
  const receipt = args?.receipt;
  const registry = args?.registry;
  const attester = safeAddress(receipt?.attester);
  if (!attester || registry === null || typeof registry !== "object" || Array.isArray(registry)) {
    return sampleDiagnosticResult({
      code: "SAMPLE_SIGNER_ROLE_UNRESOLVED",
      detail: "the sample attester or registry is malformed",
      atSeconds,
    });
  }
  const publicKeys = Array.isArray(registry.public_keys) ? registry.public_keys : [];
  const revokedKeys = Array.isArray(registry.revoked_keys) ? registry.revoked_keys : null;
  if (
    revokedKeys === null ||
    revokedKeys.some((value) => typeof value !== "string" || value.length === 0) ||
    new Set(revokedKeys).size !== revokedKeys.length
  ) {
    return sampleDiagnosticResult({
      code: "SAMPLE_SIGNER_ROLE_UNRESOLVED",
      detail: "the registry revocation set is malformed",
      atSeconds,
    });
  }
  const matches = publicKeys.filter((entry) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return false;
    const publicKey = safeAddress(entry.public_key);
    const legacyAddress = safeAddress(entry.address);
    if (publicKey && legacyAddress && publicKey !== legacyAddress) return false;
    return (publicKey ?? legacyAddress) === attester;
  });
  if (matches.length !== 1) {
    return sampleDiagnosticResult({
      code: "SAMPLE_SIGNER_ROLE_UNRESOLVED",
      detail: "the sample attester does not resolve to exactly one registry key",
      atSeconds,
    });
  }
  const key = matches[0];
  if (
    key.role !== "sample" ||
    key.algorithm !== "EIP-712/secp256k1" ||
    typeof key.key_id !== "string" ||
    key.key_id.length === 0 ||
    key.revoked !== false ||
    revokedKeys.includes(key.key_id) ||
    typeof key.validFrom !== "string" ||
    (key.validUntil !== null && typeof key.validUntil !== "string")
  ) {
    return sampleDiagnosticResult({
      code: "SAMPLE_SIGNER_ROLE_UNRESOLVED",
      detail: "the matching key is not one active, well-formed sample-role key",
      atSeconds,
    });
  }
  const verification = verifyOracleSafetyCheckWithSigningKeys({
    receipt,
    registry,
    actionInstance: args.actionInstance,
    unitContract: args.unitContract,
    nowSeconds: atSeconds,
    policy: args.policy ?? {},
  }, {
    signingKeys: Object.freeze([Object.freeze({
      keyId: key.key_id,
      signer: attester,
      algorithm: key.algorithm,
      validFrom: key.validFrom,
      validUntil: key.validUntil,
      admission: "REGISTRY_DECLARED_SAMPLE_DIAGNOSTIC_ONLY",
    })]),
    rotationMode: true,
  });
  return sampleDiagnosticResult({
    code: verification.ok
      ? "SYNTHETIC_SAMPLE_ONLY"
      : "SAMPLE_DIAGNOSTIC_VERIFICATION_FAILED",
    detail: verification.ok
      ? "The signature and UID are valid under the registry-declared sample key, but the receipt is synthetic and was not accepted as an observation."
      : "The registry-declared sample did not pass the complete local receipt contract.",
    atSeconds,
    verification,
  });
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
