import { createHash } from "node:crypto";

import {
  ROTATION_CANDIDATE_SIGNING_KEYS,
  canonicalize,
  sha256Hex,
  verifyOracleSafetyCheckRotation,
} from "../insight-zap1-receiver-v1/adapter.mjs";

const MAX_RECEIPT_TRANSPORT_BYTES = 128 * 1024;
const MAX_REGISTRY_TRANSPORT_BYTES = 128 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 100_000;
const HEX_64_LOWER = /^[0-9a-f]{64}$/;
export const MAX_REGISTRY_STATUS_AGE_SECONDS = 300;
export const MAX_HTTP_DATE_SKEW_SECONDS = 300;

export const ROTATION_OBSERVER_VERSION = "insight-zap1-rotation-observer-v2";
export const ROTATION_OBSERVER_VERSION_V3 = "insight-zap1-rotation-observer-v3";

export const TRUST_BUNDLE_V2 = Object.freeze({
  schema: "frontier-compute.insight-trust-bundle.v2",
  epoch: 2,
  predecessor: Object.freeze({
    policy_version: "insight-zap1-receiver-policy-v1",
    registry_sha256: "9e7bc705e32280d4997c3ed3d27b5c8794c80198d2eaeaa3310893e939a7deae",
    key_id: "insight-oracle-safety-v2",
  }),
  issuer: "https://www.oracleinsight.xyz",
  keys: ROTATION_CANDIDATE_SIGNING_KEYS,
  admission: Object.freeze({
    old_key: "FROZEN_2026_08_21_REGISTRY_AND_NATIVE_SIGNATURE",
    new_key: "UNRESOLVED_NO_INDEPENDENT_SUCCESSION_PROOF",
    registry_role: "REQUIRED_STATUS_TELEMETRY_NOT_KEY_ADMISSION_AUTHORITY",
    production_action_authorized: false,
  }),
});

export const TRUST_BUNDLE_V2_SHA256 = sha256Hex(TRUST_BUNDLE_V2);

function rawBytes(value, field, maximum) {
  if (!(value instanceof Uint8Array)) throw new TypeError(`${field} must be a Uint8Array`);
  if (value.byteLength === 0) throw new TypeError(`${field} must not be empty`);
  if (value.byteLength > maximum) throw new TypeError(`${field} exceeds ${maximum} bytes`);
  return Buffer.from(value);
}

function rawSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function signatureSha256(signature) {
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
  return rawSha256(Buffer.from(signature.slice(2), "hex"));
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function immutableCanonicalSnapshot(value, field) {
  try {
    return JSON.parse(canonicalize(value));
  } catch (error) {
    throw new TypeError(`${field} cannot be captured as deterministic JSON: ${error.message}`);
  }
}

function validateJsonStructure(text) {
  const backslash = String.fromCharCode(92);
  const simpleEscapes = new Set(["\"", "/", "b", "f", "n", "r", "t"]);
  const isWhitespace = (character) => character !== undefined && [0x20, 0x09, 0x0a, 0x0d].includes(character.charCodeAt(0));
  let index = 0;
  let nodes = 0;
  const skipWhitespace = () => {
    while (index < text.length && isWhitespace(text[index])) index += 1;
  };
  const parseString = () => {
    if (text[index] !== "\"") throw new SyntaxError("expected JSON string");
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === "\"") {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      if (character === backslash) {
        index += 1;
        const escaped = text[index];
        if (escaped === "u") {
          const digits = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) throw new SyntaxError("invalid JSON unicode escape");
          index += 5;
          continue;
        }
        if (!simpleEscapes.has(escaped)) throw new SyntaxError("invalid JSON escape");
        index += 1;
        continue;
      }
      if (character.charCodeAt(0) < 0x20) throw new SyntaxError("unescaped JSON control character");
      index += 1;
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const parseValue = (depth) => {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) throw new SyntaxError(`JSON exceeds ${MAX_JSON_NODES} nodes`);
    if (depth > MAX_JSON_DEPTH) throw new SyntaxError(`JSON exceeds depth ${MAX_JSON_DEPTH}`);
    skipWhitespace();
    const character = text[index];
    if (character === "{") {
      index += 1;
      skipWhitespace();
      const keys = new Set();
      if (text[index] === "}") {
        index += 1;
        return;
      }
      for (;;) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) throw new SyntaxError(`duplicate JSON object key ${key}`);
        keys.add(key);
        skipWhitespace();
        if (text[index] !== ":") throw new SyntaxError("expected JSON object colon");
        index += 1;
        parseValue(depth + 1);
        skipWhitespace();
        if (text[index] === "}") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new SyntaxError("expected JSON object comma");
        index += 1;
      }
    }
    if (character === "[") {
      index += 1;
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return;
      }
      for (;;) {
        parseValue(depth + 1);
        skipWhitespace();
        if (text[index] === "]") {
          index += 1;
          return;
        }
        if (text[index] !== ",") throw new SyntaxError("expected JSON array comma");
        index += 1;
      }
    }
    if (character === "\"") {
      parseString();
      return;
    }
    const start = index;
    while (index < text.length && !isWhitespace(text[index]) && ![",", "]", "}"].includes(text[index])) index += 1;
    if (start === index) throw new SyntaxError("expected JSON value");
    const primitive = JSON.parse(text.slice(start, index));
    if (primitive !== null && typeof primitive === "object") throw new SyntaxError("invalid JSON primitive");
  };
  parseValue(0);
  skipWhitespace();
  if (index !== text.length) throw new SyntaxError("trailing bytes after JSON value");
}

function parseJsonBytes(value, field, maximum) {
  const bytes = rawBytes(value, field, maximum);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  validateJsonStructure(text);
  return { bytes, parsed: JSON.parse(text), sha256: rawSha256(bytes) };
}

export function parseStrictJsonBytes(value, field, maximum) {
  if (!Number.isSafeInteger(maximum) || maximum <= 0 || maximum > MAX_REGISTRY_TRANSPORT_BYTES) {
    throw new TypeError("maximum must be a positive safe integer no greater than 131072");
  }
  return parseJsonBytes(value, field, maximum);
}

function captureReceipt(receiptRaw, receipt) {
  const capture = parseJsonBytes(receiptRaw, "receiptRaw", MAX_RECEIPT_TRANSPORT_BYTES);
  if (sameCanonical(capture.parsed, receipt)) {
    return { ...capture, receipt: capture.parsed, source: "JSON_OBJECT_DIRECT" };
  }
  if (sameCanonical(capture.parsed?.data?.attestation, receipt)) {
    return { ...capture, receipt: capture.parsed.data.attestation, source: "JSON_WRAPPER_DATA_ATTESTATION" };
  }
  throw new TypeError("receiptRaw does not contain the receipt object used for verification");
}

function captureRegistry(registryRaw, registry) {
  const capture = parseJsonBytes(registryRaw, "registryRaw", MAX_REGISTRY_TRANSPORT_BYTES);
  if (!sameCanonical(capture.parsed, registry)) {
    throw new TypeError("registryRaw does not parse to the registry object used for verification");
  }
  return capture;
}

function timestampSeconds(value) {
  if (typeof value !== "string") return null;
  const seconds = Date.parse(value) / 1000;
  return Number.isFinite(seconds) ? seconds : null;
}

export function evaluatePinnedKeyLifecycle(key, checkedAt) {
  if (!key || !Number.isSafeInteger(checkedAt)) {
    return { ok: false, code: "KEY_LIFECYCLE_INPUT_INVALID" };
  }
  const validFrom = timestampSeconds(key.validFrom);
  const validUntil = key.validUntil === null ? null : timestampSeconds(key.validUntil);
  if (validFrom === null || (key.validUntil !== null && validUntil === null)) {
    return { ok: false, code: "KEY_LIFECYCLE_INPUT_INVALID" };
  }
  if (checkedAt < validFrom) return { ok: false, code: "KEY_NOT_YET_VALID" };
  if (validUntil !== null && checkedAt >= validUntil) return { ok: false, code: "KEY_EXPIRED" };
  return { ok: true, code: "KEY_ACTIVE", valid_from: validFrom, valid_until: validUntil };
}

function failureStage(code) {
  if (/registry|key_|attester|signature/.test(code)) return "trust_root";
  if (/receipt_|time_|ttl|signed_at/.test(code)) return "freshness";
  if (/action|request|AssetId|subjectChainId|tradeAmountUsd/.test(code)) return "action_binding";
  if (/policy|quorum|coverage|independence|deviation|risk|agreement|depeg|position|price/.test(code)) return "oracle_policy";
  return "input";
}

function resultEnvelope({
  decision,
  code,
  evaluatedAt,
  verification = null,
  trust = null,
  receipt = null,
  evidence = null,
  retryable = false,
  message,
  operatorAction,
  keyContinuityState = "NOT_EVALUATED",
  registryStatusState = "NOT_EVALUATED",
  receiptPolicyState = null,
}) {
  const recoveredSignerMatchesSelectedKey = Boolean(
    verification?.native?.recoveredSigner &&
    verification?.native?.selectedKey?.signer &&
    verification.native.recoveredSigner === verification.native.selectedKey.signer
  );
  const cryptographicSignatureState = recoveredSignerMatchesSelectedKey
    ? "CRYPTOGRAPHIC_SIGNATURE_VALID"
    : "INVALID_OR_NOT_VERIFIED";
  const observationAccepted = decision === "OBSERVATION_ONLY" || decision === "ACCEPTED_HISTORICAL_ONLY";
  return {
    schema: "frontier-compute.insight-receiver-result.v2",
    decision,
    current_action_eligible: false,
    signature_state: cryptographicSignatureState === "CRYPTOGRAPHIC_SIGNATURE_VALID" ? "VERIFIED" : "NOT_VERIFIED",
    cryptographic_signature_state: cryptographicSignatureState,
    recovered_signer_matches_selected_key: recoveredSignerMatchesSelectedKey,
    issuer_key_continuity_state: keyContinuityState,
    registry_status_state: registryStatusState,
    receipt_policy_state: receiptPolicyState ?? (verification?.ok ? "PASSED" : "NOT_ESTABLISHED"),
    observation_state: observationAccepted ? "OBSERVATION_ONLY" : "NOT_ACCEPTED",
    action_state: "ACTION_AUTHORIZATION_BLOCKED",
    code,
    stage: failureStage(code.toLowerCase()),
    retryable,
    customer_message: message,
    operator_action: operatorAction,
    trust,
    time: {
      evaluated_at: Number.isSafeInteger(evaluatedAt) ? evaluatedAt : null,
      checked_at: verification?.native?.checkedAt ?? null,
      receipt_valid_until: verification?.native?.validUntil ?? null,
      key_valid_from: verification?.native?.selectedKey?.validFrom ?? null,
      key_valid_until: verification?.native?.selectedKey?.validUntil ?? null,
    },
    receipt,
    evidence,
    verification,
    binding: null,
    zap1_external_action_args: null,
    zap1_agent_action_args: null,
    non_authorizations: [
      "NO_TRADE_OR_EXECUTION_AUTHORITY",
      "NO_ZAP1_ATTESTATION_OR_WRITE",
      "NO_PROOF_INCLUSION_OR_ZCASH_ANCHOR",
      "NO_REGISTRY_SUCCESSION_OR_ROLLBACK_PROOF",
      "NO_PAYMENT_OR_WALLET_ACTION",
    ],
  };
}

function terminalFailure(code, detail, evaluatedAt, decision = "REJECTED", retryable = false) {
  return resultEnvelope({
    decision,
    code,
    evaluatedAt,
    retryable,
    message: detail,
    operatorAction: retryable ? "Retry the read-only observation after the dependency recovers." : "Inspect the named failure before accepting new evidence.",
    verification: { ok: false, failures: [{ code: code.toLowerCase(), detail }], native: null },
  });
}

function selectedRegistryRecord(registry, selectedKey) {
  if (!selectedKey || !Array.isArray(registry?.public_keys)) return null;
  const matches = registry.public_keys.filter((candidate) => candidate?.key_id === selectedKey.keyId);
  return matches.length === 1 ? matches[0] : null;
}

function requireRotationMetadata(registry, selectedKey) {
  if (typeof registry?.key_rotation_policy !== "string" || registry.key_rotation_policy.length === 0) {
    return "registry key_rotation_policy is missing";
  }
  if (!Array.isArray(registry.revoked_keys)) return "registry revoked_keys must be an array";
  const record = selectedRegistryRecord(registry, selectedKey);
  if (!record) return "selected key has no unique registry record";
  for (const field of ["validFrom", "validUntil", "revoked"]) {
    if (!Object.hasOwn(record, field)) return `selected registry key is missing ${field}`;
  }
  if (typeof record.revoked !== "boolean") return "selected registry key revoked must be exactly boolean";
  return null;
}

function verifyObservation(args, evaluatedAt, mode) {
  let receiptCapture;
  let registryCapture;
  let actionInstanceSnapshot;
  let unitContractSnapshot;
  let policySnapshot;
  try {
    receiptCapture = captureReceipt(args.receiptRaw, args.receipt);
    registryCapture = captureRegistry(args.registryRaw, args.registry);
    actionInstanceSnapshot = immutableCanonicalSnapshot(args.actionInstance, "actionInstance");
    unitContractSnapshot = immutableCanonicalSnapshot(args.unitContract, "unitContract");
    policySnapshot = immutableCanonicalSnapshot(args.policy ?? {}, "policy");
  } catch (error) {
    return terminalFailure("INPUT_CAPTURE_INVALID", error.message, evaluatedAt);
  }

  let verification;
  try {
    verification = verifyOracleSafetyCheckRotation({
      receipt: receiptCapture.receipt,
      registry: registryCapture.parsed,
      actionInstance: actionInstanceSnapshot,
      unitContract: unitContractSnapshot,
      nowSeconds: evaluatedAt,
      policy: policySnapshot,
    });
  } catch (error) {
    return terminalFailure("INTERNAL_VERIFIER_FAILURE", error.message, evaluatedAt, "UNKNOWN_BLOCKED", false);
  }

  if (!verification.ok) {
    const first = verification.failures[0] ?? { code: "verification_failed", detail: "verification failed without a named cause" };
    const dependencyUnknown = [
      "registry_missing",
      "registry_key_missing",
      "registry_key_status_invalid",
      "registry_revoked_keys_invalid",
    ].includes(first.code);
    const selectedKey = verification.native?.selectedKey ?? null;
    const provisional = selectedKey?.admission === "CANDIDATE_NOT_ADMITTED_PUBLIC_REGISTRY_AND_NATIVE_SIGNATURE_ONLY";
    return resultEnvelope({
      decision: dependencyUnknown ? "UNKNOWN_BLOCKED" : "REJECTED",
      code: first.code.toUpperCase(),
      evaluatedAt,
      verification,
      retryable: dependencyUnknown,
      message: first.detail,
      operatorAction: dependencyUnknown ? "Obtain a bounded current registry snapshot and retry." : "Do not use this receipt; inspect the named verifier failure.",
      receipt: { transport_sha256: receiptCapture.sha256, transport_source: receiptCapture.source },
      trust: { bundle_sha256: TRUST_BUNDLE_V2_SHA256, bundle_epoch: TRUST_BUNDLE_V2.epoch, registry_sha256: registryCapture.sha256 },
      keyContinuityState: provisional ? "ISSUER_KEY_CONTINUITY_UNKNOWN_BLOCKED" : "NOT_ESTABLISHED",
      registryStatusState: dependencyUnknown ? "UNKNOWN_BLOCKED" : "NOT_ACCEPTED",
    });
  }

  const metadataFailure = requireRotationMetadata(registryCapture.parsed, verification.native.selectedKey);
  if (metadataFailure) {
    return resultEnvelope({
      decision: "UNKNOWN_BLOCKED",
      code: "REGISTRY_ROTATION_METADATA_INVALID",
      evaluatedAt,
      verification,
      retryable: true,
      message: metadataFailure,
      operatorAction: "Obtain a complete, well-typed bounded registry snapshot and retry.",
      receipt: { transport_sha256: receiptCapture.sha256, transport_source: receiptCapture.source },
      trust: { bundle_sha256: TRUST_BUNDLE_V2_SHA256, bundle_epoch: TRUST_BUNDLE_V2.epoch, registry_sha256: registryCapture.sha256 },
      keyContinuityState: "NOT_ESTABLISHED",
      registryStatusState: "UNKNOWN_BLOCKED",
      receiptPolicyState: "PASSED",
    });
  }

  const selectedKey = verification.native.selectedKey;
  const observerVersion = verification.native.schemaVersion === 3
    ? ROTATION_OBSERVER_VERSION_V3
    : ROTATION_OBSERVER_VERSION;
  const receiptEvidence = {
    transport_sha256: receiptCapture.sha256,
    transport_source: receiptCapture.source,
    uid: receiptCapture.receipt.uid,
    signature_sha256: signatureSha256(receiptCapture.receipt.signature),
  };
  const provisional = selectedKey.admission === "CANDIDATE_NOT_ADMITTED_PUBLIC_REGISTRY_AND_NATIVE_SIGNATURE_ONLY";
  const keyContinuityState = provisional
    ? "ISSUER_KEY_CONTINUITY_UNKNOWN_BLOCKED"
    : "ESTABLISHED_FROZEN_PREDECESSOR";
  const registryStatusState = mode === "CURRENT_OBSERVATION"
    ? "ROLLBACK_PROOF_UNAVAILABLE"
    : "HISTORICAL_SNAPSHOT_ONLY";
  const trust = {
    observer_version: observerVersion,
    core_policy_version: verification.policy.coreVersion,
    bundle_sha256: TRUST_BUNDLE_V2_SHA256,
    bundle_epoch: TRUST_BUNDLE_V2.epoch,
    registry_sha256: registryCapture.sha256,
    key_id: selectedKey.keyId,
    signer: selectedKey.signer,
    key_admission: selectedKey.admission,
    issuer_succession_proof: provisional ? "UNRESOLVED" : "FROZEN_PREDECESSOR",
  };
  const historical = mode === "HISTORICAL_INSPECTION";
  const decision = provisional || !historical ? "UNKNOWN_BLOCKED" : "ACCEPTED_HISTORICAL_ONLY";
  const code = provisional
    ? "ISSUER_KEY_CONTINUITY_UNRESOLVED"
    : historical
      ? "HISTORICAL_SIGNATURE_VERIFIED"
      : "REGISTRY_ROLLBACK_PROOF_UNAVAILABLE";
  const effectivePolicySha256 = sha256Hex(verification.policy);
  const evidence = {
    schema: "frontier-compute.insight-observation-evidence.v2",
    effective_policy_sha256: effectivePolicySha256,
    transport_status: null,
    hash: sha256Hex({
      domain: "frontier-compute-insight-observation-evidence-v2",
      observer_version: observerVersion,
      core_policy_version: verification.policy.coreVersion,
      effective_policy_sha256: effectivePolicySha256,
      mode,
      decision,
      code,
      cryptographic_signature_state: "CRYPTOGRAPHIC_SIGNATURE_VALID",
      issuer_key_continuity_state: keyContinuityState,
      registry_status_state: registryStatusState,
      action_state: "ACTION_AUTHORIZATION_BLOCKED",
      evaluated_at: evaluatedAt,
      trust_bundle_sha256: trust.bundle_sha256,
      trust_bundle_epoch: trust.bundle_epoch,
      registry_sha256: trust.registry_sha256,
      selected_key_id: trust.key_id,
      selected_signer: trust.signer,
      selected_key_lifecycle: {
        valid_from: selectedKey.validFrom,
        valid_until: selectedKey.validUntil,
      },
      receipt_transport_sha256: receiptEvidence.transport_sha256,
      receipt_uid: receiptEvidence.uid,
      receipt_signature_sha256: receiptEvidence.signature_sha256,
      ...(verification.native.schemaVersion === 3 ? {
        receipt_schema_version: verification.native.schemaVersion,
        receipt_domain_version: verification.native.domainVersion,
        receipt_primary_type: verification.native.primaryType,
      } : {}),
      intended_action_hash: verification.native.intendedActionHash,
      action_instance_commitment: verification.native.actionInstanceCommitment,
    }),
  };
  if (!HEX_64_LOWER.test(evidence.hash)) throw new Error("internal observation evidence hash invariant failed");

  return resultEnvelope({
    decision,
    code,
    evaluatedAt,
    verification,
    trust,
    receipt: receiptEvidence,
    evidence,
    retryable: false,
    message: provisional
      ? "The candidate address produced a valid signature, but continuity from the frozen issuer key is not independently authenticated."
      : historical
        ? "The frozen predecessor signature and policy checks pass at the supplied historical time; no current-action binding is emitted."
        : "The signature is valid, but the live registry has no authenticated monotonic sequence or rollback proof.",
    operatorAction: provisional
      ? "Obtain an independently authenticated issuer-succession receipt and explicit operator admission."
      : "Add rollback-resistant registry state before relying on current revocation status.",
    keyContinuityState,
    registryStatusState,
    receiptPolicyState: "PASSED",
  });
}

const BASE_ARGUMENTS = new Set(["receipt", "receiptRaw", "registry", "registryRaw", "actionInstance", "unitContract", "policy"]);

export function verifyCurrentObservation(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return terminalFailure("INPUT_INVALID", "arguments must be a plain object", Math.floor(Date.now() / 1000));
  }
  const unknown = Reflect.ownKeys(args).filter((key) => typeof key !== "string" || !BASE_ARGUMENTS.has(key));
  const evaluatedAt = Math.floor(Date.now() / 1000);
  if (unknown.length > 0) {
    return terminalFailure("CALLER_TIME_OR_FIELD_REJECTED", `unsupported current-mode field ${String(unknown[0])}`, evaluatedAt);
  }
  return verifyObservation(args, evaluatedAt, "CURRENT_OBSERVATION");
}

export function verifyHistoricalObservation(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    return terminalFailure("INPUT_INVALID", "arguments must be a plain object", null);
  }
  const allowed = new Set([...BASE_ARGUMENTS, "atSeconds"]);
  const unknown = Reflect.ownKeys(args).filter((key) => typeof key !== "string" || !allowed.has(key));
  if (unknown.length > 0 || !Number.isSafeInteger(args.atSeconds)) {
    return terminalFailure("HISTORICAL_TIME_INVALID", "historical inspection requires one explicit safe-integer atSeconds", null);
  }
  return verifyObservation(args, args.atSeconds, "HISTORICAL_INSPECTION");
}

export function unavailableCurrentObservation(detail) {
  const message = typeof detail === "string" && detail.length > 0
    ? detail.slice(0, 1000)
    : "required read-only dependency evidence is unavailable";
  return terminalFailure(
    "LIVE_DEPENDENCY_UNAVAILABLE",
    message,
    Math.floor(Date.now() / 1000),
    "UNKNOWN_BLOCKED",
    true,
  );
}

function bindTransportStatus(result, transportStatus) {
  if (!result.evidence?.hash) return { ...result, transport_status: transportStatus };
  const evidence = {
    ...result.evidence,
    transport_status: transportStatus,
    hash: sha256Hex({
      domain: "frontier-compute-insight-observation-transport-ruling-v2",
      observation_evidence_hash: result.evidence.hash,
      transport_status: transportStatus,
    }),
  };
  return { ...result, evidence, transport_status: transportStatus };
}

export function gateRegistryStatusFreshness(
  result,
  { ageSeconds, maxAgeSeconds, observedAtSeconds, responseDateSeconds },
) {
  const validAge = Number.isSafeInteger(ageSeconds) && ageSeconds >= 0;
  const validMaximum = Number.isSafeInteger(maxAgeSeconds) && maxAgeSeconds >= 0;
  const validObservedAt = Number.isSafeInteger(observedAtSeconds) && observedAtSeconds >= 0;
  const validResponseDate = Number.isSafeInteger(responseDateSeconds) && responseDateSeconds >= 0;
  let state = "WITHIN_LOCAL_FRESHNESS_BOUND";
  let blockerCode = null;

  if (!validAge || !validMaximum || !validObservedAt || !validResponseDate) {
    state = "FRESHNESS_EVIDENCE_MISSING_OR_MALFORMED";
    blockerCode = "REGISTRY_STATUS_FRESHNESS_UNKNOWN";
  } else if (maxAgeSeconds > MAX_REGISTRY_STATUS_AGE_SECONDS) {
    state = "SERVER_MAX_AGE_EXCEEDS_LOCAL_LIMIT";
    blockerCode = "REGISTRY_STATUS_CACHE_POLICY_UNACCEPTABLE";
  } else if (Math.abs((observedAtSeconds - responseDateSeconds) - ageSeconds) > MAX_HTTP_DATE_SKEW_SECONDS) {
    state = "HTTP_DATE_AGE_INCONSISTENT";
    blockerCode = "REGISTRY_STATUS_TIME_INCONSISTENT";
  } else if (ageSeconds >= Math.min(maxAgeSeconds, MAX_REGISTRY_STATUS_AGE_SECONDS)) {
    state = "STALE_AT_HALF_OPEN_BOUNDARY";
    blockerCode = "REGISTRY_STATUS_STALE";
  }

  const transportStatus = {
    state,
    age_seconds: validAge ? ageSeconds : null,
    server_max_age_seconds: validMaximum ? maxAgeSeconds : null,
    local_max_age_seconds: MAX_REGISTRY_STATUS_AGE_SECONDS,
    observed_at_seconds: validObservedAt ? observedAtSeconds : null,
    response_date_seconds: validResponseDate ? responseDateSeconds : null,
    blocker_code: blockerCode,
  };
  const withTransport = bindTransportStatus(result, transportStatus);
  if (!blockerCode || result.decision === "REJECTED") return withTransport;
  if (result.decision === "UNKNOWN_BLOCKED") {
    return {
      ...withTransport,
      registry_transport_blocker_code: blockerCode,
      customer_message: `${result.customer_message} Registry transport is also blocked: ${state.toLowerCase().replaceAll("_", " ")}.`,
      operator_action: `${result.operator_action} Also retry a bounded revalidated GET before evaluating current registry status.`,
    };
  }
  return {
    ...withTransport,
    decision: "UNKNOWN_BLOCKED",
    observation_state: "NOT_ACCEPTED",
    code: blockerCode,
    stage: "trust_root",
    retryable: true,
    customer_message: `Current registry status is unavailable: ${state.toLowerCase().replaceAll("_", " ")}.`,
    operator_action: "Retry a bounded revalidated GET; do not use this registry response for a current decision.",
  };
}
