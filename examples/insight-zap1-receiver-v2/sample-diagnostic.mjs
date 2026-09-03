import { createHash } from "node:crypto";

import { verifyOracleSafetyCheckSampleDiagnostic } from "../insight-zap1-receiver-v1/adapter.mjs";
import { parseStrictJsonBytes } from "./rotation-adapter.mjs";

const MAX_BODY_BYTES = 128 * 1024;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function blocked(code, detail, atSeconds = null) {
  return Object.freeze({
    schema: "frontier-compute.insight-captured-sample-diagnostic.v1",
    decision: "UNKNOWN_BLOCKED",
    code,
    diagnostic_valid: false,
    signature_state: "NOT_VERIFIED",
    cryptographic_signature_state: "INVALID_OR_NOT_VERIFIED",
    observation_state: "NOT_ACCEPTED",
    replay_state: "NOT_COMMITTED",
    current_action_eligible: false,
    action_state: "ACTION_AUTHORIZATION_BLOCKED",
    action_authorized: false,
    binding: null,
    zap1_external_action_args: null,
    zap1_agent_action_args: null,
    evaluated_at_seconds: atSeconds,
    registry_transport_sha256: null,
    sample_transport_sha256: null,
    detail,
    verification: null,
  });
}

/**
 * Parses exact captured registry and sample-response bytes, verifies the
 * embedded receipt against the one registry-declared sample key, and always
 * returns a non-authorizing diagnostic ruling.
 */
export function verifyCapturedSampleDiagnostic({
  registryRaw,
  sampleRaw,
  actionInstance,
  unitContract,
  atSeconds,
  policy = {},
}) {
  if (!Number.isSafeInteger(atSeconds) || atSeconds < 0) {
    return blocked(
      "SAMPLE_DIAGNOSTIC_INPUT_INVALID",
      "atSeconds must be an explicit non-negative safe integer",
    );
  }
  let registry;
  let sample;
  try {
    registry = parseStrictJsonBytes(registryRaw, "registryRaw", MAX_BODY_BYTES);
    sample = parseStrictJsonBytes(sampleRaw, "sampleRaw", MAX_BODY_BYTES);
  } catch (error) {
    return blocked(
      "SAMPLE_DIAGNOSTIC_INPUT_INVALID",
      error instanceof Error ? error.message : "captured bytes are invalid",
      atSeconds,
    );
  }
  const wrapper = sample.parsed;
  const receipt = wrapper?.data?.attestation;
  if (
    wrapper?.success !== true ||
    receipt === null ||
    typeof receipt !== "object" ||
    Array.isArray(receipt)
  ) {
    return Object.freeze({
      ...blocked(
        "SAMPLE_DIAGNOSTIC_INPUT_INVALID",
        "sampleRaw must contain success=true and data.attestation",
        atSeconds,
      ),
      registry_transport_sha256: sha256(registry.bytes),
      sample_transport_sha256: sha256(sample.bytes),
    });
  }
  const result = verifyOracleSafetyCheckSampleDiagnostic({
    receipt,
    registry: registry.parsed,
    actionInstance,
    unitContract,
    atSeconds,
    policy,
  });
  return Object.freeze({
    ...result,
    schema: "frontier-compute.insight-captured-sample-diagnostic.v1",
    registry_transport_sha256: sha256(registry.bytes),
    sample_transport_sha256: sha256(sample.bytes),
    receipt_uid: typeof receipt.uid === "string" ? receipt.uid : null,
    sample_signer: typeof receipt.attester === "string" ? receipt.attester : null,
  });
}
