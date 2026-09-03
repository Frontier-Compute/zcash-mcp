import {
  gateRegistryStatusFreshness,
  unavailableCurrentObservation,
  type ObservationResult,
} from "./rotation-adapter.mjs";
import {
  registryFreshnessFromHeaders,
  type RegistryFreshnessEvidence,
} from "./http-freshness.mjs";
import {
  verifyCapturedSampleDiagnostic,
  type CapturedSampleDiagnosticResult,
} from "./sample-diagnostic.mjs";

const REGISTRY_URL = "https://www.oracleinsight.xyz/.well-known/oracle-keys.json";
const SAMPLE_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample";
const MAX_BYTES = 128 * 1024;
const TIMEOUT_MS = 15_000;

export interface PublicObservationInput {
  actionInstance: unknown;
  unitContract: unknown;
  policy?: Record<string, unknown>;
}

export interface PublicSampleObservationResult extends ObservationResult {
  readonly diagnostic_valid: boolean;
  readonly replay_state: "NOT_COMMITTED";
  readonly action_authorized: false;
  readonly registry_transport_sha256: string | null;
  readonly sample_transport_sha256: string | null;
  readonly sample_signer: string | null;
}

export interface CapturedJson<T> {
  readonly raw: Uint8Array;
  readonly value: T;
  readonly latencyMs: number;
  readonly freshness: RegistryFreshnessEvidence;
  readonly cache: {
    readonly age: string | null;
    readonly cacheControl: string | null;
    readonly responseDate: string | null;
    readonly observedAtSeconds: number;
  };
}

async function getBoundedJson<T>(url: string): Promise<CapturedJson<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("request timeout")), TIMEOUT_MS);
  const started = performance.now();
  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { accept: "application/json", "cache-control": "no-cache", pragma: "no-cache" },
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`GET ${url} returned HTTP ${response.status}`);
    const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") throw new Error(`GET ${url} did not return application/json`);
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_BYTES) throw new Error(`GET ${url} declared an oversized body`);
    if (!response.body) throw new Error(`GET ${url} returned no body`);

    const chunks: Uint8Array[] = [];
    const reader = response.body.getReader();
    let length = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BYTES) {
        await reader.cancel("body limit exceeded");
        throw new Error(`GET ${url} exceeded ${MAX_BYTES} bytes`);
      }
      chunks.push(value);
    }
    const raw = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      raw.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    const observedAtSeconds = Math.floor(Date.now() / 1000);
    return {
      raw,
      value: JSON.parse(text) as T,
      latencyMs: performance.now() - started,
      freshness: registryFreshnessFromHeaders(response.headers, observedAtSeconds),
      cache: {
        age: response.headers.get("age"),
        cacheControl: response.headers.get("cache-control"),
        responseDate: response.headers.get("date"),
        observedAtSeconds,
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}

function assertNonAuthorizing<T extends ObservationResult>(result: T): T {
  if (
    result.schema !== "frontier-compute.insight-receiver-result.v2" ||
    result.current_action_eligible !== false ||
    result.action_state !== "ACTION_AUTHORIZATION_BLOCKED" ||
    result.binding !== null ||
    result.zap1_external_action_args !== null ||
    result.zap1_agent_action_args !== null
  ) {
    throw new Error("receiver result violated the non-authorizing v2 contract");
  }
  return result;
}

function sampleDiagnosticObservation(result: CapturedSampleDiagnosticResult): PublicSampleObservationResult {
  const native = result.verification?.native;
  const recoveredSigner = native?.recoveredSigner;
  const selectedSigner = native?.selectedKey?.signer;
  const signerMatches =
    typeof recoveredSigner === "string" &&
    typeof selectedSigner === "string" &&
    recoveredSigner === selectedSigner;
  return {
    schema: "frontier-compute.insight-receiver-result.v2",
    decision: "UNKNOWN_BLOCKED",
    current_action_eligible: false,
    signature_state: result.signature_state,
    cryptographic_signature_state: result.cryptographic_signature_state,
    recovered_signer_matches_selected_key: signerMatches,
    issuer_key_continuity_state: "NOT_APPLICABLE_SAMPLE_ROLE",
    registry_status_state: result.diagnostic_valid
      ? "SAMPLE_ROLE_VERIFIED_DIAGNOSTIC_ONLY"
      : "SAMPLE_ROLE_NOT_ESTABLISHED",
    receipt_policy_state: result.diagnostic_valid ? "PASSED_DIAGNOSTIC_ONLY" : "NOT_ESTABLISHED",
    observation_state: "NOT_ACCEPTED",
    action_state: "ACTION_AUTHORIZATION_BLOCKED",
    code: result.code,
    stage: "sample_diagnostic",
    retryable: false,
    customer_message: result.detail,
    operator_action: result.code === "SYNTHETIC_SAMPLE_ONLY"
      ? "Supply exact caller-owned receipt bytes through the production observation API."
      : "Inspect the named sample-diagnostic failure; do not treat the public sample as an observation.",
    trust: null,
    time: {
      evaluated_at: result.evaluated_at_seconds,
      checked_at: native?.checkedAt ?? null,
      receipt_valid_until: native?.validUntil ?? null,
      key_valid_from: native?.selectedKey?.validFrom ?? null,
      key_valid_until: native?.selectedKey?.validUntil ?? null,
    },
    receipt: result.sample_transport_sha256 ? {
      ...(result.receipt_uid ? { uid: result.receipt_uid } : {}),
      transport_sha256: result.sample_transport_sha256,
      transport_source: "PUBLIC_SAMPLE_RESPONSE",
    } : null,
    evidence: null,
    verification: result.verification,
    binding: null,
    zap1_external_action_args: null,
    zap1_agent_action_args: null,
    non_authorizations: [
      "NO_OBSERVATION_ACCEPTANCE",
      "NO_REPLAY_COMMIT",
      "NO_TRADE_OR_EXECUTION_AUTHORITY",
      "NO_ZAP1_ATTESTATION_OR_WRITE",
      "NO_PAYMENT_OR_WALLET_ACTION",
    ],
    diagnostic_valid: result.diagnostic_valid,
    replay_state: "NOT_COMMITTED",
    action_authorized: false,
    registry_transport_sha256: result.registry_transport_sha256,
    sample_transport_sha256: result.sample_transport_sha256,
    sample_signer: result.sample_signer,
  };
}

function unavailablePublicSample(detail: string): PublicSampleObservationResult {
  return {
    ...unavailableCurrentObservation(detail),
    diagnostic_valid: false,
    replay_state: "NOT_COMMITTED",
    action_authorized: false,
    registry_transport_sha256: null,
    sample_transport_sha256: null,
    sample_signer: null,
  };
}

/**
 * GET-only customer reference. It verifies a public sample locally for
 * diagnostics, then forces any otherwise-valid sample to UNKNOWN_BLOCKED.
 * It cannot accept an observation, return an executable action, perform a
 * ZAP1 write, or produce a payment/wallet instruction.
 */
export async function verifyPublicCurrentObservation(input: PublicObservationInput): Promise<PublicSampleObservationResult> {
  try {
    const [registry, sample] = await Promise.all([
      getBoundedJson<unknown>(REGISTRY_URL),
      getBoundedJson<unknown>(SAMPLE_URL),
    ]);
    const result = sampleDiagnosticObservation(verifyCapturedSampleDiagnostic({
      registryRaw: registry.raw,
      sampleRaw: sample.raw,
      actionInstance: input.actionInstance,
      unitContract: input.unitContract,
      atSeconds: registry.cache.observedAtSeconds,
      ...(input.policy ? { policy: input.policy } : {}),
    }));
    return assertNonAuthorizing(gateRegistryStatusFreshness(result, registry.freshness));
  } catch (error) {
    const detail = error instanceof Error ? error.message : "read-only dependency failure";
    return assertNonAuthorizing(unavailablePublicSample(detail));
  }
}
