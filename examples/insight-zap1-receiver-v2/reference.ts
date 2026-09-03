import {
  gateRegistryStatusFreshness,
  unavailableCurrentObservation,
  verifyCurrentObservation,
  type ObservationInputs,
  type ObservationResult,
} from "./rotation-adapter.mjs";
import {
  registryFreshnessFromHeaders,
  type RegistryFreshnessEvidence,
} from "./http-freshness.mjs";

const REGISTRY_URL = "https://www.oracleinsight.xyz/.well-known/oracle-keys.json";
const SAMPLE_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample";
const MAX_BYTES = 128 * 1024;
const TIMEOUT_MS = 15_000;

export interface PublicObservationInput {
  actionInstance: unknown;
  unitContract: unknown;
  policy?: Record<string, unknown>;
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

interface PublicSampleResponse {
  data?: { attestation?: unknown };
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

function assertNonAuthorizing(result: ObservationResult): ObservationResult {
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

function classifyPublicSampleOnly(result: ObservationResult): ObservationResult {
  if (result.decision !== "OBSERVATION_ONLY") return result;
  return {
    ...result,
    decision: "UNKNOWN_BLOCKED",
    observation_state: "NOT_ACCEPTED",
    code: "SYNTHETIC_SAMPLE_ONLY",
    retryable: false,
    customer_message: "The public sample is synthetic diagnostic material. Its receipt was not accepted as an observation.",
    operator_action: "Supply exact caller-owned receipt bytes through the production observation API.",
  };
}

/**
 * GET-only customer reference. It verifies a public sample locally for
 * diagnostics, then forces any otherwise-valid sample to UNKNOWN_BLOCKED.
 * It cannot accept an observation, return an executable action, perform a
 * ZAP1 write, or produce a payment/wallet instruction.
 */
export async function verifyPublicCurrentObservation(input: PublicObservationInput): Promise<ObservationResult> {
  try {
    const [registry, sample] = await Promise.all([
      getBoundedJson<unknown>(REGISTRY_URL),
      getBoundedJson<PublicSampleResponse>(SAMPLE_URL),
    ]);
    const receipt = sample.value.data?.attestation;
    if (!receipt || typeof receipt !== "object") throw new Error("sample response is missing data.attestation");
    const receiverInput: ObservationInputs = {
      receipt,
      receiptRaw: sample.raw,
      registry: registry.value,
      registryRaw: registry.raw,
      actionInstance: input.actionInstance,
      unitContract: input.unitContract,
      ...(input.policy ? { policy: input.policy } : {}),
    };
    const result = gateRegistryStatusFreshness(verifyCurrentObservation(receiverInput), registry.freshness);
    return assertNonAuthorizing(classifyPublicSampleOnly(result));
  } catch (error) {
    const detail = error instanceof Error ? error.message : "read-only dependency failure";
    return assertNonAuthorizing(unavailableCurrentObservation(detail));
  }
}
