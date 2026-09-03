import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  gateRegistryStatusFreshness,
  unavailableCurrentObservation,
  verifyCurrentObservation,
} from "./rotation-adapter.mjs";
import { registryFreshnessFromHeaders } from "./http-freshness.mjs";

const REGISTRY_URL = "https://www.oracleinsight.xyz/.well-known/oracle-keys.json";
const SAMPLE_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample";
const MAX_REGISTRY_BYTES = 128 * 1024;
const MAX_SAMPLE_BYTES = 128 * 1024;
const TIMEOUT_MS = 15_000;

const here = path.dirname(fileURLToPath(import.meta.url));
const v1 = path.resolve(here, "../insight-zap1-receiver-v1");

async function boundedJsonGet(url, maximumBytes) {
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
    if (contentType !== "application/json") throw new Error(`GET ${url} returned ${contentType ?? "no content type"}`);
    const declaredLength = Number(response.headers.get("content-length"));
    if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
      throw new Error(`GET ${url} declared ${declaredLength} bytes; limit is ${maximumBytes}`);
    }
    if (!response.body) throw new Error(`GET ${url} returned no body`);
    const reader = response.body.getReader();
    const chunks = [];
    let length = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel("body limit exceeded");
        throw new Error(`GET ${url} exceeded ${maximumBytes} bytes`);
      }
      chunks.push(value);
    }
    const raw = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), length);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    const observedAtSeconds = Math.floor(Date.now() / 1000);
    return {
      raw,
      value: JSON.parse(text),
      latency_ms: Number((performance.now() - started).toFixed(3)),
      freshness: registryFreshnessFromHeaders(response.headers, observedAtSeconds),
      cache: {
        age: response.headers.get("age"),
        cache_control: response.headers.get("cache-control"),
        date: response.headers.get("date"),
        vercel_cache: response.headers.get("x-vercel-cache"),
        observed_at_seconds: observedAtSeconds,
      },
    };
  } finally {
    clearTimeout(timeout);
  }
}

function compact(result, transport = {}) {
  return {
    schema: "frontier-compute.insight-live-check.v2",
    checked_at_utc: new Date().toISOString(),
    decision: result.decision,
    code: result.code,
    signature: {
      state: result.signature_state,
      cryptographic_state: result.cryptographic_signature_state,
      recovered_signer_matches_selected_key: result.recovered_signer_matches_selected_key,
      uid: result.receipt?.uid ?? null,
      key_id: result.trust?.key_id ?? null,
      signer: result.trust?.signer ?? null,
      key_admission: result.trust?.key_admission ?? null,
      issuer_succession_proof: result.trust?.issuer_succession_proof ?? null,
    },
    observation: result.observation_state,
    issuer_key_continuity: result.issuer_key_continuity_state,
    registry_status: result.registry_status_state,
    registry_transport_status: result.transport_status ?? null,
    receipt_policy: result.receipt_policy_state,
    action: result.action_state,
    current_action_eligible: result.current_action_eligible,
    evidence: {
      observation_hash: result.evidence?.hash ?? null,
      receipt_transport_sha256: result.receipt?.transport_sha256 ?? null,
      registry_sha256: result.trust?.registry_sha256 ?? null,
      trust_bundle_sha256: result.trust?.bundle_sha256 ?? null,
    },
    transport: {
      method: "GET_ONLY",
      hosted_verify_called: false,
      write_performed: false,
      registry_latency_ms: transport.registry?.latency_ms ?? null,
      sample_latency_ms: transport.sample?.latency_ms ?? null,
      total_latency_ms: transport.total_latency_ms ?? null,
      registry_cache: transport.registry?.cache ?? null,
    },
    customer_message: result.customer_message,
    operator_action: result.operator_action,
    non_authorizations: result.non_authorizations,
  };
}

export async function runLiveCheck({ jsonOnly = false } = {}) {
  const started = performance.now();
  const [registryCapture, sampleCapture, unitContract, actionInstance] = await Promise.all([
    boundedJsonGet(REGISTRY_URL, MAX_REGISTRY_BYTES),
    boundedJsonGet(SAMPLE_URL, MAX_SAMPLE_BYTES),
    readFile(path.join(v1, "UNIT-CONTRACT.json"), "utf8").then(JSON.parse),
    readFile(path.join(v1, "ACTION-INSTANCE.json"), "utf8").then(JSON.parse),
  ]);
  const receipt = sampleCapture.value?.data?.attestation;
  if (!receipt || typeof receipt !== "object") throw new Error("sample response is missing data.attestation");
  const verification = verifyCurrentObservation({
    receipt,
    receiptRaw: sampleCapture.raw,
    registry: registryCapture.value,
    registryRaw: registryCapture.raw,
    actionInstance,
    unitContract,
  });
  const result = gateRegistryStatusFreshness(verification, registryCapture.freshness);
  const output = compact(result, {
    registry: registryCapture,
    sample: sampleCapture,
    total_latency_ms: Number((performance.now() - started).toFixed(3)),
  });
  if (!jsonOnly) {
    console.log(`SIGNATURE: ${output.signature.state} key=${output.signature.key_id ?? "unknown"} signer=${output.signature.signer ?? "unknown"}`);
    console.log(`CONTINUITY: ${output.issuer_key_continuity} issuer_succession_proof=${output.signature.issuer_succession_proof ?? "unknown"}`);
    console.log(`RESULT: ${output.observation} registry_status=${output.registry_status}`);
    console.log(`ACTION: ${output.action} current_action_eligible=${output.current_action_eligible}`);
  }
  console.log(JSON.stringify(output, null, 2));
  if (output.decision === "OBSERVATION_ONLY") return { exitCode: 0, output };
  if (output.decision === "UNKNOWN_BLOCKED") return { exitCode: output.code.includes("DEPENDENCY") ? 4 : 3, output };
  return { exitCode: 2, output };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const { exitCode } = await runLiveCheck({ jsonOnly: process.argv.includes("--json") });
    process.exitCode = exitCode;
  } catch (error) {
    console.error(JSON.stringify(compact(unavailableCurrentObservation(error.message)), null, 2));
    process.exitCode = 4;
  }
}
