import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { verifyCapturedSampleDiagnostic } from "./sample-diagnostic.mjs";

const REGISTRY_URL = "https://www.oracleinsight.xyz/.well-known/oracle-keys.json";
const SAMPLE_URL = "https://www.oracleinsight.xyz/api/v1/safety/attestation/sample";
const MAX_BODY_BYTES = 128 * 1024;
const TIMEOUT_MS = 15_000;
const here = path.dirname(fileURLToPath(import.meta.url));
const v1 = path.resolve(here, "../insight-zap1-receiver-v1");

async function boundedGet(url, signal) {
  const response = await fetch(url, {
    method: "GET",
    headers: {
      accept: "application/json",
      "cache-control": "no-cache",
      pragma: "no-cache",
    },
    cache: "no-store",
    redirect: "error",
    signal,
  });
  if (!response.ok) throw new Error(`GET ${url} returned HTTP ${response.status}`);
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new Error(`GET ${url} did not return application/json`);
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    throw new Error(`GET ${url} declared an oversized body`);
  }
  if (!response.body) throw new Error(`GET ${url} returned no body`);
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_BODY_BYTES) {
      await reader.cancel("body limit exceeded");
      throw new Error(`GET ${url} exceeded ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, length);
}

export async function runLiveSampleCheck() {
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("read-only sample check timed out")),
    TIMEOUT_MS,
  );
  try {
    const [registryRaw, sampleRaw, actionInstanceRaw, unitContractRaw] = await Promise.all([
      boundedGet(REGISTRY_URL, controller.signal),
      boundedGet(SAMPLE_URL, controller.signal),
      readFile(path.join(v1, "ACTION-INSTANCE.json")),
      readFile(path.join(v1, "UNIT-CONTRACT.json")),
    ]);
    const result = verifyCapturedSampleDiagnostic({
      registryRaw,
      sampleRaw,
      actionInstance: JSON.parse(actionInstanceRaw),
      unitContract: JSON.parse(unitContractRaw),
      atSeconds: Math.floor(Date.now() / 1000),
    });
    return Object.freeze({
      ...result,
      transport: Object.freeze({
        exact_get_count: 2,
        methods: Object.freeze(["GET", "GET"]),
        hosted_verify_called: false,
        credentials_sent: false,
        write_performed: false,
      }),
    });
  } catch (error) {
    controller.abort(
      error instanceof Error
        ? error
        : new Error("read-only sample check failed"),
    );
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = await runLiveSampleCheck();
    console.log(JSON.stringify(result, null, 2));
    process.exitCode =
      result.code === "SYNTHETIC_SAMPLE_ONLY" && result.diagnostic_valid === true
        ? 0
        : 3;
  } catch (error) {
    console.error(JSON.stringify({
      schema: "frontier-compute.insight-live-sample-check-error.v1",
      decision: "UNKNOWN_BLOCKED",
      code: "LIVE_DEPENDENCY_UNAVAILABLE",
      detail: error instanceof Error ? error.message : "read-only dependency unavailable",
      exact_get_count: 2,
      observation_state: "NOT_ACCEPTED",
      replay_state: "NOT_COMMITTED",
      action_authorized: false,
    }, null, 2));
    process.exitCode = 4;
  }
}
