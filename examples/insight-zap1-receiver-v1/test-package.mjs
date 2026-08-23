import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { runFrozenTests } from "./test-frozen.mjs";
import { runMcpContractTest } from "./test-mcp.mjs";
import { verifySourceManifest } from "./verify-source-manifest.mjs";

const nodeMajor = Number(process.versions.node.split(".")[0]);
assert(Number.isInteger(nodeMajor) && nodeMajor >= 20, `Node >=20 is required; found ${process.versions.node}`);

const packageContract = JSON.parse(await readFile(new URL("./PACKAGE-CONTRACT.json", import.meta.url), "utf8"));
assert.equal(packageContract.network.hosted_verdict_trusted, false);
assert.equal(
  packageContract.network.hosted_verify_endpoint_role,
  "OPTIONAL_PROVIDER_DIAGNOSTIC_ONLY_NEVER_ACCEPTANCE_AUTHORITY",
);
assert.equal(packageContract.network.legacy_v1_shape_check_accepts_hosted_verdict_as_native_proof, false);
assert.equal(
  packageContract.security_contract.unit_contract_role,
  "LOCAL_FIXED_POINT_INTERPRETATION_ARTIFACT_NOT_ON_CHAIN_ISSUER_CONTRACT",
);
assert.equal(packageContract.security_contract.dynamic_registry_rotation_supported, false);
assert.equal(packageContract.security_contract.live_registry_fetch_authorizes_new_trust_root, false);
assert.equal(packageContract.security_contract.registry_change_behavior, "FAIL_CLOSED_AND_REOPEN");
assert.deepEqual(packageContract.security_contract.dynamic_rotation_prerequisites, [
  "authenticated registry succession independent of mutable transport",
  "monotonic epoch or sequence with previous-registry digest",
  "key status, validity window, overlap, and revocation semantics",
  "rollback-resistant last-known-good state and outage behavior",
  "deterministic adversarial rotation and recovery tests",
]);

const manifest = await verifySourceManifest();
const frozen = await runFrozenTests();
const mcp = await runMcpContractTest(frozen.binding);

console.log(JSON.stringify({
  suite: "insight-zap1-receiver-package-v1",
  pass: true,
  node: process.versions.node,
  manifest,
  policy_contract: {
    hosted_verdict_trusted: packageContract.network.hosted_verdict_trusted,
    hosted_verify_endpoint_role: packageContract.network.hosted_verify_endpoint_role,
    unit_contract_role: packageContract.security_contract.unit_contract_role,
    dynamic_registry_rotation_supported: packageContract.security_contract.dynamic_registry_rotation_supported,
    live_registry_fetch_authorizes_new_trust_root: packageContract.security_contract.live_registry_fetch_authorizes_new_trust_root,
    registry_change_behavior: packageContract.security_contract.registry_change_behavior,
  },
  frozen: {
    pass: frozen.pass,
    frozen_vectors: frozen.frozen_vectors,
    independent_action_instance: frozen.independent_action_instance,
    native_uid: frozen.native_uid,
    recovered_signer: frozen.recovered_signer,
    unit_contract_hash: frozen.unit_contract_hash,
    display: frozen.display,
    zap1_hashes: frozen.zap1_hashes,
    current_authorization: frozen.current_authorization,
    resilience: frozen.resilience,
  },
  mcp,
  non_actions: {
    local_loopback_attest_event_called: true,
    live_attest_event_called: false,
    deployed_proof_fetched: false,
    production_merkle_proof_created: false,
    synthetic_single_leaf_conformance_proof_created: true,
    zcash_anchor_created_or_verified: false,
    trade_or_payment_authorized: false,
  },
}, null, 2));
