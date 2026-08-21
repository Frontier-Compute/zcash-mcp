import assert from "node:assert/strict";

import { runFrozenTests } from "./test-frozen.mjs";
import { runMcpContractTest } from "./test-mcp.mjs";
import { verifySourceManifest } from "./verify-source-manifest.mjs";

const nodeMajor = Number(process.versions.node.split(".")[0]);
assert(Number.isInteger(nodeMajor) && nodeMajor >= 20, `Node >=20 is required; found ${process.versions.node}`);

const manifest = await verifySourceManifest();
const frozen = await runFrozenTests();
const mcp = await runMcpContractTest(frozen.binding);

console.log(JSON.stringify({
  suite: "insight-zap1-receiver-package-v1",
  pass: true,
  node: process.versions.node,
  manifest,
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
  },
  mcp,
  non_actions: {
    attest_event_called: false,
    merkle_proof_created: false,
    zcash_anchor_created_or_verified: false,
    trade_or_payment_authorized: false,
  },
}, null, 2));
