# Insight OracleSafetyCheck v2 -> ZAP1 receiver package

This is a source-complete, receiver-reproducible reference for one bounded
claim:

> A frozen, issuer-key-signed representative Insight OracleSafetyCheck v2 demo
> receipt was independently valid for a separately supplied action instance at
> the recorded check time, and the resulting deterministic hashes satisfy the public ZAP1
> `zap1_attest_external_action` request contract.

It does **not** call the live ZAP1 service, build a production Merkle proof,
anchor anything to Zcash, authorize a trade, touch a wallet, or prove current
price freshness. The test does call attest_event against an in-process
127.0.0.1 mock to prove the exact POST /event wire contract.

## Requirements

- Node.js `>=20` (enforced before tests run)
- npm with access to the registry for the initial `npm ci`
- no parent checkout, sibling checkout, global MCP package, or environment
  variable

The receiver archive contains the complete `zcash-mcp` source tree pinned by
`BASE-PROVENANCE.json`. Keep this directory at
`examples/insight-zap1-receiver-v1` inside that extracted tree; the declared
relative repository root is `../..` and is verified from the source manifest.

From the extracted archive root:

```text
npm ci --ignore-scripts
npm run test:insight-receiver
```

The test is offline after dependency installation. It verifies the package
manifest, unit contract, frozen passing/tampered/expired vectors, independent
action-instance binding, exact-expiry rejection, mandatory replay reservation,
the real MCP stdio contract, a localhost POST /event, response-substitution
rejection, bounded JSON responses, and a synthetic single-leaf receipt-v2
inclusion. Success ends with `"pass": true` and remains explicitly
no-live-write and not anchored.

## Independent action input

`ACTION-INSTANCE.json` exists before and independently of any receipt. Its
human amount (`10000.000000 USD`) and atom count (`10000000000`) must agree
under the pinned USD `1e6` scale. The verifier compares that action to the
receipt and recomputes the canonical EIP-712 request hash. It never constructs
the intended action by copying receipt fields.

The ZAP1 `intent_hash` binds the intended action and fixed-point contract.
A separate salted `action_instance_commitment` binds the action-instance id,
receiver id, nonce, and intended-action hash without disclosing the raw values.
Replaying the same native receipt for a different action instance therefore
changes the claim and evidence hashes.

The atomic API also requires a replay guard with an atomic reserve method. The
same action instance can reserve once; a duplicate reservation, missing store,
or store error fails closed before a binding is returned. The included
in-memory guard is for conformance tests. A production receiver needs a durable
multi-process implementation.

The receiver API is atomic: it verifies the native receipt and constructs
`result.binding` in one call. The binding exposes
`zap1_external_action_args` and the exact retained
`zap1_agent_action_args` witness. It uses
`status: verification_completed`, keeps `request_hash` distinct from
`intent_hash`, and omits `quote_hash` because the sample is not an economic
quote.

Registry evidence uses exact-byte semantics. The transport-safe
`fixtures/registry-20260821.body.b64` decodes to the exact captured response
bytes, and `registry_sha256` hashes those bytes without whitespace or
line-ending normalization. The decoded JSON must also equal the registry
object used for verification. Semantically equivalent pretty-printed, LF, or
CRLF variants are rejected by the immutable receiver pin. The trust-root
issuer, key id, signer, registry SHA-256, PASS-only verdict, and 600-second TTL
cannot be changed through runtime policy. Runtime policy accepts only bounded,
strictness-increasing risk, freshness, quorum, and clock-skew settings.

## Fixed-point units

`UNIT-CONTRACT.json` makes every numeric interpretation explicit:

- `tradeAmountUsd` and `recommendedMaxPositionUsd`: USD atoms at `1e6`;
- `consensusPrice`: USD per one source asset at `1e8`;
- percentage risk/deviation fields: basis points;
- cross-provider agreement: a 0..1 ratio at `1e4`.

Those scales are pinned to immutable public Insight source commit
`8f84ecaa83f587b1b4a797926e1a509077c5f2f9` and exact Git blob ids. The live
well-known registry does not currently publish the units, so a source, schema,
or issuer clarification change is a hard reopen trigger.

## Frozen corpus labels

- `FRESHLY_SIGNED_REPRESENTATIVE_DEMO_SNAPSHOT`: issuer-key-signed receipt
  captured from the public sample endpoint. It is a representative demo
  envelope, not evidence that its provider-observation fields came from live
  provider queries. Historical signature and policy verification uses
  `checkedAt + 1`; current authorization must reject it after expiry.
- `DELIBERATE_FAILURE_DEMO_TAMPERED`: issuer-provided demo with a forged verdict
  after signing. It must fail UID and signer checks.
- `DELIBERATE_FAILURE_DEMO_EXPIRED`: issuer-provided, validly signed receipt
  backdated beyond its 600-second window. It must fail freshness checks.

All three sample-endpoint fixtures are conformance material, not production
incidents or proof of live provider observations. The frozen passing receipt is
historical signature evidence, not a current trade signal.

## Hosted verifier boundary

The public hosted Insight verifier is outside the receiver trust root and is
neither called nor trusted by this package. The receiver recomputes the EIP-712
digest and canonical request hash locally, recovers the signature signer, and
requires the exact frozen registry bytes plus the pinned issuer key. Local
issuer hardening is not established as deployed.

## Source and proof boundaries

- `SOURCE-MANIFEST.json` records a controlling raw-byte SHA-256 for every
  receiver-package file and the complete MCP `src` and `schemas` closures,
  plus root dependency/build files. A second canonical-text SHA-256 is an
  explicit portability cross-check only. The manifest excludes itself to avoid
  a circular hash and declares that sole exclusion.
- The included `.gitattributes` pins every manifest-controlled text path to LF,
  so fresh Git checkouts and the attachment preserve the same controlling bytes.
- Text normalization never changes the controlling raw hash. It applies only
  to the secondary canonical-text field and to the base64 wrapper text, not to
  the decoded registry evidence. The test separately checks that those decoded
  bytes hash to the captured registry-body SHA-256.
- `BASE-PROVENANCE.json` resolves the public repository, base commit, base tree,
  local hardening candidate, ZAP1 compatibility audit through
  00979c616d3407b48eee5f6c4ea0591d7fb88a45, and Insight source blobs used for
  the unit contract.
- The MCP test launches the included repository's built `dist/index.js` and
  calls the public tool through stdio. It does not import a mock or assume an
  undeclared checkout.
- `PROOF-SHAPE-PROVENANCE.json` pins the deployed proof response's URL,
  byte count, and SHA-256 as `LIVE_DEPLOYED_SHAPE_ONLY`. Its public leaf
  withholds the AGENT_ACTION preimage, so it is not an Insight semantic vector.
  The receiver retains its own witness and the v2 verifier recomputes the typed
  leaf. When the API returns `anchor: { "txid": null, "height": null }`, the
  strict receipt omits `anchor` entirely.
- The included receipt-v2 inclusion test uses a clearly synthetic single-leaf
  proof. It exercises cryptographic verifier behavior after a localhost-only
  POST /event, without fetching a deployed proof or claiming a Zcash anchor.
- The resulting object is still only a receipt request. Final acceptance needs
  an authorized ZAP1 proof bundle with sibling positions and `leaf_count`, plus
  independent Zcash anchor confirmation.
