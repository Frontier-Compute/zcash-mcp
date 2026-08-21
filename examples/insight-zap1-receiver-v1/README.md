# Insight OracleSafetyCheck v2 -> ZAP1 receiver package

This is a source-complete, receiver-reproducible reference for one bounded
claim:

> A frozen Insight OracleSafetyCheck v2 receipt was independently valid for a
> separately supplied action instance at the recorded check time, and the
> resulting deterministic hashes satisfy the public ZAP1
> `zap1_attest_external_action` request contract.

It does **not** attest an event, build a Merkle proof, anchor anything to
Zcash, authorize a trade, touch a wallet, or prove current price freshness.

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
manifest, unit contract, frozen valid/tampered/expired vectors, independent
action-instance binding, current-expiry rejection, and the real MCP stdio
contract. Success ends with `"pass": true` and the state
`RECEIPT_REQUEST_BUILT_NOT_ATTESTED_NOT_ANCHORED`.

## Independent action input

`ACTION-INSTANCE.json` exists before and independently of any receipt. Its
human amount (`10000.000000 USD`) and atom count (`10000000000`) must agree
under the pinned USD `1e6` scale. The verifier compares that action to the
receipt and recomputes the canonical EIP-712 request hash. It never constructs
the intended action by copying receipt fields.

The ZAP1 `intent_hash` also binds the action-instance id, receiver id, nonce,
unit contract, and exact native request. Replaying the same native receipt for
a different action instance therefore changes or fails the binding.

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

- `VALID_LIVE_SNAPSHOT`: production-key receipt captured from the public
  sample endpoint. Historical verification uses `checkedAt + 1`; current
  authorization must reject it after expiry.
- `DELIBERATE_FAILURE_DEMO_TAMPERED`: issuer-provided demo with a forged verdict
  after signing. It must fail UID and signer checks.
- `DELIBERATE_FAILURE_DEMO_EXPIRED`: issuer-provided, validly signed receipt
  backdated beyond its 600-second window. It must fail freshness checks.

Demo fixtures are negative conformance material, not production incidents.
The frozen valid receipt is historical evidence, not a current trade signal.

## Source and proof boundaries

- `SOURCE-MANIFEST.json` hashes every executable receiver source, contract,
  fixture, and critical base file. The manifest excludes itself to avoid a
  circular hash and declares that exclusion explicitly.
- `BASE-PROVENANCE.json` resolves the public repository, base commit, base tree,
  and Insight source blobs used for the unit contract.
- The MCP test launches the included repository's built `dist/index.js` and
  calls the public tool through stdio. It does not import a mock or assume an
  undeclared checkout.
- The resulting object is still only a receipt request. Final acceptance needs
  an authorized ZAP1 proof bundle with sibling positions and `leaf_count`, plus
  independent Zcash anchor confirmation.

