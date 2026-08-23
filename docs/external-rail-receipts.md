# External Rail Receipts

ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute
maintains the reference ZAP1 implementation.

A wrapper makes you trust the server. ZAP1 makes the server unnecessary to
trust.

External rails can execute actions. ZAP1 can bind evidence about those actions
into receipts another party can verify later.

This document defines the generic pattern. It does not claim ownership of any
wallet, router, payment rail, settlement venue, bridge, exchange, or execution
environment.

## Core Flow

1. An external system executes or reports an action.
2. The integration extracts only bounded fields and hashes sensitive evidence.
3. The integration creates a ZAP1 receipt request.
4. ZAP1 records the supported `AGENT_ACTION` event as a typed leaf.
5. The leaf is included under a count-bound Merkle root.
6. A receiver recomputes the leaf and positioned path without trusting the original server.
7. If anchor finality is required, a separate verifier opens the root commitment and checks independently sourced Zcash chain state.

Short form:

`verification completed -> evidence bounded -> AGENT_ACTION leaf -> inclusion verified -> anchor verified separately`

## External Action Request

Use an external action request when the action happened outside ZAP1 but needs a
portable receipt.

Recommended fields:

- `rail_id`: generic rail or integration identifier
- `agent_id`: hash-only agent identity used by the `AGENT_ACTION` wire contract
- `action_type`: bounded verification class, for example `price_integrity_receipt_verified`
- `request_hash`: hash of the verification request (not a quote)
- `action_instance_commitment`: unique salted commitment for this one verification instance
- `intent_hash`: hash of the requested outcome or instruction
- `quote_hash`: optional hash of the quote or offer accepted
- `route_hash`: optional hash of routing or solver metadata
- `origin_txid`: optional public source transaction id
- `settlement_txid`: optional public settlement transaction id
- `destination_txid`: optional public destination transaction id
- `status`: external action status
- `disclosed_fields`: fields intentionally disclosed in the receipt
- `redaction_policy`: privacy profile applied to withheld fields
- `counterparty_digest`: hash-only counterparty binding when needed
- `operator_digest`: hash-only operator binding when needed

Sensitive payloads should be hashed before they are sent to ZAP1.

## Status Values

ZAP1 receipt status:

- `requested`
- `attested`
- `anchored`
- `verified`
- `disputed`
- `expired`
- `revoked`

External verification status:

- `verification_completed`
- `verification_failed`

Generic rail lifecycle labels remain available where they are literally true:

- `rail_pending`
- `rail_broadcasted`
- `rail_failed`
- `rail_refunded`

`verification_completed` does not mean `rail_settled`. These labels describe
bounded evidence state and never override the external rail's native settlement
rules.

## Output Shape

The receipt request should produce:

- `subject_hash`
- `claim_hash`
- `evidence_hash`
- `zap1_agent_action_args`
- `attest_event_args`
- `zap1-receipt-v2` stub
- verifier hints

The supported write mapping is exact:

```json
{
  "event_type": "AGENT_ACTION",
  "agent_id": "<subject hash>",
  "action_type": "price_integrity_receipt_verified",
  "input_hash": "<claim hash>",
  "output_hash": "<evidence hash>"
}
```

The MCP `attest_event` tool sends this mapping to the authoritative ZAP1
`POST /event` route. The bridge precomputes `expected_leaf_hash` from these
exact four fields. Reject the write response unless its returned `leaf_hash`
matches that local value before requesting a proof bundle. The MCP handoff
includes `expected_leaf_hash` as a local-only guard; `attest_event` strips it
from the wire body and fails closed on a mismatching response.

The final v2 packet retains the typed leaf fields, every sibling hash with its
`left` or `right` position, the committed `leaf_count`, and the count-bound root.
The verifier binds `subject_hash` to `agent_id`, `claim_hash` to `input_hash`, and
`evidence_hash` to `output_hash`.

## Verification Semantics

The official `/verify/{leaf}/proof.json` response is a `protocol: ZAP1`,
`version: "2"` envelope containing server leaf metadata, positioned `proof`
steps, `root`, and usually an `anchor` object whose values may both be null. It
deliberately withholds the event preimage. Retain the exact `AGENT_ACTION`
arguments from the write as a separate witness.

Call `zap1_verify_receipt_v2` with:

```json
{
  "proof_bundle": { "protocol": "ZAP1", "version": "2", "leaf": {}, "proof": [], "root": {} },
  "agent_action_witness": {
    "event_type": "AGENT_ACTION",
    "agent_id": "...",
    "action_type": "price_integrity_receipt_verified",
    "input_hash": "...",
    "output_hash": "..."
  }
}
```

The tool strictly accepts `ZAP1_COUNT_BOUND_V2`; it does not admit a legacy
scheme through the v2 path. It normalizes `{ "txid": null, "height": null }`
by omitting the anchor rather than manufacturing an anchor reference.

The verifier recomputes:

1. the typed `AGENT_ACTION` leaf with the ZAP1 BLAKE2b leaf personalization;
2. every Merkle node in the declared sibling position;
3. the v2 root commitment over the raw root and `leaf_count`.

Only that recomputation can produce `cryptographic_inclusion_valid: true`.
An `anchor.txid`, `anchor.height`, or claimed `status` is only a reference. This
tool always returns `anchor_confirmed: false` and `acceptance_ready: false` until
a separate verifier receives a complete anchor-opening artifact and checks it
against independent chain state.

An integration-bound `zap1-receipt-v2` packet remains accepted for callers that
already retained the same witness beside the proof. The official bundle plus
witness path is the canonical receiver interface and does not rename the
server envelope.

The legacy `zap1_verify_external_receipt` tool is intentionally shape-only for
`zap1-receipt-v1`; it cannot reconstruct sibling order or the count-bound root.
It also cannot promote a hosted external verifier's `valid: true` response into
native receipt authentication. A hosted verifier may be a diagnostic, but the
receiver must independently authenticate the external rail's signed payload,
schema, issuer trust root, freshness, and action binding before constructing a
ZAP1 receipt request.

## Boundaries

ZAP1 does not:

- route funds
- swap assets
- sign transactions
- custody keys
- scan wallet balances
- broadcast transactions
- settle external actions
- verify external compliance by itself

ZAP1 does:

- bind a claim to bounded evidence
- produce typed event leaves
- anchor receipt commitments
- return proof material
- let receivers verify receipt packets later

## Supported Event Contract

External verification receipts use `AGENT_ACTION`. Arbitrary labels such as
`EXTERNAL_ACTION_RECEIPT` are not advertised as write-compatible event types.
The bounded external meaning belongs in `action_type`; the ZAP1 wire event stays
`AGENT_ACTION`.

## Red-Team Rejects

Reject an integration if it:

- sends raw secrets, private keys, viewing keys, seeds, PCZTs, or customer rows
- treats a quote as settlement
- translates `verification_completed` into `rail_settled`
- treats an unanchored receipt as final evidence
- treats txid, height, or self-claimed status as anchor confirmation
- treats a hosted verifier response as native cryptographic verification
- accepts a new key from a mutable registry without authenticated succession and rollback protection
- drops sibling positions or `leaf_count`
- hides which fields were redacted
- claims ZAP1 audited the external rail
- claims ZAP1 owns the wallet, router, payment, or settlement layer

Keep the rail/action boundary explicit. The external system executes. ZAP1
proves the receipt.
