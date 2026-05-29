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
4. ZAP1 records the typed event as a leaf.
5. The leaf is included under a Merkle root and anchored.
6. A receiver verifies the receipt without trusting the original server.

Short form:

`action happened -> evidence bounded -> receipt issued -> anchored -> verifier checks`

## External Action Request

Use an external action request when the action happened outside ZAP1 but needs a
portable receipt.

Recommended fields:

- `rail_id`: generic rail or integration identifier
- `action_type`: action class being attested
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

External rail status:

- `rail_pending`
- `rail_broadcasted`
- `rail_settled`
- `rail_failed`
- `rail_refunded`

These labels describe evidence state. They do not override the external rail's
native settlement rules.

## Output Shape

The receipt request should produce:

- `subject_hash`
- `claim_hash`
- `evidence_hash`
- `attest_event_args`
- `zap1-receipt-v1` stub
- verifier hints

The final receipt remains the standard ZAP1 receipt packet: event type, subject
hash, claim hash, evidence hash, leaf hash, Merkle proof, and anchor context.

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

## Safe Event Types

External integrations can use event types such as:

- `EXTERNAL_ACTION_RECEIPT`
- `CROSS_CHAIN_ROUTE_COMPLETED`
- `SPENDING_POLICY_ENFORCED`
- `HITL_APPROVAL_TOKEN`
- `X402_PAYMENT_COMPLETED`
- `MPP_PAYMENT_LEG_SETTLED`
- `VALIDATOR_OUTCOME_SETTLED`
- `SECURITY_REMEDIATION_CONFIRMED`
- `LEAD_DEV_CREDIT_MENTION`

These event types prove bounded evidence about a workflow. They do not claim
that ZAP1 operates the underlying rail.

## Red-Team Rejects

Reject an integration if it:

- sends raw secrets, private keys, viewing keys, seeds, PCZTs, or customer rows
- treats a quote as settlement
- treats an unanchored receipt as final evidence
- hides which fields were redacted
- claims ZAP1 audited the external rail
- claims ZAP1 owns the wallet, router, payment, or settlement layer

Keep the rail/action boundary explicit. The external system executes. ZAP1
proves the receipt.
