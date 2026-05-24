# ZAP1 Proof Rail

ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute
maintains the reference ZAP1 implementation.

A wrapper makes you trust the server. ZAP1 makes the server unnecessary to
trust.

Core rule: observe state, bound the claim, hash evidence, issue a receipt,
verify later.

ZAP1 coule de source: receipt truth flows from observed state, bounded claims,
hashes, anchors, and independent verification.

Wallets move value. ZAP1 proves the workflow around the value, and the
counterparty can verify the proof without trusting Frontier.

Tool servers expose what a backend says right now. ZAP1 produces a receipt that
another party can verify later from the schema, proof material, and Zcash anchor.

The core surface is four verbs:

1. `attest`: create a typed event leaf for an agent, payment, operator action, or policy decision.
2. `anchor`: commit batches of leaves into a Merkle root and anchor the root to Zcash.
3. `prove`: return the receipt packet for a leaf, including the Merkle path and anchor context.
4. `verify`: let another agent, user, service, or auditor check the receipt without trusting the original runtime.

## What ZAP1 Covers

ZAP1 covers receipts, not custody.

The protocol is designed for workflows where the important question is not just
"did a transaction exist" but "what claim was made, by which workflow, under
which proof, and how can another party verify it later."

In scope:

- agent action receipts
- payment and invoice receipt packets
- wallet action receipts
- operator lifecycle events
- policy and reputation attestations
- Zcash memo decoding for ZAP1 payloads
- Merkle inclusion proofs
- anchor status and anchor history
- public chain context needed to interpret anchors

Out of scope:

- private key custody
- seed handling
- wallet balance scanning
- PCZT signing
- shielded spend construction
- lightwalletd or Zaino wallet synchronization
- claiming that an unanchored leaf is final settlement evidence

## Receipt Model

A ZAP1 receipt packet should be enough for an independent verifier to replay the
proof check.

Minimum fields:

- `event_type`
- `subject_hash`
- `claim_hash`
- `evidence_hash`
- `leaf_hash`
- `merkle_root`
- `merkle_path`
- `schema_version`
- `anchor_txid`, when anchored
- `anchor_height`, when known
- `verification_url`, when available

Acceptance checks:

- the receipt has a leaf hash
- the leaf verifies under the returned Merkle root
- anchored receipts include an anchor transaction or anchor height
- verification can be repeated without trusting the original agent
- no private keys, seeds, PCZTs, or wallet scan state were sent to the ZAP1 server

## Integration Pattern

Use ZAP1 before or after wallet-layer tools.

Before a wallet action:

- attest an approval, policy check, quote, route decision, or operator state
- pass the receipt hash into the wallet or service layer as context

After a wallet action:

- call `zap1_wallet_receipt_request` with the wallet result
- attest the returned hash-only request
- anchor the receipt
- hand the proof packet to the counterparty

This keeps the category clear:

- wallet tools hold keys, scan state, build transactions, and broadcast spends
- ZAP1 tools create receipts, anchor proofs, and verify claims

## Product Position

`@frontiercompute/zcash-mcp` is the reference ZAP1 implementation for MCP
agents.

It gives agents a narrow, verifiable proof layer that can compose with any
wallet, signer, custody system, lightwalletd stack, Zaino stack, or application
workflow.

The product should get stronger by deepening the proof rail, not by becoming a
wallet.

Public claim:

> Wallets move value. ZAP1 proves the workflow around the value, and you can verify the proof yourself on Zcash.

## Red Team Rejects

Reject any integration that:

- treats a payment URI as proof of payment
- treats a pending leaf as anchored finality
- asks ZAP1 to hold keys or recover seeds
- asks ZAP1 to sign or submit transactions
- hides the boundary between wallet action and receipt verification
- mixes custody claims into receipt claims
