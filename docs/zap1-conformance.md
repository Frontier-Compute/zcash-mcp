# ZAP1 Conformance

ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute
maintains the reference ZAP1 implementation.

A wrapper makes you trust the server. ZAP1 makes the server unnecessary to
trust.

Core rule: observe state, bound the claim, hash evidence, issue a receipt,
verify later.

ZAP1 coule de source: receipt truth flows from observed state, bounded claims,
hashes, anchors, and independent verification.

This document defines the minimum contract for a ZAP1-compatible integration.
It is intentionally narrow. Wallets, signers, payment systems, and explorers can
compose with ZAP1 without becoming ZAP1.

The conformance problem is not whether an endpoint can be wrapped. Any backend
can be exposed to agents. The question is whether a receiver can verify the
claim after the backend is unavailable or no longer trusted.

## Required Claims

A conforming integration must keep these claims separate:

- wallet action: the wallet, signer, service, or user performed an operation
- ZAP1 receipt: an event claim was committed as a ZAP1 leaf
- ZAP1 proof: the leaf is included under a Merkle root
- Zcash anchor: the root was anchored by a Zcash transaction or block context

Do not present a wallet action as a ZAP1 proof. Do not present a pending leaf as
anchored finality. Do not present a payment URI as payment evidence.

## Receipt Packet

A handoff receipt should include:

- `event_type`
- `subject_hash`
- `claim_hash`
- `evidence_hash`
- `leaf_hash`
- `merkle_root`
- `merkle_path`
- `anchor_txid`, when anchored
- `anchor_height`, when known
- `verification_url`
- `schema_version`

The packet should be hash-only for sensitive workflow data. ZAP1 proves the
commitment and inclusion path, not the plaintext business payload.

## Acceptance Checks

Before another agent or service accepts a ZAP1 receipt:

1. Verify the receipt has a `leaf_hash`.
2. Verify the leaf under the returned Merkle path.
3. Verify the root matches the claimed anchor context.
4. Treat unanchored leaves as pending evidence, not settlement evidence.
5. Confirm no private keys, seeds, PCZTs, wallet scan state, or spend authority
   were sent to the ZAP1 server.

## Boundary

ZAP1 covers:

- typed event leaves
- receipt packets
- Merkle inclusion proofs
- Zcash anchor context
- memo decoding for ZAP1 payloads
- verification workflows

ZAP1 does not own:

- private key custody
- seed handling
- balance scanning
- PCZT signing
- shielded spend construction
- lightwalletd or Zaino wallet synchronization
- transaction broadcast authority

## Composition Rule

Use wallet-layer systems to move value. Use ZAP1 to prove the workflow around the
value.

Safe integration pattern:

1. Wallet or service performs its native action.
2. Integration hashes the relevant public or private evidence.
3. Wallet integrations call `zap1_wallet_receipt_request` to build bounded
   `attest_event` arguments.
4. Integration submits the typed ZAP1 event.
5. Integration waits for anchor context when final evidence is required.
6. Downstream verifier checks the ZAP1 receipt without trusting the original
   runtime.

## Red-Team Rejects

Reject an integration if it:

- claims ZAP1 is a wallet
- asks ZAP1 to hold keys or recover seeds
- asks ZAP1 to sign or submit transactions
- hides whether a receipt is anchored or pending
- treats wallet balance state as ZAP1 truth
- omits Merkle path verification
- claims MCP reference status instead of reference ZAP1 implementation

The core is the receipt and proof contract. Keep it narrow, verifiable, and
composable.
