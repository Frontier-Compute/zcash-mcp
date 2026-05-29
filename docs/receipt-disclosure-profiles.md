# Receipt Disclosure Profiles

ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute
maintains the reference ZAP1 implementation.

A wrapper makes you trust the server. ZAP1 makes the server unnecessary to
trust.

Receipt profiles define how much evidence a receiver is allowed to see. The
same action can produce different packets for public observers, counterparties,
auditors, operators, grant reviewers, or compliance reviewers.

## Profile Summary

| Profile | Audience | Purpose |
|---|---|---|
| `public_hash_only` | Public observers | Show that a receipt exists without exposing private evidence |
| `counterparty_receipt` | Receiver or counterparty | Let the other side verify the action and anchor context |
| `auditor_packet` | Trusted reviewer | Provide expanded evidence for private review |
| `operator_internal` | Operator or developer | Preserve full debugging and incident continuity |
| `grant_proof_packet` | Grant or milestone reviewer | Prove delivered work without leaking private internals |
| `compliance_audit_packet` | Legal, tax, or policy reviewer | Support regulated disclosure with explicit redaction boundaries |

## public_hash_only

Use when a public surface only needs proof that a receipt commitment exists.

Include:

- `schema_version`
- `event_type`
- `leaf_hash`
- `merkle_root`
- `anchor_txid`
- `anchor_height`
- `verification_url`

Do not include:

- counterparties
- raw action metadata
- private evidence
- customer or operator rows
- wallet state

## counterparty_receipt

Use when the receiver needs to verify a specific action.

Include:

- standard ZAP1 receipt fields
- `subject_hash`
- `claim_hash`
- `evidence_hash`
- intentionally disclosed action label
- relevant public transaction id, if intentionally public
- redaction policy

Do not include:

- private keys
- seeds
- viewing keys
- raw wallet scan state
- private notes

## auditor_packet

Use for a trusted reviewer who needs more context than a counterparty.

Include:

- standard ZAP1 receipt fields
- evidence manifest
- disclosed fields list
- redacted fields list
- source hashes
- review purpose
- expiration or review window, if applicable

Do not include raw secrets unless the review process explicitly requires them
and the packet is handled outside public ZAP1 surfaces.

## operator_internal

Use for internal continuity, debugging, and incident response.

Include:

- full hash manifest
- local references
- timestamps
- retry state
- failure state
- operator notes hash
- source artifact hashes

Do not publish this profile. It can contain context that is safe internally but
unsafe for public receivers.

## grant_proof_packet

Use for retro grants, milestone acceptance, or public-good delivery evidence.

Include:

- standard ZAP1 receipt fields
- milestone or deliverable id
- public repository, issue, release, advisory, or endpoint references
- source hashes
- acceptance checks
- maintainer or reviewer public-credit reference, if present
- redaction policy

Do not include:

- private vulnerability details
- PoC material
- bounty math
- private counterparty messages
- non-public infrastructure paths

## compliance_audit_packet

Use for legal, tax, policy, or regulated disclosure workflows.

Include:

- standard ZAP1 receipt fields
- disclosure purpose
- disclosed fields list
- redacted fields list
- authority or review context
- source hashes
- retention or expiration notes

Do not include anything outside the stated disclosure purpose.

## Redaction Policy

Each profile should name the redaction policy used:

- `hash_only`
- `counterparty_visible`
- `auditor_visible`
- `operator_private`
- `grant_public`
- `compliance_limited`

Receivers should reject packets that do not explain why sensitive fields are
missing or withheld.

## Verification Rule

A profile changes who can see evidence. It does not change what ZAP1 proves.

Every profile still resolves to:

- a bounded claim
- evidence hashes
- a ZAP1 leaf
- a Merkle proof
- an anchor context

The receiver verifies the receipt. The receiver does not need to trust the
issuer server.
