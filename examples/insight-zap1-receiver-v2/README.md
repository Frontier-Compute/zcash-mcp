# Insight OracleSafetyCheck v2/v3 verifier

Status: public source-review reference. It is not a deployment, package release,
key admission, customer integration, or action-authority surface.

This directory extends the frozen v1 receiver with exact schema dispatch for
OracleSafetyCheck v2 and v3:

- v3 uses the EIP-712 domain version `3` and the ordered 27-field
  OracleSafetyCheck type.
- `requiredSourceGroupCount` is field 27, must equal `2`, and is enforced
  together with the measured `sourceGroupCount` and local policy.
- the v2-only compatibility APIs reject v3 instead of reinterpreting it.
- a historical v2 receipt can be inspected through the registry's published
  `OracleSafetyCheckV2` alias without treating that retired alias as current
  signing authority.
- mutable registry bytes never add a trusted signer or admit a registry head.

## Synthetic sample boundary

`sample-diagnostic.mjs` parses exact captured bytes, verifies the EIP-712 UID
and signature under exactly one active registry key whose role is `sample`,
and still returns:

- `UNKNOWN_BLOCKED / SYNTHETIC_SAMPLE_ONLY`;
- `observation_state: NOT_ACCEPTED`;
- `replay_state: NOT_COMMITTED`;
- no binding or ZAP1 arguments; and
- `action_authorized: false`.

An absent, ambiguous, malformed, non-sample, or revoked signer returns
`UNKNOWN_BLOCKED / SAMPLE_SIGNER_ROLE_UNRESOLVED`. A bad signature, UID,
schema, field order, threshold, request binding, or policy check returns
`UNKNOWN_BLOCKED / SAMPLE_DIAGNOSTIC_VERIFICATION_FAILED`.

The frozen v3 fixture was captured with two unauthenticated public GETs on
September 3, 2026. It is regression evidence, not a claim about current endpoint
state. Its raw hashes and provenance are recorded in
`fixtures/FIXTURE-MANIFEST.json`.

## Run

Use Node.js v22.22.2:

```text
npm ci
npm run test:insight-receiver
```

The suite exercises v2/v3 dispatch, the signed v3 independence threshold,
historical v2 alias behavior, signature and UID recovery, signer lifecycle and
revocation, malformed and duplicate registry entries, strict JSON capture,
freshness gates, replay non-authority, and the synthetic sample boundary.

## Publication boundary

Only public endpoint captures and deterministic synthetic test identities are
included. Private correspondence and private rotation-signature transcripts are
not included. Issuer-key succession and any mutable successor registry head
remain unadmitted unless a separate authenticated evidence and operator
admission process completes.

Nothing here authorizes a trade, position, wallet action, payment, settlement,
ZAP1 write, deployment, partnership, endorsement, or customer claim.
