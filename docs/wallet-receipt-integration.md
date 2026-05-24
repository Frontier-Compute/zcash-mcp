# Wallet Receipt Integration

ZAP1 composes with wallet-layer systems without becoming the wallet.

Wallets keep custody, signing, scanning, PCZT construction, policy enforcement,
and transaction broadcast. ZAP1 receives only bounded hashes and returns a
receipt path another party can verify later.

A wrapper makes you trust the server. ZAP1 makes the server unnecessary to
trust.

## Contract

A wallet integration should produce a wallet action result, then pass a
hash-only summary into `zap1_wallet_receipt_request`.

Minimum action result:

- `wallet_provider`: wallet or service name
- `action_type`: action being attested, such as `shielded_send`,
  `invoice_paid`, `pczt_created`, `policy_approved`, or `sync_checkpoint`
- `action_status`: `requested`, `approved`, `submitted`, `confirmed`,
  `completed`, or `failed`
- `action_reference`: wallet-local operation reference, hashed first if
  sensitive
- `txid`: optional public transaction id when the action produced one
- `result_hash`: optional hash of the wallet result object

The tool returns:

- deterministic `subject_hash`, `claim_hash`, and `evidence_hash`
- `attest_event_args` ready to pass to `attest_event`
- a `zap1-receipt-v1` stub for the final receipt packet
- next steps for anchor status, proof fetch, and conformance check

## Flow

1. Wallet executes the native action.
2. Wallet hashes the action result or passes already hashed fields.
3. Integration calls `zap1_wallet_receipt_request`.
4. Integration calls `attest_event` with the returned `attest_event_args`.
5. Integration waits for anchor context if the receiver needs final evidence.
6. Integration calls `zap1_prove_receipt` and hands the receipt to the receiver.
7. Receiver calls `zcash_conformance_check` and verifies the proof.

## Example

```json
{
  "wallet_provider": "wallet-demo",
  "action_type": "shielded_send",
  "action_status": "confirmed",
  "action_reference": "op-123",
  "txid": "2222222222222222222222222222222222222222222222222222222222222222",
  "amount_zat": 1000,
  "result_hash": "3333333333333333333333333333333333333333333333333333333333333333"
}
```

The returned `attest_event_args` is the handoff:

```json
{
  "event_type": "WALLET_ACTION_RECEIPT",
  "wallet_hash": "<subject_hash>",
  "serial_number": "op-123",
  "action_type": "shielded_send",
  "input_hash": "<claim_hash>",
  "output_hash": "<evidence_hash>"
}
```

## Boundaries

Send to ZAP1:

- hashes
- public transaction ids when intentionally public
- action state labels
- wallet-local references only when safe or already hashed

Do not send to ZAP1:

- private keys
- seeds
- PCZTs
- viewing keys
- balances
- raw customer rows
- raw payment rows
- raw wallet scan state
- spend authority

## Product Split

Wallet MCPs execute wallet actions.

ZAP1 gives those actions receipts.

That split lets a wallet product add verifiable receipts without changing its
custody model or asking receivers to trust the wallet server.
