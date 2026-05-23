# zcash-mcp

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-mcp)](https://www.npmjs.com/package/@frontiercompute/zcash-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-published-green)](https://registry.modelcontextprotocol.io/)
![downloads](https://img.shields.io/npm/dw/@frontiercompute/zcash-mcp)
![license](https://img.shields.io/npm/l/@frontiercompute/zcash-mcp)

ZAP1 attestation and proof-verification MCP for Zcash agents.

MCP is the standard way for AI agents to call external tools. `zcash-mcp`
exposes the ZAP1 attestation layer for agents that need verifiable receipts
around Zcash workflows: write ZAP1 attestations to Zcash memos, query
attestation state, and verify proof receipts.

This is not a full wallet MCP. Balance scanning, private key custody, seed
handling, PCZT signing, shielded spend construction, and lightwalletd or Zaino
wallet synchronization are complementary wallet-layer work, not this server's
scope.

## Why ZAP1

Wallet MCPs can move value. ZAP1 proves the workflow around the value.

Agent systems need more than a payment or a transaction lookup. They need a
receipt that another agent, user, auditor, or service can verify later:

- what event was asserted
- which agent or workflow asserted it
- which ZAP1 leaf records it
- which Merkle root includes it
- which Zcash transaction anchored that root
- how to verify the proof without trusting the original agent

That is the lane for this server. It gives Zcash agents a receipt layer that can
sit beside any wallet, signer, custody system, lightwalletd stack, Zaino stack,
or application-specific payment flow.

## Capability Boundary

The `zcash_capability_manifest` tool gives agents a machine-readable scope map:

- owned here: ZAP1 receipts, lifecycle attestations, proof verification, anchor
  state, memo decoding, and public chain context
- not owned here: custody, seed handling, balance scanning, PCZT signing,
  shielded spend construction, and wallet-server synchronization
- composition rule: use this server before or after wallet-layer actions to
  create, query, and verify receipts

Good fits:

- agent action receipts
- payment and invoice proof packets
- operator lifecycle events
- policy and reputation attestations
- public anchor verification for private workflows
- cross-agent handoffs where the receiver needs proof, not custody

Poor fits:

- holding keys
- scanning wallet balances
- signing PCZTs
- broadcasting shielded spends
- replacing a wallet SDK

## Customer Flow

Use `zcash_receipt_template` first when you are wiring ZAP1 into a product. It
returns a customer-ready workflow for the receipt type you want:

- `agent_action`: prove an agent performed a named action with specific input
  and output hashes
- `payment_receipt`: bind invoice or payment metadata to a ZAP1 leaf and later
  prove inclusion under an anchored root
- `operator_lifecycle`: record deployment, upgrade, incident, recovery, or
  policy state as a verifiable lifecycle event
- `policy_attestation`: record an agent, service, or workflow policy decision
  as a verifiable event

Expected flow:

1. Call `zcash_capability_manifest` to confirm the attestation boundary.
2. Call `zcash_receipt_template` for the use case.
3. Call `attest_event` to create the typed ZAP1 leaf.
4. Call `get_anchor_status` to check whether the leaf is anchored or waiting.
5. Call `verify_proof` to verify tree inclusion.
6. Call `zcash_prove_payment` to fetch a handoff proof bundle.

Acceptance checks:

- the receipt has a leaf hash
- the leaf verifies under a returned Merkle root
- anchored receipts include an anchor transaction or anchor height
- another verifier can repeat verification without trusting the original agent
- no private keys, seeds, PCZTs, or wallet scan state were sent to this server

Red-team rejects:

- treating a payment URI as proof of payment
- treating an unanchored leaf as final settlement evidence
- asking this server to sign, scan balances, recover seeds, or hold keys
- mixing custody claims into ZAP1 receipt claims
- hiding the distinction between wallet action and receipt verification

## Tools

| Tool | What it does |
|------|-------------|
| `zcash_capability_manifest` | Machine-readable scope map for agent use: owned surfaces, excluded wallet functions, and composition rules |
| `zcash_receipt_template` | Customer-ready receipt workflow for agent actions, payment receipts, operator lifecycle events, and policy attestations |
| `attest_event` | Write a ZAP1 attestation to the Zcash blockchain |
| `verify_proof` | Verify a ZAP1 Merkle proof |
| `zcash_prove_payment` | Fetch the full Merkle proof bundle for a leaf hash |
| `get_anchor_history` | All ZAP1 Merkle root anchors with txids and block heights |
| `get_anchor_status` | Current Merkle tree state: root, unanchored leaves, recommendation |
| `get_stats` | ZAP1 protocol stats: leaves, anchors, types |
| `get_events` | Recent ZAP1 attestation events with type, wallet hash, leaf hash |
| `get_agent_status` | Attestation summary for a ZAP1 agent ID |
| `zcash_identity_register` | Register an agent identity via AGENT_REGISTER attestation |
| `zcash_reputation_score` | Fetch agent bond data and policy compliance as a reputation object |
| `decode_memo` | Decode Zcash memo payloads: ZAP1 typed, ZIP 302, text, binary |
| `zcash_create_invoice` | Create a ZAP1 payment invoice and receipt metadata |
| `zcash_watch_payment` | Poll an invoice until paid or timeout |
| `get_block_height` | Current chain height from Zebra |
| `lookup_transaction` | Raw transaction data by txid |
| `get_balance` | ZAP1 lifecycle and anchor status for a wallet hash or agent ID |
| `send_shielded` | Generate a ZIP 321 `zcash:` payment URI |
| `zcash_crosschain_swap` | Generate a cross-chain swap intent with ZAP1 attestation metadata |
| `zcash_create_wallet` | Return split-key wallet creation instructions for external Ika tooling |
| `zcash_sign_mpc` | Return MPC signing instructions for external Ika tooling |
| `zcash_shield` | Return a shield-to-Orchard transition plan with ZAP1 attestation metadata |
| `zcash_verify_evm` | Verify a ZAP1 Merkle proof on-chain via EVM contract |

## Install

```bash
npx @frontiercompute/zcash-mcp
```

Or install globally:

```bash
npm install -g @frontiercompute/zcash-mcp
```

## Quickstart

Add this to your MCP config:

```json
{
  "mcpServers": {
    "zcash": {
      "command": "npx",
      "args": ["@frontiercompute/zcash-mcp"]
    }
  }
}
```

Restart your client and ask for the current Zcash block height. Read-only tools
do not need an API key.

Get a trial key for write operations:

```bash
curl -s -X POST https://frontiercompute.cash/api/trial-key
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ZEBRA_RPC_URL` | `http://127.0.0.1:8232` | Zebra node JSON-RPC endpoint |
| `ZAP1_API_URL` | `https://pay.frontiercompute.io` | ZAP1 attestation API |
| `ZAP1_API_KEY` | none | API key for write operations |

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "zcash": {
      "command": "npx",
      "args": ["@frontiercompute/zcash-mcp"],
      "env": {
        "ZEBRA_RPC_URL": "http://127.0.0.1:8232",
        "ZAP1_API_KEY": "your-key-here"
      }
    }
  }
}
```

### Any MCP Client

The server communicates over stdio using JSON-RPC. Point your MCP client at the
`zcash-mcp` binary.

## Build From Source

```bash
git clone https://github.com/Frontier-Compute/zcash-mcp.git
cd zcash-mcp
npm ci
npm run build
node dist/index.js
```

## Testing

Offline verification covers the built stdio server and a clean-room install from
the packed npm tarball:

```bash
npm run test:offline
```

Live verification hits a real Zebra RPC and ZAP1 API:

```bash
ZEBRA_RPC_URL=http://127.0.0.1:8232 \
ZAP1_API_URL=http://127.0.0.1:3080 \
ZAP1_API_KEY=your-key-here \
npm run test:live
```

`test:live` drives the MCP server over stdio and exercises the live tool surface,
not just the underlying HTTP endpoints. Set `ZAP1_AGENT_ID` if you want the
`get_agent_status` check to target a specific deployed agent.

GitHub Actions mirrors that split:

- `.github/workflows/offline-ci.yml` runs deterministic packaging and MCP
  handshake checks on every push and pull request.
- `.github/workflows/live-e2e.yml` runs secret-backed live checks on `main`, on
  a schedule, and by manual dispatch.

## Dependencies

- A running [Zebra](https://github.com/ZcashFoundation/zebra) node for chain
  queries
- The ZAP1 API for attestation, proof, anchor, event, and receipt tools
- Memo decoding works locally with no external dependencies

## Related Packages

| Package | What it does |
|---------|-------------|
| [@frontiercompute/zcash-ika](https://www.npmjs.com/package/@frontiercompute/zcash-ika) | Zcash and Bitcoin signing via Ika 2PC-MPC |
| [@frontiercompute/openclaw-zap1](https://www.npmjs.com/package/@frontiercompute/openclaw-zap1) | OpenClaw skill for ZAP1 attestation |
| [@frontiercompute/zap1](https://www.npmjs.com/package/@frontiercompute/zap1) | ZAP1 attestation client |
| [@frontiercompute/silo-zap1](https://www.npmjs.com/package/@frontiercompute/silo-zap1) | Silo agent attestation via ZAP1 |

## Links

- [Dashboard](https://frontiercompute.cash/dashboard.html)
- [MCP Registry](https://registry.modelcontextprotocol.io/)
- [Frontier Compute](https://frontiercompute.cash)
- [Live stats](https://api.frontiercompute.cash/stats)

## License

MIT
