# zcash-mcp

[![npm](https://img.shields.io/npm/v/@frontiercompute/zcash-mcp)](https://www.npmjs.com/package/@frontiercompute/zcash-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-published-green)](https://registry.modelcontextprotocol.io/)
![downloads](https://img.shields.io/npm/dw/@frontiercompute/zcash-mcp)
![license](https://img.shields.io/npm/l/@frontiercompute/zcash-mcp)

Zcash MCP server. Connects AI agents to shielded Zcash operations. Published on the MCP registry.

MCP (Model Context Protocol) is the standard way for AI models to call external tools. This server exposes 12 Zcash tools that any MCP client can use - Claude Desktop, ChatGPT, OpenClaw, or anything that speaks the protocol.

## Tools

| Tool | What it does |
|------|-------------|
| `get_balance` | ZAP1 attestation history and anchor status for a wallet hash |
| `send_shielded` | Generate a zcash: payment URI (ZIP 321) |
| `decode_memo` | Decode shielded memos - ZAP1 typed, ZIP 302, text, binary |
| `attest_event` | Write a ZAP1 attestation to the Zcash blockchain |
| `verify_proof` | Verify a ZAP1 Merkle proof |
| `get_stats` | ZAP1 protocol stats (leaves, anchors, types) |
| `get_block_height` | Current chain height from Zebra |
| `lookup_transaction` | Raw transaction data by txid |
| `get_anchor_history` | All ZAP1 Merkle root anchors with txids and block heights |
| `get_anchor_status` | Current Merkle tree state: root, unanchored leaves, recommendation |
| `get_events` | Recent ZAP1 attestation events with type, wallet hash, leaf hash |
| `get_agent_status` | Attestation summary for a ZAP1 agent ID |
| `zcash_create_invoice` | Create a ZAP1 payment invoice, returns address, amount, zcash: URI, expiry |
| `zcash_watch_payment` | Poll an invoice until paid or timeout, returns txid, height, amount |
| `zcash_prove_payment` | Fetch the full Merkle proof bundle for a leaf hash |
| `zcash_identity_register` | Register an agent identity via AGENT_REGISTER attestation |
| `zcash_reputation_score` | Fetch agent bond data and policy compliance as a reputation object |
| `zcash_crosschain_swap` | Cross-chain swap intent: ZEC transparent to BTC, USDC, USDT via Ika or NEAR |
| `zcash_create_wallet` | Create a split-key wallet via Ika 2PC-MPC (secp256k1 signs for ZEC, BTC, ETH) |
| `zcash_sign_mpc` | Sign a message hash through Ika 2PC-MPC (neither party sees the full key) |
| `zcash_shield` | Move ZEC from transparent MPC custody to shielded Orchard pool |
| `zcash_verify_evm` | Verify a ZAP1 Merkle proof on-chain via EVM contract (Sepolia, Base, Arbitrum) |

## Install

```bash
npx @frontiercompute/zcash-mcp
```

Or install globally:

```bash
npm install -g @frontiercompute/zcash-mcp
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ZEBRA_RPC_URL` | `http://127.0.0.1:8232` | Zebra node JSON-RPC endpoint |
| `ZAP1_API_URL` | `https://pay.frontiercompute.io` | ZAP1 attestation API |
| `ZAP1_API_KEY` | none | API key for attest_event |

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

### Any MCP client

The server communicates over stdio using JSON-RPC. Point your MCP client at the `zcash-mcp` binary.

## Build from source

```bash
git clone https://github.com/Frontier-Compute/zcash-mcp.git
cd zcash-mcp
npm ci
npm run build
node dist/index.js
```

## Testing

Offline verification covers the built stdio server and a clean-room install from the packed npm tarball:

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

`test:live` drives the MCP server over stdio and exercises the live tool surface, not just the underlying HTTP endpoints. Set `ZAP1_AGENT_ID` if you want the `get_agent_status` check to target a specific deployed agent.

GitHub Actions mirrors that split:

- `.github/workflows/offline-ci.yml` runs deterministic packaging and MCP handshake checks on every push and pull request.
- `.github/workflows/live-e2e.yml` runs secret-backed live checks on `main`, on a schedule, and by manual dispatch.

## Dependencies

- A running [Zebra](https://github.com/ZcashFoundation/zebra) node for chain queries (get_block_height, lookup_transaction)
- The ZAP1 API at pay.frontiercompute.io for attestation tools (get_balance, attest_event, verify_proof, get_stats, get_anchor_history, get_anchor_status, get_events, get_agent_status)
- Memo decoding works locally with no external dependencies

## Related Packages

| Package | What it does |
|---------|-------------|
| [@frontiercompute/zcash-ika](https://www.npmjs.com/package/@frontiercompute/zcash-ika) | Zcash + Bitcoin signing via Ika 2PC-MPC |
| [@frontiercompute/openclaw-zap1](https://www.npmjs.com/package/@frontiercompute/openclaw-zap1) | OpenClaw skill for ZAP1 attestation |
| [@frontiercompute/zap1](https://www.npmjs.com/package/@frontiercompute/zap1) | ZAP1 attestation client |
| [@frontiercompute/silo-zap1](https://www.npmjs.com/package/@frontiercompute/silo-zap1) | Silo agent attestation via ZAP1 |

## Links

- [Dashboard](https://frontiercompute.cash/dashboard.html) - live ZAP1 attestation dashboard
- [MCP Registry](https://registry.modelcontextprotocol.io/) - published MCP server listing
- [Frontier Compute](https://frontiercompute.cash) - project homepage

## License

MIT

## quickstart (5 minutes)

add to your MCP config:

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

restart your client.  ask: "what is the current zcash block height?"

done.  12 tools available.  no API key needed for read operations.

get a trial key for write operations:

```
curl -s -X POST https://frontiercompute.cash/api/trial-key
```

