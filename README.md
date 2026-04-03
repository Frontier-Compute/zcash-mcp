# zcash-mcp

Zcash MCP server. Connects AI agents to shielded Zcash operations.

MCP (Model Context Protocol) is the standard way for AI models to call external tools. This server exposes 12 Zcash tools that any MCP client can use - Claude Desktop, ChatGPT, OpenClaw, or anything that speaks the protocol.

## Tools

| Tool | What it does |
|------|-------------|
| `get_balance` | ZAP1 lifecycle events and anchor status for a wallet hash |
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

## License

MIT
