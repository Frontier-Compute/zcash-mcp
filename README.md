# zcash-mcp

Zcash MCP server. Connects AI agents to shielded Zcash operations.

MCP (Model Context Protocol) is the standard way for AI models to call external tools. This server exposes 8 Zcash tools that any MCP client can use - Claude Desktop, ChatGPT, OpenClaw, or anything that speaks the protocol.

## Tools

| Tool | What it does |
|------|-------------|
| `get_balance` | Shielded balance for an address via Zebra RPC |
| `send_shielded` | Generate a zcash: payment URI (ZIP 321) |
| `decode_memo` | Decode shielded memos - ZAP1 typed, ZIP 302, text, binary |
| `attest_event` | Write a ZAP1 attestation to the Zcash blockchain |
| `verify_proof` | Verify a ZAP1 Merkle proof |
| `get_stats` | ZAP1 protocol stats (leaves, anchors, types) |
| `get_block_height` | Current chain height from Zebra |
| `lookup_transaction` | Raw transaction data by txid |

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
npm install
npm run build
node dist/index.js
```

## Dependencies

- A running [Zebra](https://github.com/ZcashFoundation/zebra) node for chain queries (get_balance, get_block_height, lookup_transaction)
- The ZAP1 API at pay.frontiercompute.io for attestation tools (attest_event, verify_proof, get_stats)
- Memo decoding works locally with no external dependencies

## License

MIT
