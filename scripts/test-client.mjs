import assert from "node:assert/strict";
import process from "node:process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  SAMPLE_ADDRESS,
  assertDecodeMemoResult,
  assertSendShieldedResult,
  assertToolRegistration,
  parseJsonTextResult,
} from "./test-helpers.mjs";

export async function runMcpSmokeTest(serverEntry, { cwd, label }) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    cwd,
    env: { ...process.env },
    stderr: "pipe",
  });

  let stderr = "";
  const stderrStream = transport.stderr;
  if (stderrStream && typeof stderrStream.on === "function") {
    if (typeof stderrStream.setEncoding === "function") {
      stderrStream.setEncoding("utf8");
    }
    stderrStream.on("data", (chunk) => {
      stderr += chunk.toString();
    });
  }

  const client = new Client({
    name: "zcash-mcp-smoke",
    version: "0.2.0",
  });
  let stage = "connect";

  try {
    await client.connect(transport);

    stage = "server metadata";
    const serverInfo = client.getServerVersion();
    assert(serverInfo, `${label}: server did not report version metadata`);
    assert.equal(serverInfo.name, "zcash-mcp", `${label}: unexpected server name`);
    assert.match(serverInfo.version, /^\d+\.\d+\.\d+/, `${label}: invalid server version`);

    stage = "list tools";
    const tools = await client.listTools();
    assertToolRegistration(tools.tools);
    assert.equal(tools.tools.length, 18, `${label}: tool count drifted`);

    stage = "ping";
    await client.ping();

    stage = "send_shielded";
    const sendResult = await client.callTool({
      name: "send_shielded",
      arguments: {
        address: SAMPLE_ADDRESS,
        amount: 0.01,
        memo: "hello world",
        label: "zcash mcp",
      },
    });
    assert(!sendResult.isError, `${label}: send_shielded returned an error`);
    assertSendShieldedResult(parseJsonTextResult(sendResult));

    stage = "decode_memo";
    const memoResult = await client.callTool({
      name: "decode_memo",
      arguments: {
        memo: Buffer.from("hello world", "utf8").toString("hex"),
      },
    });
    assert(!memoResult.isError, `${label}: decode_memo returned an error`);
    assertDecodeMemoResult(parseJsonTextResult(memoResult));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const suffix = stderr.trim() ? `\nserver stderr:\n${stderr.trim()}` : "";
    throw new Error(`${label} failed during ${stage}: ${message}${suffix}`);
  } finally {
    await transport.close().catch(() => {});
  }
}
