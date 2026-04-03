import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

// ZAP1 type byte definitions
const ZAP1_TYPES: Record<number, string> = {
  0x00: "text/plain",
  0x01: "payment_request",
  0x02: "payment_receipt",
  0x03: "attestation",
  0x04: "credential",
  0x05: "anchor",
  0x06: "routing",
  0x07: "key_exchange",
  0x08: "revocation",
  0x09: "delegation",
  0x0a: "timestamp",
  0x0b: "metadata",
  0x0c: "binary",
  0x0d: "governance_proposal",
  0x0e: "governance_vote",
  0x0f: "governance_result",
  0x10: "signal_message",
  0x11: "signal_prekey_bundle",
  0x12: "signal_session",
};

function decodeMemo(hexOrBase64: string): {
  format: string;
  type_byte?: number;
  type_name?: string;
  text?: string;
  raw_hex: string;
} {
  let buf: Buffer;

  // Try hex first, then base64
  if (/^[0-9a-fA-F]+$/.test(hexOrBase64)) {
    buf = Buffer.from(hexOrBase64, "hex");
  } else {
    buf = Buffer.from(hexOrBase64, "base64");
  }

  const rawHex = buf.toString("hex");

  // Strip trailing zero padding
  let end = buf.length;
  while (end > 0 && buf[end - 1] === 0) end--;
  const trimmed = buf.subarray(0, end);

  if (trimmed.length === 0) {
    return { format: "empty", raw_hex: rawHex };
  }

  const firstByte = trimmed[0]!;

  // ZAP1 memo: first byte is a known type
  if (firstByte in ZAP1_TYPES) {
    const typeName = ZAP1_TYPES[firstByte]!;
    const payload = trimmed.subarray(1);

    // Text types decode as UTF-8
    if (firstByte <= 0x02 || firstByte === 0x0d || firstByte === 0x0e || firstByte === 0x0f) {
      return {
        format: "zap1",
        type_byte: firstByte,
        type_name: typeName,
        text: payload.toString("utf-8"),
        raw_hex: rawHex,
      };
    }

    return {
      format: "zap1",
      type_byte: firstByte,
      type_name: typeName,
      text: payload.toString("hex"),
      raw_hex: rawHex,
    };
  }

  // ZIP 302: starts with 0xF6 prefix
  if (firstByte === 0xf6) {
    return {
      format: "zip302",
      text: trimmed.subarray(1).toString("utf-8"),
      raw_hex: rawHex,
    };
  }

  // Plain UTF-8 text (printable ASCII range check on first bytes)
  if (firstByte >= 0x20 && firstByte < 0x7f) {
    return {
      format: "text",
      text: trimmed.toString("utf-8"),
      raw_hex: rawHex,
    };
  }

  return {
    format: "binary",
    raw_hex: rawHex,
  };
}

export function registerMemoTool(server: McpServer) {
  server.tool(
    "decode_memo",
    "Decode a Zcash shielded memo field. Handles ZAP1 typed memos, ZIP 302, plain text, and raw binary.",
    {
      memo: z.string().max(2048).describe("Memo data as hex string or base64 (max 1024 bytes decoded)"),
    },
    async ({ memo }) => {
      try {
        const result = decodeMemo(memo);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
          content: [{ type: "text" as const, text: `Error: ${msg}` }],
          isError: true,
        };
      }
    }
  );
}
