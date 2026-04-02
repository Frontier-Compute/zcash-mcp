import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const ZAP1_API = process.env.ZAP1_API_URL ?? "https://pay.frontiercompute.io";

export function registerAttestTool(server: McpServer) {
  server.tool(
    "attest_event",
    "Create a ZAP1 attestation. Writes a typed memo to the Zcash blockchain via the ZAP1 protocol, returning a leaf hash and Merkle proof.",
    {
      type_byte: z.number().int().min(0).max(255).describe("ZAP1 type byte (e.g. 0x03 for attestation)"),
      payload: z.string().describe("Payload string to attest"),
      api_key: z.string().optional().describe("ZAP1 API key (or set ZAP1_API_KEY env var)"),
    },
    async ({ type_byte, payload, api_key }) => {
      const key = api_key ?? process.env.ZAP1_API_KEY;
      if (!key) {
        return {
          content: [
            {
              type: "text" as const,
              text: "Error: No API key. Pass api_key or set ZAP1_API_KEY env var.",
            },
          ],
          isError: true,
        };
      }

      try {
        const res = await fetch(`${ZAP1_API}/attest`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${key}`,
          },
          body: JSON.stringify({ type_byte, payload }),
        });

        if (!res.ok) {
          const text = await res.text();
          throw new Error(`${res.status}: ${text}`);
        }

        const data = await res.json();
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(data, null, 2),
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
