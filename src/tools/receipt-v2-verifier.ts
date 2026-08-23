import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";

const HEX_64 = /^[0-9a-fA-F]{64}$/;
const MASK_64 = (1n << 64n) - 1n;
const encoder = new TextEncoder();

const IV = [
  0x6a09e667f3bcc908n,
  0xbb67ae8584caa73bn,
  0x3c6ef372fe94f82bn,
  0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n,
  0x9b05688c2b3e6c1fn,
  0x1f83d9abfb41bd6bn,
  0x5be0cd19137e2179n,
] as const;

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
] as const;

const receiptProfile = z.enum([
  "public_hash_only",
  "counterparty_receipt",
  "auditor_packet",
  "operator_internal",
  "grant_proof_packet",
  "compliance_audit_packet",
]);

const redactionPolicy = z.enum([
  "hash_only",
  "counterparty_visible",
  "auditor_visible",
  "operator_private",
  "grant_public",
  "compliance_limited",
]);

const IntegrationReceiptV2Schema = z
  .object({
    schema_version: z.literal("zap1-receipt-v2"),
    event_type: z.literal("AGENT_ACTION"),
    profile: receiptProfile.optional(),
    subject_hash: z.string().regex(HEX_64, "subject_hash must be 64-char hex"),
    claim_hash: z.string().regex(HEX_64, "claim_hash must be 64-char hex"),
    evidence_hash: z.string().regex(HEX_64, "evidence_hash must be 64-char hex"),
    leaf: z
      .object({
        hash: z.string().regex(HEX_64, "leaf.hash must be 64-char hex"),
        event_type: z.literal("AGENT_ACTION"),
        agent_id: z.string().regex(HEX_64, "leaf.agent_id must be a 64-char hash"),
        action_type: z.string().min(1).max(64),
        input_hash: z.string().regex(HEX_64, "leaf.input_hash must be 64-char hex"),
        output_hash: z.string().regex(HEX_64, "leaf.output_hash must be 64-char hex"),
      })
      .strict(),
    proof: z
      .array(
        z
          .object({
            hash: z.string().regex(HEX_64, "proof hash must be 64-char hex"),
            position: z.enum(["left", "right"]),
          })
          .strict()
      )
      .max(64),
    root: z
      .object({
        hash: z.string().regex(HEX_64, "root.hash must be 64-char hex"),
        leaf_count: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        scheme: z.literal("ZAP1_COUNT_BOUND_V2"),
      })
      .strict(),
    anchor: z
      .object({
        txid: z.string().regex(HEX_64, "anchor.txid must be 64-char hex"),
        height: z.number().int().positive(),
      })
      .strict()
      .optional(),
    status: z.string().min(1).max(64).optional(),
    disclosed_fields: z.array(z.string().min(1).max(64)).optional(),
    redaction_policy: redactionPolicy.optional(),
  })
  .strict();

const AgentActionWitnessSchema = z
  .object({
    event_type: z.literal("AGENT_ACTION"),
    agent_id: z.string().min(1).max(128),
    action_type: z.string().min(1).max(64),
    input_hash: z.string().min(1).max(128),
    output_hash: z.string().min(1).max(128),
  })
  .strict();

const OfficialProofBundleV2Schema = z
  .object({
    protocol: z.literal("ZAP1"),
    version: z.literal("2"),
    leaf: z
      .object({
        hash: z.string().regex(HEX_64, "leaf.hash must be 64-char hex"),
        event_type: z.literal("AGENT_ACTION"),
        created_at: z.string().min(1).max(128),
        preimage_disclosure: z.literal("withheld from the public proof bundle"),
        event_type_authentication: z.literal("unverified_server_metadata_without_disclosed_witness"),
      })
      .strict(),
    proof: z
      .array(
        z
          .object({
            hash: z.string().regex(HEX_64, "proof hash must be 64-char hex"),
            position: z.enum(["left", "right"]),
          })
          .strict()
      )
      .max(64),
    root: z
      .object({
        hash: z.string().regex(HEX_64, "root.hash must be 64-char hex"),
        leaf_count: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        created_at: z.string().min(1).max(128),
        scheme: z.literal("ZAP1_COUNT_BOUND_V2"),
        legacy_allowed: z.literal(false),
        legacy_max_anchor_height: z.number().int().nonnegative(),
      })
      .strict(),
    anchor: z
      .object({
        txid: z.string().regex(HEX_64, "anchor.txid must be 64-char hex").nullable(),
        height: z.number().int().positive().nullable(),
      })
      .strict()
      .optional(),
    verify_command: z.string().min(1).max(256).optional(),
  })
  .strict();

function readU64Le(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  return value;
}

function writeU64Le(value: bigint, output: Uint8Array, offset: number): void {
  for (let i = 0; i < 8; i += 1) {
    output[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
  }
}

function rotateRight(value: bigint, bits: bigint): bigint {
  return ((value >> bits) | (value << (64n - bits))) & MASK_64;
}

function mix(v: bigint[], a: number, b: number, c: number, d: number, x: bigint, y: bigint): void {
  v[a] = (v[a] + v[b] + x) & MASK_64;
  v[d] = rotateRight(v[d] ^ v[a], 32n);
  v[c] = (v[c] + v[d]) & MASK_64;
  v[b] = rotateRight(v[b] ^ v[c], 24n);
  v[a] = (v[a] + v[b] + y) & MASK_64;
  v[d] = rotateRight(v[d] ^ v[a], 16n);
  v[c] = (v[c] + v[d]) & MASK_64;
  v[b] = rotateRight(v[b] ^ v[c], 63n);
}

function personalization(label: string): Uint8Array {
  const bytes = encoder.encode(label);
  if (bytes.length > 16) {
    throw new Error(`BLAKE2b personalization exceeds 16 bytes: ${label}`);
  }
  const result = new Uint8Array(16);
  result.set(bytes);
  return result;
}

function blake2b256(input: Uint8Array, personalLabel: string): Uint8Array {
  const params = new Uint8Array(64);
  params[0] = 32;
  params[2] = 1;
  params[3] = 1;
  params.set(personalization(personalLabel), 48);

  const h = IV.map((word, index) => word ^ readU64Le(params, index * 8));
  const blockCount = Math.max(1, Math.ceil(input.length / 128));
  let total = 0n;

  for (let blockIndex = 0; blockIndex < blockCount; blockIndex += 1) {
    const start = blockIndex * 128;
    const chunk = input.subarray(start, Math.min(start + 128, input.length));
    const block = new Uint8Array(128);
    block.set(chunk);
    total += BigInt(chunk.length);

    const m = Array.from({ length: 16 }, (_, index) => readU64Le(block, index * 8));
    const v = [...h, ...IV];
    v[12] ^= total & MASK_64;
    v[13] ^= total >> 64n;
    if (blockIndex === blockCount - 1) {
      v[14] ^= MASK_64;
    }

    for (let round = 0; round < 12; round += 1) {
      const s = SIGMA[round];
      mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
      mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
      mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
      mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
      mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
      mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
      mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
      mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (let i = 0; i < 8; i += 1) {
      h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK_64;
    }
  }

  const digest = new Uint8Array(32);
  for (let i = 0; i < 4; i += 1) {
    writeU64Le(h[i], digest, i * 8);
  }
  return digest;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u16Be(value: number): Uint8Array {
  if (value > 0xffff) {
    throw new Error("AGENT_ACTION field exceeds the u16 length prefix");
  }
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function u64Be(value: number): Uint8Array {
  let remaining = BigInt(value);
  const output = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) {
    output[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function lengthPrefixed(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concatBytes(u16Be(bytes.length), bytes);
}

function fromHex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function computeAgentActionLeafHex(
  agentId: string,
  actionType: string,
  inputHash: string,
  outputHash: string
): string {
  const preimage = concatBytes(
    Uint8Array.of(0x42),
    lengthPrefixed(agentId),
    lengthPrefixed(actionType),
    lengthPrefixed(inputHash),
    lengthPrefixed(outputHash)
  );
  return toHex(blake2b256(preimage, "NordicShield_"));
}

function computeNodeHex(left: string, right: string): string {
  return toHex(blake2b256(concatBytes(fromHex(left), fromHex(right)), "NordicShield_MRK"));
}

export function computeCountBoundRootHex(rawRoot: string, leafCount: number): string {
  const preimage = concatBytes(Uint8Array.of(0x01), u64Be(leafCount), fromHex(rawRoot));
  return toHex(blake2b256(preimage, "NordicShield_RTK"));
}

export function registerReceiptV2VerifierTool(server: McpServer) {
  server.tool(
    "zap1_verify_receipt_v2",
    "Cryptographically verify either an integration receipt-v2 or the official ZAP1 proof-bundle-v2 plus its separately retained AGENT_ACTION witness. Anchor metadata is never treated as chain confirmation.",
    {
      receipt: z.unknown().optional().describe("Strict integration zap1-receipt-v2 AGENT_ACTION packet."),
      proof_bundle: z
        .unknown()
        .optional()
        .describe("Official /verify/{leaf}/proof.json version-2 bundle. Supply agent_action_witness with it."),
      agent_action_witness: AgentActionWitnessSchema.optional().describe(
        "Separately retained typed preimage fields; the public proof endpoint intentionally withholds them."
      ),
      expected_agent_id: z.string().min(1).max(128).optional(),
      expected_action_type: z.string().min(1).max(64).optional(),
      expected_input_hash: z.string().min(1).max(128).optional(),
      expected_output_hash: z.string().min(1).max(128).optional(),
    },
    async ({
      receipt,
      proof_bundle,
      agent_action_witness,
      expected_agent_id,
      expected_action_type,
      expected_input_hash,
      expected_output_hash,
    }) => {
      const integrationMode = receipt !== undefined;
      const officialMode = proof_bundle !== undefined || agent_action_witness !== undefined;
      if (integrationMode === officialMode) {
        const result = {
          valid: false,
          schema_valid: false,
          typed_leaf_valid: false,
          binding_valid: false,
          proof_topology_valid: false,
          cryptographic_inclusion_valid: false,
          anchor_reference_present: false,
          anchor_confirmed: false,
          acceptance_ready: false,
          status: "malformed",
          errors: [
            {
              path: "input",
              message:
                "Supply exactly one mode: receipt, or proof_bundle together with agent_action_witness.",
            },
          ],
        };
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
          isError: true,
        };
      }

      let sourceFormat: "integration_receipt_v2" | "official_proof_bundle_v2_with_witness";
      let leafHash: string;
      let witness: z.infer<typeof AgentActionWitnessSchema>;
      let proof: { hash: string; position: "left" | "right" }[];
      let root: { hash: string; leaf_count: number; scheme: "ZAP1_COUNT_BOUND_V2" };
      let anchor: { txid: string; height: number } | undefined;
      let claimedStatus: string | null = null;
      let normalizedReceipt: Record<string, unknown>;
      const bindingMismatches: string[] = [];

      if (officialMode) {
        const bundleParsed = OfficialProofBundleV2Schema.safeParse(proof_bundle);
        const witnessParsed = AgentActionWitnessSchema.safeParse(agent_action_witness);
        if (!bundleParsed.success || !witnessParsed.success) {
          const errors = [
            ...(!bundleParsed.success
              ? bundleParsed.error.issues.map((issue) => ({
                  path: `proof_bundle.${issue.path.join(".")}`,
                  message: issue.message,
                }))
              : []),
            ...(!witnessParsed.success
              ? witnessParsed.error.issues.map((issue) => ({
                  path: `agent_action_witness.${issue.path.join(".")}`,
                  message: issue.message,
                }))
              : []),
          ];
          const result = {
            valid: false,
            schema_valid: false,
            typed_leaf_valid: false,
            binding_valid: false,
            proof_topology_valid: false,
            cryptographic_inclusion_valid: false,
            anchor_reference_present: false,
            anchor_confirmed: false,
            acceptance_ready: false,
            status: "malformed",
            errors,
          };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
            isError: true,
          };
        }

        const bundle = bundleParsed.data;
        const hasAnchorTxid = bundle.anchor?.txid !== null && bundle.anchor?.txid !== undefined;
        const hasAnchorHeight = bundle.anchor?.height !== null && bundle.anchor?.height !== undefined;
        if (hasAnchorTxid !== hasAnchorHeight) {
          const result = {
            valid: false,
            schema_valid: false,
            typed_leaf_valid: false,
            binding_valid: false,
            proof_topology_valid: false,
            cryptographic_inclusion_valid: false,
            anchor_reference_present: false,
            anchor_confirmed: false,
            acceptance_ready: false,
            status: "malformed",
            errors: [
              {
                path: "proof_bundle.anchor",
                message: "anchor txid and height must either both be null/omitted or both be present",
              },
            ],
          };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
            isError: true,
          };
        }

        sourceFormat = "official_proof_bundle_v2_with_witness";
        leafHash = bundle.leaf.hash;
        witness = witnessParsed.data;
        proof = bundle.proof;
        root = bundle.root;
        anchor =
          hasAnchorTxid && hasAnchorHeight
            ? { txid: bundle.anchor!.txid!, height: bundle.anchor!.height! }
            : undefined;
        normalizedReceipt = {
          schema_version: "zap1-receipt-v2",
          protocol: bundle.protocol,
          version: bundle.version,
          server_leaf: bundle.leaf,
          agent_action_witness: witness,
          proof: bundle.proof,
          root: bundle.root,
          ...(anchor ? { anchor } : {}),
        };
      } else {
        const parsed = IntegrationReceiptV2Schema.safeParse(receipt);
        if (!parsed.success) {
          const result = {
            valid: false,
            schema_valid: false,
            typed_leaf_valid: false,
            binding_valid: false,
            proof_topology_valid: false,
            cryptographic_inclusion_valid: false,
            anchor_reference_present: false,
            anchor_confirmed: false,
            acceptance_ready: false,
            status: "malformed",
            errors: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
          };
          return {
            content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
            isError: true,
          };
        }

        const value = parsed.data;
        sourceFormat = "integration_receipt_v2";
        leafHash = value.leaf.hash;
        witness = {
          event_type: value.leaf.event_type,
          agent_id: value.leaf.agent_id,
          action_type: value.leaf.action_type,
          input_hash: value.leaf.input_hash,
          output_hash: value.leaf.output_hash,
        };
        proof = value.proof;
        root = value.root;
        anchor = value.anchor;
        claimedStatus = value.status ?? null;
        normalizedReceipt = value;
        bindingMismatches.push(
          ...(value.subject_hash.toLowerCase() !== value.leaf.agent_id.toLowerCase()
            ? ["subject_hash != leaf.agent_id"]
            : []),
          ...(value.claim_hash.toLowerCase() !== value.leaf.input_hash.toLowerCase()
            ? ["claim_hash != leaf.input_hash"]
            : []),
          ...(value.evidence_hash.toLowerCase() !== value.leaf.output_hash.toLowerCase()
            ? ["evidence_hash != leaf.output_hash"]
            : [])
        );
      }

      bindingMismatches.push(
        ...(expected_agent_id && expected_agent_id !== witness.agent_id
          ? ["agent_id did not match expected_agent_id"]
          : []),
        ...(expected_action_type && expected_action_type !== witness.action_type
          ? ["action_type did not match expected_action_type"]
          : []),
        ...(expected_input_hash && expected_input_hash !== witness.input_hash
          ? ["input_hash did not match expected_input_hash"]
          : []),
        ...(expected_output_hash && expected_output_hash !== witness.output_hash
          ? ["output_hash did not match expected_output_hash"]
          : [])
      );

      const computedLeafHash = computeAgentActionLeafHex(
        witness.agent_id,
        witness.action_type,
        witness.input_hash,
        witness.output_hash
      );
      const typedLeafValid = computedLeafHash === leafHash.toLowerCase();
      const bindingValid = bindingMismatches.length === 0;

      const maxDepth = Math.ceil(Math.log2(root.leaf_count));
      const proofTopologyValid =
        (root.leaf_count === 1 ? proof.length === 0 : proof.length > 0) && proof.length <= maxDepth;

      let rawRoot = computedLeafHash;
      for (const sibling of proof) {
        rawRoot =
          sibling.position === "left"
            ? computeNodeHex(sibling.hash.toLowerCase(), rawRoot)
            : computeNodeHex(rawRoot, sibling.hash.toLowerCase());
      }
      const computedRootHash = computeCountBoundRootHex(rawRoot, root.leaf_count);
      const rootValid = computedRootHash === root.hash.toLowerCase();
      const inclusionValid = typedLeafValid && bindingValid && proofTopologyValid && rootValid;
      const anchorReferencePresent = anchor !== undefined;
      const result = {
        valid: inclusionValid,
        schema_valid: true,
        source_format: sourceFormat,
        typed_leaf_valid: typedLeafValid,
        typed_witness_authenticated: typedLeafValid,
        binding_valid: bindingValid,
        proof_topology_valid: proofTopologyValid,
        root_valid: rootValid,
        cryptographic_inclusion_valid: inclusionValid,
        computed: {
          leaf_hash: computedLeafHash,
          raw_merkle_root: rawRoot,
          count_bound_root: computedRootHash,
        },
        claimed: {
          leaf_hash: leafHash.toLowerCase(),
          root_hash: root.hash.toLowerCase(),
          status: claimedStatus,
        },
        normalized_receipt: normalizedReceipt,
        mismatches: [
          ...bindingMismatches,
          ...(!typedLeafValid ? ["leaf.hash did not match the typed AGENT_ACTION preimage"] : []),
          ...(!proofTopologyValid ? ["proof length is impossible for the declared leaf_count"] : []),
          ...(!rootValid ? ["root.hash did not match the positioned, count-bound Merkle proof"] : []),
        ],
        anchor_reference_present: anchorReferencePresent,
        anchor_reference: anchor ?? null,
        anchor_confirmed: false,
        acceptance_ready: false,
        status: inclusionValid
          ? anchorReferencePresent
            ? "included_anchor_unverified"
            : "included_unanchored"
          : "invalid",
        warnings: [
          "Anchor confirmation is deliberately false: txid, height, and claimed status are metadata, not a Zcash anchor-opening proof.",
          "Acceptance remains false until a separate verifier checks a complete anchor-opening artifact against independently sourced chain state.",
        ],
        boundary:
          "This tool authenticates the separately supplied AGENT_ACTION witness against the official bundle leaf and verifies count-bound Merkle inclusion. It does not confirm that the root was committed on Zcash.",
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
        isError: !inclusionValid,
      };
    }
  );
}
