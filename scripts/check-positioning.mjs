import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const canonical =
  "ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute maintains the reference ZAP1 implementation.";

const requiredFiles = [
  "README.md",
  "docs/zap1-proof-rail.md",
  "docs/zap1-conformance.md",
  ".well-known/mcp.json",
  "server.json",
  "src/tools/capabilities.ts",
];

const banned = [
  "reference MCP implementation",
  "reference MCP surface",
  "Frontier Compute builds the proof layer for private Zcash workflows",
  "Frontier is the proof layer of private digital money",
  "What ZAP1 Owns",
  "ZAP1 owns receipts",
  "owned here",
  "not owned here",
];

let failed = false;

function normalize(text) {
  return text.replace(/\s+/g, " ").trim();
}

for (const file of requiredFiles) {
  const absolute = path.join(root, file);
  const text = fs.readFileSync(absolute, "utf8");
  const normalizedText = normalize(text);

  if (!normalizedText.includes(canonical) && ![".well-known/mcp.json", "server.json"].includes(file)) {
    console.error(`${file}: missing canonical ZAP1 positioning line`);
    failed = true;
  }

  for (const phrase of banned) {
    if (text.includes(phrase)) {
      console.error(`${file}: banned positioning phrase found: ${phrase}`);
      failed = true;
    }
  }
}

const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const indexText = fs.readFileSync(path.join(root, "src/index.ts"), "utf8");
if (!indexText.includes(`version: "${pkg.version}"`)) {
  console.error(`src/index.ts: server version must match package.json version ${pkg.version}`);
  failed = true;
}

for (const file of [
  "schemas/zap1-receipt-v1.schema.json",
  "examples/operator-lifecycle-receipt.json",
  "examples/payment-receipt.json",
]) {
  if (!fs.existsSync(path.join(root, file))) {
    console.error(`${file}: required ZAP1 conformance artifact missing`);
    failed = true;
  }
}

if (failed) {
  process.exit(1);
}

console.log("positioning ok");
