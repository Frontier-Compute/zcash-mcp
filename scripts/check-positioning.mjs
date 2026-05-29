import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const canonical =
  "ZAP1 is an attestation and proof rail for Zcash workflows. Frontier Compute maintains the reference ZAP1 implementation.";
const trustBoundary =
  "A wrapper makes you trust the server. ZAP1 makes the server unnecessary to trust.";

const requiredFiles = [
  "README.md",
  "docs/zap1-proof-rail.md",
  "docs/zap1-conformance.md",
  "docs/external-rail-receipts.md",
  "docs/receipt-disclosure-profiles.md",
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

const bannedPatterns = [
  /\bTEE\b/i,
  /\benclave\b/i,
  /\bpermissioned shard\b/i,
  /\bvalidator-attested\b/i,
  /\bconfidential by default\b/i,
  /\bany chain\b/i,
  /\bHIP-4\b/i,
  /\bPolymarket\b/i,
  /\bNEAR Intents\b/i,
  /\bUniversal Send\b/i,
  /\bZipher\b/i,
  /\bAtmosphere Labs\b/i,
  /\bHyperliquid\b/i,
  /\bHYPE\b/,
  /\bKenbak\b/i,
  /\ba16z\b/i,
  /\binvestor\b/i,
  /\bdockstation\b/i,
  /\bshielded yield\b/i,
  /\bprivate yield\b/i,
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

  if (!normalizedText.includes(trustBoundary) && ![".well-known/mcp.json", "server.json"].includes(file)) {
    console.error(`${file}: missing canonical ZAP1 trust-boundary line`);
    failed = true;
  }

  for (const phrase of banned) {
    if (text.includes(phrase)) {
      console.error(`${file}: banned positioning phrase found: ${phrase}`);
      failed = true;
    }
  }

  for (const pattern of bannedPatterns) {
    if (pattern.test(text)) {
      console.error(`${file}: banned category-drift pattern found: ${pattern}`);
      failed = true;
    }
  }
}

const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const indexText = fs.readFileSync(path.join(root, "src/index.ts"), "utf8");
const readmeText = fs.readFileSync(path.join(root, "README.md"), "utf8");
const wellKnown = JSON.parse(fs.readFileSync(path.join(root, ".well-known/mcp.json"), "utf8"));
const serverJson = JSON.parse(fs.readFileSync(path.join(root, "server.json"), "utf8"));
const gitignoreText = fs.readFileSync(path.join(root, ".gitignore"), "utf8");

if (!indexText.includes(`version: "${pkg.version}"`)) {
  console.error(`src/index.ts: server version must match package.json version ${pkg.version}`);
  failed = true;
}

if (wellKnown.version !== pkg.version) {
  console.error(`.well-known/mcp.json: version must match package.json version ${pkg.version}`);
  failed = true;
}

if (serverJson.version !== pkg.version) {
  console.error(`server.json: version must match package.json version ${pkg.version}`);
  failed = true;
}

for (const npmPackage of serverJson.packages ?? []) {
  if (npmPackage.identifier === pkg.name && npmPackage.version !== pkg.version) {
    console.error(`server.json: package version for ${pkg.name} must match package.json version ${pkg.version}`);
    failed = true;
  }
}

for (const tool of wellKnown.tools ?? []) {
  if (!readmeText.includes(`| \`${tool}\` |`)) {
    console.error(`README.md: missing tool table row for ${tool}`);
    failed = true;
  }
}

if (!indexText.includes(`(${wellKnown.tools.length} tools)`)) {
  console.error(`src/index.ts: startup tool count must match .well-known/mcp.json (${wellKnown.tools.length})`);
  failed = true;
}

if (!gitignoreText.split(/\r?\n/).includes(".npmrc")) {
  console.error(".gitignore: .npmrc must be ignored");
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
