import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(packageDirectory, "../..");
const manifestPath = "examples/insight-zap1-receiver-v1/SOURCE-MANIFEST.json";
const completeRoots = [
  "examples/insight-zap1-receiver-v1",
  "examples/insight-zap1-receiver-v2",
  "src",
  "schemas",
];
const requiredRootFiles = [
  ".gitattributes",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
];

async function listFiles(relativeDirectory) {
  const absoluteDirectory = path.resolve(repositoryRoot, ...relativeDirectory.split("/"));
  const entries = await readdir(absoluteDirectory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relative = relativeDirectory + "/" + entry.name;
    if (entry.isDirectory()) files.push(...await listFiles(relative));
    else if (entry.isFile()) files.push(relative);
    else throw new Error(`non-regular manifest input ${relative}`);
  }
  return files;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalTextBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return Buffer.from(text.replaceAll("\r\n", "\n").replaceAll("\r", "\n"), "utf8");
}

function roleFor(file) {
  if (file === ".gitattributes") return "repository line-ending policy";
  if (file === "package.json") return "root runtime and test contract";
  if (file === "package-lock.json") return "exact dependency resolution";
  if (file === "tsconfig.json") return "TypeScript build configuration";
  if (file.startsWith("src/")) return "complete MCP runtime source";
  if (file.startsWith("schemas/")) return "complete MCP schema closure";
  return "complete receiver package file";
}

const files = new Set(requiredRootFiles);
for (const root of completeRoots) {
  for (const file of await listFiles(root)) files.add(file);
}
files.delete(manifestPath);

const entries = [];
for (const file of [...files].sort((left, right) => left.localeCompare(right, "en"))) {
  const bytes = await readFile(path.resolve(repositoryRoot, ...file.split("/")));
  entries.push({
    path: file,
    role: roleFor(file),
    content_type: "text_utf8",
    raw_sha256: digest(bytes),
    canonical_text_sha256: digest(canonicalTextBytes(bytes)),
  });
}

const manifest = {
  schema: "frontier-compute.insight-zap1-source-manifest.v3",
  hash_algorithm: "sha256",
  raw_byte_sha256_controlling: true,
  canonical_text_sha256_role: "secondary portability cross-check only",
  scope: "all files in the v1 and v2-v3 receiver references and the complete MCP src and schemas closures, plus exact root dependency and build contracts",
  repository_root_relative: "../..",
  package_files_complete: true,
  runtime_source_files_complete: true,
  complete_roots: completeRoots,
  required_root_files: requiredRootFiles,
  excluded_from_self_hash: [manifestPath],
  files: entries,
};

await writeFile(
  path.join(repositoryRoot, manifestPath),
  JSON.stringify(manifest) + "\n",
  "utf8",
);
console.log(JSON.stringify({ generated: manifestPath, files: entries.length }));
