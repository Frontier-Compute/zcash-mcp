import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));
const manifestRelativePath = "examples/insight-zap1-receiver-v1/SOURCE-MANIFEST.json";

async function json(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await listFiles(absolute)));
    else if (entry.isFile() || entry.isSymbolicLink()) files.push(absolute);
  }
  return files;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function manifestPath(repositoryRoot, absolute) {
  return path.relative(repositoryRoot, absolute).replaceAll(path.sep, "/");
}

function canonicalTextBytes(bytes) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return Buffer.from(text.replaceAll("\r\n", "\n").replaceAll("\r", "\n"), "utf8");
}

export async function verifySourceManifest() {
  const manifestFile = path.join(packageDirectory, "SOURCE-MANIFEST.json");
  const manifest = await json(manifestFile);
  assert.equal(manifest.schema, "frontier-compute.insight-zap1-source-manifest.v3");
  assert.equal(manifest.hash_algorithm, "sha256");
  assert.equal(manifest.raw_byte_sha256_controlling, true);
  assert.equal(manifest.canonical_text_sha256_role, "secondary portability cross-check only");
  assert.equal(manifest.package_files_complete, true);
  assert.equal(manifest.runtime_source_files_complete, true);
  assert.deepEqual(manifest.excluded_from_self_hash, [manifestRelativePath]);
  assert.deepEqual(manifest.complete_roots, [
    "examples/insight-zap1-receiver-v1",
    "examples/insight-zap1-receiver-v2",
    "src",
    "schemas",
  ]);
  assert.deepEqual(manifest.required_root_files, [
    ".gitattributes",
    "package.json",
    "package-lock.json",
    "tsconfig.json",
  ]);

  const repositoryRoot = path.resolve(packageDirectory, manifest.repository_root_relative);
  const failures = [];
  const entriesByPath = new Map();
  for (const entry of manifest.files) {
    if (entriesByPath.has(entry.path)) {
      failures.push({ path: entry.path, error: "duplicate_manifest_path" });
      continue;
    }
    entriesByPath.set(entry.path, entry);
    const absolute = path.resolve(repositoryRoot, entry.path);
    const relative = path.relative(repositoryRoot, absolute);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      failures.push({ path: entry.path, error: "path_escape" });
      continue;
    }
    try {
      const metadata = await lstat(absolute);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        failures.push({ path: entry.path, error: "not_a_regular_file" });
        continue;
      }
      const bytes = await readFile(absolute);
      const actualRaw = digest(bytes);
      if (actualRaw !== entry.raw_sha256) {
        failures.push({
          path: entry.path,
          field: "raw_sha256",
          expected: entry.raw_sha256,
          actual: actualRaw,
        });
      }
      if (entry.content_type !== "text_utf8") {
        failures.push({ path: entry.path, error: "unsupported_content_type" });
        continue;
      }
      const actualCanonical = digest(canonicalTextBytes(bytes));
      if (actualCanonical !== entry.canonical_text_sha256) {
        failures.push({
          path: entry.path,
          field: "canonical_text_sha256",
          expected: entry.canonical_text_sha256,
          actual: actualCanonical,
        });
      }
    } catch (error) {
      failures.push({ path: entry.path, error: error.code ?? error.message });
    }
  }

  const excluded = new Set(manifest.excluded_from_self_hash);
  for (const root of manifest.complete_roots) {
    const absoluteRoot = path.resolve(repositoryRoot, root);
    for (const absolute of await listFiles(absoluteRoot)) {
      const relative = manifestPath(repositoryRoot, absolute);
      if (!entriesByPath.has(relative) && !excluded.has(relative)) {
        failures.push({ path: relative, error: "undeclared_complete_root_file" });
      }
    }
    for (const declared of entriesByPath.keys()) {
      if (declared === root || declared.startsWith(root + "/")) {
        const absolute = path.resolve(repositoryRoot, declared);
        try {
          const metadata = await lstat(absolute);
          if (!metadata.isFile() || metadata.isSymbolicLink()) {
            failures.push({ path: declared, error: "declared_complete_root_file_not_regular" });
          }
        } catch (error) {
          failures.push({ path: declared, error: error.code ?? error.message });
        }
      }
    }
  }
  for (const required of manifest.required_root_files) {
    if (!entriesByPath.has(required)) failures.push({ path: required, error: "required_root_file_undeclared" });
  }

  assert.deepEqual(failures, [], JSON.stringify(failures, null, 2));
  return {
    pass: true,
    files_verified: manifest.files.length,
    raw_byte_hashes_verified: manifest.files.length,
    canonical_text_hashes_verified: manifest.files.length,
    complete_roots: manifest.complete_roots,
    manifest_scope: manifest.scope,
  };
}
