import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = path.dirname(fileURLToPath(import.meta.url));

async function json(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await listFiles(absolute)));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

export async function verifySourceManifest() {
  const manifestPath = path.join(packageDirectory, "SOURCE-MANIFEST.json");
  const manifest = await json(manifestPath);
  assert.equal(manifest.schema, "frontier-compute.insight-zap1-source-manifest.v1");
  assert.equal(manifest.hash_algorithm, "sha256");
  assert.deepEqual(manifest.excluded_from_self_hash, ["examples/insight-zap1-receiver-v1/SOURCE-MANIFEST.json"]);
  const repositoryRoot = path.resolve(packageDirectory, manifest.repository_root_relative);
  const failures = [];
  for (const entry of manifest.files) {
    const absolute = path.resolve(repositoryRoot, entry.path);
    const relative = path.relative(repositoryRoot, absolute);
    if (relative.startsWith("..") || path.isAbsolute(relative)) {
      failures.push({ path: entry.path, error: "path_escape" });
      continue;
    }
    try {
      const bytes = await readFile(absolute);
      const actual = createHash("sha256").update(bytes).digest("hex");
      if (actual !== entry.sha256) failures.push({ path: entry.path, expected: entry.sha256, actual });
    } catch (error) {
      failures.push({ path: entry.path, error: error.code ?? error.message });
    }
  }
  const packagePrefix = "examples/insight-zap1-receiver-v1/";
  const declared = new Set(manifest.files.filter((entry) => entry.path.startsWith(packagePrefix)).map((entry) => entry.path.replaceAll("/", path.sep)));
  const excluded = new Set(manifest.excluded_from_self_hash.map((entry) => entry.replaceAll("/", path.sep)));
  const actualPackageFiles = (await listFiles(packageDirectory)).map((absolute) => path.relative(repositoryRoot, absolute));
  for (const relative of actualPackageFiles) {
    if (!declared.has(relative) && !excluded.has(relative)) failures.push({ path: relative.replaceAll(path.sep, "/"), error: "undeclared_package_file" });
  }
  for (const relative of declared) {
    if (!actualPackageFiles.includes(relative)) failures.push({ path: relative.replaceAll(path.sep, "/"), error: "declared_package_file_missing" });
  }
  assert.deepEqual(failures, [], JSON.stringify(failures, null, 2));
  return { pass: true, files_verified: manifest.files.length, manifest_scope: manifest.scope };
}

