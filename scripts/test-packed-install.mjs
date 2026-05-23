import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { runMcpSmokeTest } from "./test-client.mjs";

const execFileAsync = promisify(execFile);
const npmCommand = "npm";
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

function quoteWindowsArg(arg) {
  const value = String(arg);
  return /^[A-Za-z0-9_./:\\-]+$/.test(value) ? value : `"${value.replace(/"/g, '""')}"`;
}

async function run(command, args, options) {
  const execCommand = process.platform === "win32" ? process.env.ComSpec ?? "cmd.exe" : command;
  const execArgs =
    process.platform === "win32"
      ? ["/d", "/s", "/c", [command, ...args.map(quoteWindowsArg)].join(" ")]
      : args;

  return execFileAsync(execCommand, execArgs, {
    maxBuffer: 10 * 1024 * 1024,
    ...options,
  });
}

const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "zcash-mcp-pack-"));
const npmCache = path.join(tempRoot, "npm-cache");
let tarballPath;

try {
  const pack = await run(npmCommand, ["pack", "--json"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      npm_config_cache: npmCache,
    },
  });

  const [{ filename }] = JSON.parse(pack.stdout);
  tarballPath = path.join(repoRoot, filename);

  const projectDir = path.join(tempRoot, "install-check");
  await fs.mkdir(projectDir, { recursive: true });
  await fs.writeFile(
    path.join(projectDir, "package.json"),
    JSON.stringify({ name: "zcash-mcp-pack-check", private: true }, null, 2)
  );

  await run(
    npmCommand,
    ["install", "--ignore-scripts", "--no-package-lock", "--prefer-offline", tarballPath],
    {
      cwd: projectDir,
      env: {
        ...process.env,
        npm_config_cache: npmCache,
      },
    }
  );

  const installedRoot = path.join(projectDir, "node_modules", "@frontiercompute", "zcash-mcp");
  const installedPackage = JSON.parse(
    await fs.readFile(path.join(installedRoot, "package.json"), "utf8")
  );

  assert.equal(installedPackage.main, "dist/index.js", "published main entry drifted");
  await fs.access(path.join(installedRoot, "dist", "index.js"));

  await runMcpSmokeTest(path.join(installedRoot, "dist", "index.js"), {
    cwd: projectDir,
    label: "packed install",
  });

  console.log("packed install: tarball install and MCP handshake passed");
} finally {
  if (tarballPath) {
    await fs.rm(tarballPath, { force: true });
  }
  await fs.rm(tempRoot, { recursive: true, force: true });
}
