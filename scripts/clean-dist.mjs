#!/usr/bin/env node

import { rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(process.cwd(), "dist");
const allowedTargets = new Set([
  resolve(repositoryRoot, "dist"),
  resolve(repositoryRoot, "packages/passkey-kit-sdk/dist"),
  resolve(repositoryRoot, "packages/sac-sdk/dist"),
]);

if (!allowedTargets.has(target)) {
  throw new Error(`Refusing to remove unexpected build directory: ${target}`);
}

await rm(target, { recursive: true, force: true });
