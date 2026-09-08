#!/usr/bin/env node

import { rm } from "node:fs/promises";
import { basename, resolve } from "node:path";

const target = resolve(process.cwd(), "dist");
if (basename(target) !== "dist") {
  throw new Error(`Refusing to remove unexpected build directory: ${target}`);
}

await rm(target, { recursive: true, force: true });
