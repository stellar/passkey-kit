#!/usr/bin/env node

import { readFile } from "node:fs/promises";

const readJson = async (path) =>
  JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));

const rootManifest = await readJson("../package.json");
const bindingManifests = await Promise.all([
  readJson("../packages/passkey-kit-sdk/package.json"),
  readJson("../packages/sac-sdk/package.json"),
]);

for (const bindingManifest of bindingManifests) {
  const dependencyVersion = rootManifest.dependencies?.[bindingManifest.name];

  if (dependencyVersion !== bindingManifest.version) {
    throw new Error(
      `${bindingManifest.name} must use exact version ${bindingManifest.version} in package.json; found ${dependencyVersion ?? "no dependency"}.`
    );
  }
}
