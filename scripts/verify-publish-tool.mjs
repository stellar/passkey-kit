#!/usr/bin/env node

const userAgent = process.env.npm_config_user_agent ?? "";

if (!userAgent.startsWith("pnpm/")) {
  throw new Error(
    "Publish passkey-kit with pnpm; npm CLI publication is not an approved release path."
  );
}
