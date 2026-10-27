# Operations backlog

Last reviewed: 2026-10-27 (against `main` at `c6dab0a`, `passkey-kit@0.20.0`).

Open release, test, and deploy tasks that are not code changes. Each item says
how to check it and when it is done. Remove an item when it is done, and put
its evidence (date, commit, tx hashes, deployment id) in the commit message.

## 1. Run the testnet browser e2e against 0.20.0

- **What:** 0.20.0 changed how `signAdmin` signs `addSigner`, `updateSigner`,
  `removeSigner`, and `addPolicy`. Its unit tests use a stubbed RPC. No
  testnet browser run against 0.20.0 is recorded.
- **How:** build the SDK and the demo, serve the demo locally, then run
  `pnpm run e2e:audit` from `demo/`
  ([`testnet-passkey-smoke.sh`](../scripts/e2e/testnet-passkey-smoke.sh)).
  Layers 40–45 (add-secp, add-ed25519, add-policy, update, per-signer
  transfer, remove) cover the changed path. A skipped layer is not a pass.
- **Done when:** a full run passes on a commit that contains 0.20.0. Do this
  before item 2.

## 2. Reconnect and redeploy the demo

- **What:** the Cloudflare Pages project `passkey-kit-demo` is still linked to
  the archived `kalepail/passkey-kit` repository. Pushes to
  `stellar/passkey-kit` do not start a build. The last production deploy is
  `95b60c1` (0.17.1) on 2026-09-01, so the live demo does not include
  0.18.0–0.20.0. The contract hash in `demo/.env.production` is current.
- **How:** link the Pages project to `stellar/passkey-kit` (production branch
  `main`). This needs the Cloudflare GitHub app on the `stellar` org. A manual
  deploy (`pnpm run deploy:demo:prod`) updates the site but does not fix the
  link.
- **Done when:** a push to `main` starts a Pages build, and the live
  production deployment comes from current `main`.

## 3. Redeploy the testnet relayer-proxy worker

- **What:** `passkey-kit-relayer-proxy` was last deployed on 2026-09-01. Its
  `src/` and `wrangler.toml` have not changed since, but `a345699` moved
  `@openzeppelin/relayer-plugin-channels` from 0.20 to 0.21 and dropped the
  `sharp`/`toml` overrides. The live worker still bundles the old tree.
- **How:** `cd relayer-proxy && pnpm deploy` (testnet only). Do not deploy
  `--env production`; there is no mainnet relayer by policy.
- **Done when:** the worker's latest deployment is built from current `main`,
  and the demo can still fund and transfer through it (item 1, layers 30–31).

## 4. Confirm the `contracts-legacy` Dependabot freeze

- **What:** [`.github/dependabot.yml`](../.github/dependabot.yml) ignores all
  Cargo updates in `/contracts-legacy`, because any lock change moves the
  upgrade-target hash (see `SECURITY.md`, "Legacy line"). No Dependabot run has
  happened since the rule merged.
- **How:** after the next Dependabot run, check that it opened no
  `contracts-legacy` PR. Close any such PR; do not merge it.
- **Done when:** one Dependabot run completes with no new `contracts-legacy` PR.
