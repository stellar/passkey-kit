# Operations backlog

Last reviewed: 2026-11-27 (against `main`, `passkey-kit@0.20.1`).

Open release, test, and deploy tasks that are not code changes. Each item says
how to check it and when it is done. Remove an item when it is done, and put
its evidence (date, commit, tx hashes, deployment id) in the commit message.

## 1. Reconnect Cloudflare Pages Git integration for `passkey-kit-demo`

- **What:** the Cloudflare Pages project `passkey-kit-demo` is still linked to
  the archived `kalepail/passkey-kit` repository, so pushes to
  `stellar/passkey-kit` do not trigger automatic Git builds. The live
  production site (`https://passkey-kit-demo.pages.dev`) was manually deployed
  from current `main` on 2026-11-27, so it serves current `0.20.0+` code, but
  automatic push-to-deploy remains unlinked.
- **How:** in the Cloudflare Dashboard, authorize the Cloudflare GitHub App on
  the `stellar` org and reconnect `passkey-kit-demo` to `stellar/passkey-kit`
  (production branch `main`).
- **Done when:** a push to `stellar/passkey-kit` `main` automatically starts a
  Cloudflare Pages production build.

*(Completed on 2026-11-27: full testnet browser E2E audit across all 13 layers
10–51 with zero skips on contract `CASNSHIXMHVNCLX4KWTLT55OKZERSPDP5YHPVE5LYDWY4HHUJFPP4VBK`
— deploy tx `4fa12b551b2c23002babd8f5be8bf95d363fb9d9792647533b22990ef147b0b9`,
transfer tx `f99fdd7f7dab477d28b19ed7134767e46aece0fc847b778a06cecdbb2a19a86e`;
testnet `passkey-kit-relayer-proxy` redeployed from current `main`; live
`passkey-kit-demo` deployed via Wrangler Pages; and `contracts-legacy`
Dependabot freeze confirmed with 0 new legacy Cargo PRs and all 9 frozen alerts
classified in `SECURITY.md`.)*
