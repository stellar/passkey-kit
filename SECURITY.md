# Security Policy

## Security status

The smart-wallet contract, SDKs, and repository relayer proxy have not received an independent third-party security audit.

Tests and reviews reduce risk. They do not prove that the software has no defects.

Do not store or control assets you cannot afford to lose. Limit balances and permissions. Monitor wallets and maintain recovery and authorized upgrade paths.

## Supported versions

Only the latest npm releases and the canonical smart-wallet WASM receive security fixes.

The current deployment manifest in [`docs/`](./docs/) identifies the canonical WASM. Existing wallet instances do not upgrade automatically.

## Report a vulnerability privately

Do not open a public issue, pull request, discussion, or chat message for a suspected vulnerability.

Email `tyler@stellar.org` with the subject `passkey-kit security report`. If email is unsuitable, request a private channel without including sensitive details.

Include the affected version or commit, impact, reproduction steps, and a minimal proof of concept. Do not include secrets or personal data.

Use local tests or isolated test accounts. Do not test against public user wallets or move assets that you do not own.

The maintainers will confirm receipt, investigate the report, prepare a fix, and coordinate disclosure with the reporter.
