# Legacy-line smart wallet. Separate workspace from ../contracts (v1).
# Requires the toolchain in ./rust-toolchain.toml (Rust 1.89, wasm32v1-none)
# and the stellar CLI (27.x). `stellar contract build` remaps source paths and
# optimizes by default, so the hash is reproducible across machines; a plain
# `cargo build` embeds absolute paths (panic locations) and is NOT.

WASM = out/smart_wallet.wasm

.PHONY: build hash test fmt clean

build:
	rm -rf out/
	stellar contract build --locked --package smart-wallet --out-dir out

hash: build
	@shasum -a 256 $(WASM)

# The end-to-end tests upgrade real pre-fix wallets (the mainnet WASM under
# smart-wallet/src/tests/fixtures) to the artifact that ships, so `build` runs first.
test: build
	cargo test --locked -p smart-wallet -- --nocapture

fmt:
	cargo fmt --all

clean:
	rm -rf out/
	cargo clean
