# Legacy-line smart wallet. Separate workspace from ../contracts (v1).
#
# out/smart_wallet.wasm is the CANONICAL artifact and is committed. Its sha256
# is the published upgrade-target hash. It was built with the toolchain in
# ./rust-toolchain.toml (Rust 1.89, wasm32v1-none) and stellar CLI 27.1.0 on
# macOS aarch64. `stellar contract build` remaps source paths, but rustc's
# wasm codegen still differs between host platforms, so another host produces
# a functionally equivalent artifact with a different hash. Do not overwrite
# out/ unless you intend to publish a new canonical hash.

WASM = out/smart_wallet.wasm
CANONICAL_SHA256 = c079d3a4136eb6ca68eb724acd3d8af11b0be4a0ed82605925a6dfd4dd83a97c

.PHONY: build verify test fmt clean

# Rebuilds the artifact in place. Compare with `make verify` afterwards.
build:
	stellar contract build --locked --package smart-wallet --out-dir out

# Asserts the committed artifact is the canonical one.
verify:
	@echo "$(CANONICAL_SHA256)  $(WASM)" | shasum -a 256 -c -

# The end-to-end tests upgrade real pre-fix wallets (the mainnet WASM under
# smart-wallet/src/tests/fixtures) to the committed canonical artifact.
test: verify
	cargo test --locked -p smart-wallet -- --nocapture

fmt:
	cargo fmt --all

clean:
	cargo clean
