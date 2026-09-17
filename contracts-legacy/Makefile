# Legacy-line smart wallet. Separate workspace from ../contracts (v1).
# Requires the toolchain in ./rust-toolchain.toml (Rust 1.89, wasm32v1-none)
# and the stellar CLI for `optimize`.

WASM_DIR = target/wasm32v1-none/release
WASM     = $(WASM_DIR)/smart_wallet.wasm
OPT      = $(WASM_DIR)/smart_wallet.optimized.wasm

.PHONY: build optimize hash test clean

build:
	cargo build --locked --target wasm32v1-none --release -p smart-wallet

optimize: build
	stellar contract optimize --wasm $(WASM) --wasm-out $(OPT)

hash: optimize
	@shasum -a 256 $(OPT)

# The end-to-end tests upgrade real pre-fix wallets (the mainnet WASM under
# smart-wallet/src/tests/fixtures) to the freshly built WASM, and one of them
# uses the OPTIMIZED artifact (the bytes that ship), so `optimize` runs first.
test: optimize
	cargo test --locked -p smart-wallet -- --nocapture

clean:
	cargo clean
