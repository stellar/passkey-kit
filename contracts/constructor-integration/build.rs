//! Build the wallet WASM used by the production-path constructor tests.

use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../smart-wallet/src");
    println!("cargo:rerun-if-changed=../smart-wallet-interface/src");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target_dir = out_dir.join("wallet-wasm-target");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    let status = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--package",
            "smart-wallet",
            "--target",
            "wasm32v1-none",
            "--release",
        ])
        .env("CARGO_TARGET_DIR", &target_dir)
        .status()
        .expect("start the wallet WASM build");
    assert!(status.success(), "the wallet WASM build failed");

    let source = target_dir
        .join("wasm32v1-none")
        .join("release")
        .join("smart_wallet.wasm");
    fs::copy(source, out_dir.join("smart_wallet.wasm")).expect("copy the wallet WASM test fixture");
}
