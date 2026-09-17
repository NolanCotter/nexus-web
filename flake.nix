{
  description = "Nexus alternative-web dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        # Pinned: must match rust-toolchain.toml `channel` and CI.
        # Verified 2026-09-17: rustc/cargo 1.98.1, clippy 0.1.98.
        # `stable.latest` floats and broke reproducibility; do not revert.
        rustVersion = "1.98.1";
        rustToolchain = pkgs.rust-bin.stable.${rustVersion}.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" "rust-analyzer" ];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustToolchain
            pkg-config
            openssl
            git
            gh
            jq
            cargo-audit
            cargo-fuzz
          ];
          shellHook = ''
            echo "nexus dev shell — cargo $(cargo --version)"
          '';
        };

        # Hermetic checks only: the nix build sandbox has no crates.io
        # access, so `cargo test` cannot run here (it needs the registry).
        # Full tests run via `nix develop --command cargo test --workspace`
        # (verified green) and in GitHub CI (networked).
        checks.fmt = pkgs.stdenv.mkDerivation {
          name = "nexus-fmt-check";
          src = ./.;
          buildInputs = [ rustToolchain ];
          buildPhase = "cargo fmt --all -- --check";
          installPhase = "touch $out";
        };

        # Guards the system-toolchain mismatch (nix-profile rustc 1.96.1
        # paired with clippy-driver 1.97.1): rustc and clippy must come
        # from the same pinned release.
        checks.toolchain = pkgs.runCommand "nexus-toolchain-check"
          { buildInputs = [ rustToolchain ]; } ''
          rustc --version | tee $out
          cargo --version | tee -a $out
          cargo clippy --version | tee -a $out
          rustc --version | grep -q "${rustVersion}"
        '';
      });
}
