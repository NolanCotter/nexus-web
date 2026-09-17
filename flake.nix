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
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
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
          ];
          shellHook = ''
            echo "nexus dev shell — cargo $(cargo --version)"
          '';
        };

        checks.build = pkgs.stdenv.mkDerivation {
          name = "nexus-check";
          src = ./.;
          buildInputs = [ rustToolchain ];
          buildPhase = "cargo test --workspace --offline || cargo test --workspace";
          installPhase = "touch $out";
        };
      });
}
