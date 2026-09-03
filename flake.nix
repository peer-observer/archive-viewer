{
  description = "Web-based viewer for peer-observer archive files";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            # Rust. The nixpkgs rustc already ships std for wasm32-unknown-unknown,
            # so no `rustup target add` is needed (there is no rustup here at all).
            rustc
            cargo
            clippy
            rustfmt

            # protoc, for prost-build codegen from the peer-observer submodule.
            protobuf

            # REQUIRED for the wasm build: the nixpkgs rustc sysroot ships no
            # `rust-lld`, so linking wasm32-unknown-unknown fails with
            # "error: linker `lld` not found" without this.
            lld

            # wasm-opt
            binaryen

            # Must stay in lockstep with the wasm-bindgen crate version pinned in
            # Cargo.toml; build.sh checks this and fails loudly on a mismatch.
            wasm-bindgen-cli

            # Static file server for `./build.sh --serve` (no python3/node here).
            miniserve

            # For creating/inspecting archive fixtures by hand.
            zstd

            git
          ];
        };

        # `nix flake check` runs this.
        checks.devShellBuilds = self.devShells.${system}.default;
      });
}
