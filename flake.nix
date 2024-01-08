{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs @ {
    nixpkgs,
    flake-parts,
    nixpkgs-unstable,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux"];
      perSystem = {pkgs, ...}: {
        devShells.default = with pkgs;
          mkShell {
            packages = [
              nixpkgs-unstable.legacyPackages.x86_64-linux.nim1
              nimPackages.nimble

              cargo
              stdenv.cc
              pkg-config
              openssl.dev

              openssl.dev
            ];
          };
      };
    };
}
