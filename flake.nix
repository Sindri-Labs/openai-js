{
  description = "Sindri OpenAI-Compatible JS SDK";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        go = pkgs.go_1_24;
        nodejs = pkgs.nodejs_22;

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Go tools.
            delve
            go
            go-tools
            gofumpt
            golangci-lint
            gopls

            # Node tools.
            nodejs
            yarn

            # Nix tools.
            deadnix
            nil
            nixfmt-rfc-style
            statix

            # WASM optimization tools.
            binaryen
            wabt
          ];

          shellHook = ''
            # Install JS dependencies locally.
            yarn install

            # Set GOPATH if not already set.
            export GOPATH="''${GOPATH:-$HOME/go}"
            export PATH="$GOPATH/bin:$PATH"

            # Ensure WASM builds by default.
            export GOOS=js
            export GOARCH=wasm

            echo "OpenAI JS SDK with TEE/WASM Development Environment"
            echo "======================================================"
            echo ""
            echo "Go version: $(go version)"
            echo "Node version: $(node --version)"
            echo "Yarn version: $(yarn --version)"
            echo ""

          '';
        };
      }
    );
}
