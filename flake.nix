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

        openai-sdk = pkgs.stdenv.mkDerivation {
          pname = "openai-sdk-tee";
          version = "5.12.2";

          src = ./.;

          yarnOfflineCache = pkgs.fetchYarnDeps {
            yarnLock = ./yarn.lock;
            hash = "sha256-25mD6XBvrzH4Wt20s65bNITjPGdgG9xOx3hUAVea0yQ=";
          };

          nativeBuildInputs = with pkgs; [
            yarnConfigHook
            yarnBuildHook
            yarnInstallHook
            nodejs
          ];

          yarnBuildScript = "build";

          meta = with pkgs.lib; {
            description = "Sindri OpenAI-Compatible JS SDK";
            license = licenses.asl20;
          };
        };
      in
      {
        packages.default = openai-sdk;
        devShells.default = pkgs.mkShell {
          inputsFrom = [ openai-sdk ];

          nativeBuildInputs = with pkgs; [
            yarnConfigHook
          ];

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

          inherit (openai-sdk) yarnOfflineCache;

          shellHook = ''
            echo "OpenAI JS SDK with TEE/WASM Development Environment"
            echo "======================================================"
            echo ""
            echo "Go version: $(go version)"
            echo "Node version: $(node --version)"
            echo "Yarn version: $(yarn --version)"
            echo ""

            # Set GOPATH if not already set.
            export GOPATH="''${GOPATH:-$HOME/go}"
            export PATH="$GOPATH/bin:$PATH"

            # Ensure WASM builds by default.
            export GOOS=js
            export GOARCH=wasm
            echo ""
          '';
        };
      }
    );
}
