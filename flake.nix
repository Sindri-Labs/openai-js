{
  description = "Sindri OpenAI-Compatible JS SDK";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        go = pkgs.go_1_24;
        nodejs = pkgs.nodejs_22;
        inherit (pkgs) tinygo;

        # Treefmt config.
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";

          # Go formatters.
          programs.gofumpt.enable = true;
          programs.goimports.enable = true;

          # Nix formatters.
          programs.nixfmt.enable = true;
          programs.deadnix.enable = true;
          programs.statix.enable = true;
        };

        # Package for the OpenAI SDK build.
        openai-sdk = pkgs.stdenv.mkDerivation {
          pname = "openai-sdk";
          inherit ((pkgs.lib.importJSON ./package.json)) version;

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = _path: _type: true;
          };

          nativeBuildInputs = [
            pkgs.bash
            go
            tinygo
            nodejs
            pkgs.yarn
            pkgs.yarnConfigHook
          ];

          yarnOfflineCache = pkgs.fetchYarnDeps {
            yarnLock = ./yarn.lock;
            hash = "sha256-25mD6XBvrzH4Wt20s65bNITjPGdgG9xOx3hUAVea0yQ=";
          };

          buildPhase = ''
            runHook preBuild

            # Run the TypeScript build.
            yarn build

            # Build the Go WASM module with TinyGo.
            export HOME=$TMPDIR
            export GOCACHE=$TMPDIR/go-cache
            export GOPATH=$TMPDIR/go

            pushd go
            tinygo build -o main.wasm -target wasm main.go
            popd

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            # Copy the built dist directory to output.
            mkdir -p $out
            cp -r dist/* $out/

            # Process WASM module and support files for sindri/wasm directory.
            mkdir -p $out/sindri/wasm

            # Generate base64 of WASM.
            WASM_BASE64=$(base64 -w0 go/main.wasm)

            # Create ES module version (wasm.mjs).
            cat > $out/sindri/wasm/wasm.mjs << EOF
            // Auto-generated file containing the WASM module as base64.
            export const WASM_BASE64 = '$WASM_BASE64';

            export function getWasmBytes() {
              const binaryString = atob(WASM_BASE64);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
              }
              return bytes;
            }
            EOF

            # Create CommonJS version (wasm.js).
            cat > $out/sindri/wasm/wasm.js << EOF
            // Auto-generated file containing the WASM module as base64.
            const WASM_BASE64 = '$WASM_BASE64';

            function getWasmBytes() {
              const binaryString = atob(WASM_BASE64);
              const bytes = new Uint8Array(binaryString.length);
              for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
              }
              return bytes;
            }

            module.exports = { WASM_BASE64, getWasmBytes };
            EOF

            # Copy TinyGo's wasm_exec.js as both .js and .mjs.
            cp "${tinygo}/share/tinygo/targets/wasm_exec.js" $out/sindri/wasm/wasm_exec.js
            cp "${tinygo}/share/tinygo/targets/wasm_exec.js" $out/sindri/wasm/wasm_exec.mjs

            runHook postInstall
          '';
        };

      in
      {
        packages.default = openai-sdk;

        formatter = treefmtEval.config.build.wrapper;
        checks.formatting = treefmtEval.config.build.check self;

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [

            # Go tools.
            delve
            go
            go-tools
            gofumpt
            golangci-lint
            gopls
            tinygo

            # Node tools.
            nodejs
            yarn

            # Nix tools.
            deadnix
            nil
            nixfmt-rfc-style
            statix
            treefmtEval.config.build.wrapper

            # WASM optimization tools.
            binaryen
            wabt
          ];

          shellHook = ''
            # Install JS dependencies locally.
            yarn install

            # Add node_modules/.bin to PATH for JS linting, formatting, etc.
            export PATH="$PWD/node_modules/.bin:$PATH"

            # Set GOPATH if not already set.
            export GOPATH="''${GOPATH:-$HOME/go}"
            export PATH="$GOPATH/bin:$PATH"

            # Ensure WASM builds by default.
            export GOOS=js
            export GOARCH=wasm

            echo ""
            echo "Sindri OpenAI-Compatible JS SDK Development Environment"
            echo "======================================================"
            echo "Go version: $(go version)"
            echo "Node version: $(node --version)"
            echo "Yarn version: $(yarn --version)"
            echo ""

          '';
        };
      }
    );
}
