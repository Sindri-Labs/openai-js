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
        # Overlay to patch Go to always use Fetch API in WASM
        goWasmFetchOverlay = final: prev: {
          go_1_24 = prev.go_1_24.overrideAttrs (oldAttrs: {
            patches = (oldAttrs.patches or [ ]) ++ [
              (final.writeText "go-wasm-always-use-fetch.patch" ''
                --- a/src/net/http/roundtrip_js.go
                +++ b/src/net/http/roundtrip_js.go
                @@ -13,7 +13,6 @@ import (
                 	"io"
                 	"net/http/internal/ascii"
                 	"strconv"
                -	"strings"
                 	"syscall/js"
                 )
                 
                @@ -56,8 +55,8 @@ var jsFetchMissing = js.Global().Get("fetch").IsUndefined()
                 //
                 // TODO(go.dev/issue/60810): See if it's viable to test the Fetch API
                 // code path.
                -var jsFetchDisabled = js.Global().Get("process").Type() == js.TypeObject &&
                -	strings.HasPrefix(js.Global().Get("process").Get("argv0").String(), "node")
                +// Patched to always use Fetch API for better WASM compatibility in Node.js
                +var jsFetchDisabled = false
                 
                 // RoundTrip implements the [RoundTripper] interface using the WHATWG Fetch API.
                 func (t *Transport) RoundTrip(req *Request) (*Response, error) {
              '')
            ];
          });
        };

        # Apply overlay to get patched Go
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ goWasmFetchOverlay ];
        };

        go = pkgs.go_1_24;
        nodejs = pkgs.nodejs_22;

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
            nodejs
            pkgs.yarn
            pkgs.yarnConfigHook
          ];

          yarnOfflineCache = pkgs.fetchYarnDeps {
            yarnLock = ./yarn.lock;
            hash = "sha256-8LxXXALIlx/ThTLTTsMmgtp4BypveV7cBh7eroZnUUo=";
          };

          buildPhase = ''
            runHook preBuild

            # Patch shebangs in scripts to use correct bash path.
            patchShebangs scripts/

            # Run the TypeScript build.
            yarn build

            # Build the Go WASM module with standard Go compiler.
            export HOME=$TMPDIR
            export GOCACHE=$TMPDIR/go-cache
            export GOPATH=$TMPDIR/go
            export GOOS=js
            export GOARCH=wasm

            pushd go
            go build -o main.wasm main.go
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

            # Copy standard Go's wasm_exec.js as both .js and .mjs.
            cp "${go}/share/go/lib/wasm/wasm_exec.js" $out/sindri/wasm/wasm_exec.js
            cp "${go}/share/go/lib/wasm/wasm_exec.js" $out/sindri/wasm/wasm_exec.mjs

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
