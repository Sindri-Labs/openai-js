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

          # Node formatters.
          settings.formatter.eslint = {
            command = "${pkgs.eslint}/bin/eslint";
            options = [
              "--fix"
              "--quiet"
            ];
            includes = [
              "*.js"
              "*.jsx"
              "*.ts"
              "*.tsx"
              "*.mjs"
              "*.cjs"
              "*.mts"
              "*.cts"
            ];
          };
        };

        # Package for the OpenAI SDK build.
        openai-sdk = pkgs.stdenv.mkDerivation {
          pname = "openai-sdk";
          version = (pkgs.lib.importJSON ./package.json).version;

          src = ./.;

          nativeBuildInputs = [
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

            # Run the build script.
            yarn build

            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall

            # Copy the built dist directory to output.
            mkdir -p $out
            cp -r dist/* $out/

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
            nixfmt
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
