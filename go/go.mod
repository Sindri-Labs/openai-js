module github.com/sindrilabs/openai-js/go

go 1.24.2

toolchain go1.24.5

require (
	github.com/Sindri-Labs/evllm-proxy v0.0.9-0.20250911215040-5a5f3be5f1ba
	go.uber.org/zap v1.27.0
)

require (
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.32.0 // indirect
	golang.org/x/net v0.34.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
)

replace github.com/google/logger => ./stub_logger
