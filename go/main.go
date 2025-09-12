//go:build js && wasm
// +build js,wasm

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient"
	cm "github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/clientmodels"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Configuration defaults matching TypeScript constants.
const (
	DefaultRequestTimeoutSeconds      = 300
	DefaultAttestationValidityMinutes = 60
	DefaultAttestationRenewalSeconds  = 30
)

var (
	globalConfig   *ConfigFromJS
	clientCache    map[string]*sindriclient.SindriClient
	clientCacheMux sync.RWMutex
	logger         *zap.Logger
)

// ConfigFromJS represents the configuration passed from JavaScript.
type ConfigFromJS struct {
	RequestTimeoutSeconds int                     `json:"requestTimeoutSeconds"`
	LogLevel              string                  `json:"logLevel"`
	Encryption            *EncryptionConfigFromJS `json:"encryption"`
}

// EncryptionConfigFromJS represents encryption configuration from JavaScript.
type EncryptionConfigFromJS struct {
	Enabled     bool                     `json:"enabled"`
	KeySource   string                   `json:"keySource"`
	PrivateKey  *KeyConfigFromJS         `json:"privateKey"`
	PublicKey   *KeyConfigFromJS         `json:"publicKey"`
	Attestation *AttestationConfigFromJS `json:"attestation"`
}

// KeyConfigFromJS represents key configuration from JavaScript.
type KeyConfigFromJS struct {
	Value string `json:"value"`
}

// AttestationConfigFromJS represents attestation configuration from JavaScript.
type AttestationConfigFromJS struct {
	ValidityPeriodMinutes   int                     `json:"validityPeriodMinutes"`
	RenewalThresholdSeconds int                     `json:"renewalThresholdSeconds"`
	VerifyRegisters         bool                    `json:"verifyRegisters"`
	ApprovedMeasurements    *ApprovedMeasurementsJS `json:"approvedMeasurements"`
}

// ApprovedMeasurementsJS represents approved measurements from JavaScript.
type ApprovedMeasurementsJS struct {
	RTMR1 []string `json:"rtmr1"`
	RTMR2 []string `json:"rtmr2"`
	RTMR3 []string `json:"rtmr3"`
}

// jsLog logs a message to the JavaScript console.
func jsLog(level, message string, fields ...interface{}) {
	js.Global().Get("console").Call("log", fmt.Sprintf("[WASM %s] %s %v", level, message, fields))
}

// createJSLogger creates a zap logger that outputs to JavaScript console.
func createJSLogger(logLevel string) *zap.Logger {
	// Parse log level.
	level := zapcore.InfoLevel
	switch logLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	}

	// Custom encoder that outputs to JavaScript console.
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create a custom WriteSyncer that writes to JS console.
	writeSyncer := zapcore.AddSync(&jsConsoleWriter{})

	// Create the core.
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		writeSyncer,
		level,
	)

	// Create the logger.
	return zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
}

// jsConsoleWriter implements io.Writer to write to JavaScript console.
type jsConsoleWriter struct{}

func (w *jsConsoleWriter) Write(p []byte) (n int, err error) {
	// Parse the JSON log message.
	var logEntry map[string]interface{}
	if err := json.Unmarshal(p, &logEntry); err != nil {
		// If we can't parse it, just log the raw message.
		js.Global().Get("console").Call("log", "[evllm-proxy]", string(p))
		return len(p), nil
	}

	// Format the log message.
	level := "INFO"
	if l, ok := logEntry["level"].(string); ok {
		level = l
	}

	msg := ""
	if m, ok := logEntry["msg"].(string); ok {
		msg = m
	}

	// Log to JavaScript console with proper level.
	consoleMethod := "log"
	switch level {
	case "error":
		consoleMethod = "error"
	case "warn":
		consoleMethod = "warn"
	case "debug":
		consoleMethod = "debug"
	}

	js.Global().Get("console").Call(consoleMethod, fmt.Sprintf("[evllm-proxy %s] %s", level, msg), logEntry)
	return len(p), nil
}

// buildClientOptions builds SindriClientOptions from the global configuration.
func buildClientOptions(baseURL, apiKey string) (*sindriclient.SindriClientOptions, error) {
	if globalConfig == nil {
		return nil, fmt.Errorf("configuration not initialized")
	}

	options := sindriclient.SindriClientOptions{
		BaseURL:               baseURL,
		APIKey:                apiKey,
		Logger:                logger,
		RequestTimeoutSeconds: globalConfig.RequestTimeoutSeconds,
	}

	// Set default timeout if not specified.
	if options.RequestTimeoutSeconds <= 0 {
		options.RequestTimeoutSeconds = DefaultRequestTimeoutSeconds
	}

	// Configure encryption if enabled.
	if globalConfig.Encryption != nil && globalConfig.Encryption.Enabled {
		options.EnableEncryption = true

		// Determine key source.
		switch globalConfig.Encryption.KeySource {
		case "ephemeral", "":
			options.UseEphemeralKeys = true

		case "value":
			// Use provided keys.
			if globalConfig.Encryption.PrivateKey != nil && globalConfig.Encryption.PrivateKey.Value != "" {
				// Decode from base64 or use as PEM directly.
				privKeyData, err := base64.StdEncoding.DecodeString(globalConfig.Encryption.PrivateKey.Value)
				if err != nil {
					// Assume it's already PEM.
					privKeyData = []byte(globalConfig.Encryption.PrivateKey.Value)
				}
				options.PrivateKeyPEMBytes = privKeyData
			}

			if globalConfig.Encryption.PublicKey != nil && globalConfig.Encryption.PublicKey.Value != "" {
				// Decode from base64 or use as PEM directly.
				pubKeyData, err := base64.StdEncoding.DecodeString(globalConfig.Encryption.PublicKey.Value)
				if err != nil {
					// Assume it's already PEM.
					pubKeyData = []byte(globalConfig.Encryption.PublicKey.Value)
				}
				options.PublicKeyPEMBytes = pubKeyData
			}

		default:
			return nil, fmt.Errorf("unsupported key source: %s (file sources not supported in WASM)", globalConfig.Encryption.KeySource)
		}

		// Pass through attestation config - evllm-proxy handles all verification.
		if globalConfig.Encryption.Attestation != nil {
			att := globalConfig.Encryption.Attestation
			options.AttestationValidityPeriodMinutes = att.ValidityPeriodMinutes
			options.AttestationRenewalThresholdSeconds = att.RenewalThresholdSeconds
			options.AttestationVerifyRegisters = att.VerifyRegisters

			// Pass through approved measurements if configured.
			if att.ApprovedMeasurements != nil {
				options.AttestationApprovedRegister1 = att.ApprovedMeasurements.RTMR1
				options.AttestationApprovedRegister2 = att.ApprovedMeasurements.RTMR2
				options.AttestationApprovedRegister3 = att.ApprovedMeasurements.RTMR3
			}
		}

		// Set defaults for attestation if not provided.
		if options.AttestationValidityPeriodMinutes <= 0 {
			options.AttestationValidityPeriodMinutes = DefaultAttestationValidityMinutes
		}
		if options.AttestationRenewalThresholdSeconds <= 0 {
			options.AttestationRenewalThresholdSeconds = DefaultAttestationRenewalSeconds
		}
	}

	// Validate options.
	if err := options.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &options, nil
}

// initializeSindriClient initializes the SindriClient with configuration from JavaScript.
func initializeSindriClient(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing configuration object",
		}
	}

	// Parse the configuration from JavaScript.
	configJSON := args[0].String()
	var config ConfigFromJS
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to parse configuration: %v", err),
		}
	}

	// Create logger with specified log level.
	logLevel := config.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	logger = createJSLogger(logLevel)
	logger.Info("Initializing SindriClient",
		zap.Bool("encryptionEnabled", config.Encryption != nil && config.Encryption.Enabled),
	)

	// Store the configuration globally for later use.
	// We'll create clients on-demand and cache them by apiKey+baseURL.
	globalConfig = &config
	clientCache = make(map[string]*sindriclient.SindriClient)

	// Validate that we can create a client with the encryption config.
	// Use placeholder values for validation.
	options, err := buildClientOptions("https://placeholder.com", "placeholder")
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to build options: %v", err),
		}
	}

	// Log key source info.
	if options.EnableEncryption {
		if options.UseEphemeralKeys {
			logger.Info("Using ephemeral keys for encryption")
		} else {
			logger.Info("Using provided keys for encryption")
		}
	}

	// Create a test client to validate the configuration.
	client, err := sindriclient.NewSindriClient(options)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to create SindriClient: %v", err),
		}
	}

	// Don't store a global client - we'll create one per request
	// Just validate that we can create a client with the config
	client.Stop() // Clean up the test client

	// Return the public key if using ephemeral keys.
	response := map[string]interface{}{
		"success": true,
	}

	if options.UseEphemeralKeys && options.EnableEncryption {
		// The client will generate keys internally.
		// We can't access them directly, but that's OK - the library handles it.
		response["message"] = "Using ephemeral keys managed by evllm-proxy"
	}

	logger.Info("SindriClient initialized successfully",
		zap.Bool("encryptionEnabled", options.EnableEncryption),
		zap.Bool("ephemeralKeys", options.UseEphemeralKeys),
	)

	return response
}

// getOrCreateClient gets a cached client or creates a new one for the given auth/endpoint.
func getOrCreateClient(apiKey, baseURL string) (*sindriclient.SindriClient, error) {
	// Create cache key from apiKey and baseURL
	cacheKey := fmt.Sprintf("%s|%s", apiKey, baseURL)

	// Try to get from cache first
	clientCacheMux.RLock()
	client, exists := clientCache[cacheKey]
	clientCacheMux.RUnlock()

	if exists && client != nil {
		return client, nil
	}

	// Need to create a new client
	clientCacheMux.Lock()
	defer clientCacheMux.Unlock()

	// Double-check after acquiring write lock
	client, exists = clientCache[cacheKey]
	if exists && client != nil {
		return client, nil
	}

	// Build client options with the provided auth.
	options, err := buildClientOptions(baseURL, apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build client options: %w", err)
	}

	// Create the client.
	newClient, err := sindriclient.NewSindriClient(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create SindriClient: %w", err)
	}

	// Cache the client
	clientCache[cacheKey] = newClient

	logger.Info("Created new SindriClient",
		zap.String("cacheKey", cacheKey),
		zap.Bool("encryptionEnabled", options.EnableEncryption),
	)

	return newClient, nil
}

// RequestWithAuth represents a request with auth and endpoint info
type RequestWithAuth struct {
	TEEAuth     string `json:"__tee_auth"`
	TEEEndpoint string `json:"__tee_endpoint"`
	*cm.ChatCompletionNewParams
}

// chatCompletion makes a chat completion request using the SindriClient.
func chatCompletion(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing request body",
		}
	}

	if globalConfig == nil {
		return map[string]interface{}{
			"error": "TEE not initialized. Call initialize first.",
		}
	}

	requestBody := args[0].String()

	// Create a promise to handle the async operation.
	handler := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			// Parse the request with auth info.
			var requestWithAuth map[string]interface{}
			if err := json.Unmarshal([]byte(requestBody), &requestWithAuth); err != nil {
				reject.Invoke(fmt.Sprintf("Failed to parse request: %v", err))
				return
			}

			// Extract auth and endpoint
			authHeader, _ := requestWithAuth["__tee_auth"].(string)
			endpoint, _ := requestWithAuth["__tee_endpoint"].(string)

			// Remove special fields
			delete(requestWithAuth, "__tee_auth")
			delete(requestWithAuth, "__tee_endpoint")

			// Extract base URL from endpoint (remove /v1/chat/completions)
			baseURL := endpoint
			if strings.HasSuffix(baseURL, "/v1/chat/completions") {
				baseURL = baseURL[:len(baseURL)-20]
			}

			// Extract API key from auth header
			apiKey := authHeader
			if strings.HasPrefix(apiKey, "Bearer ") {
				apiKey = apiKey[7:]
			}

			// Get or create a cached client for this auth/endpoint
			client, err := getOrCreateClient(apiKey, baseURL)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to get SindriClient: %v", err))
				return
			}

			// Re-marshal the params without auth fields
			paramsJSON, err := json.Marshal(requestWithAuth)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to marshal params: %v", err))
				return
			}

			// Parse as ChatCompletionNewParams
			var params cm.ChatCompletionNewParams
			if err := json.Unmarshal(paramsJSON, &params); err != nil {
				reject.Invoke(fmt.Sprintf("Failed to parse params: %v", err))
				return
			}

			// Create trace metadata.
			td := cm.TraceMetadata{
				"TraceId":   fmt.Sprintf("wasm-%d", time.Now().UnixNano()),
				"RequestId": fmt.Sprintf("req-%d", time.Now().UnixNano()),
			}

			// Use the evllm-proxy client with attestation and encryption.
			// The client already has the correct auth/endpoint from when it was created
			logger.Info("Calling ChatCompletionNoStream",
				zap.String("clientApiKey", apiKey[:min(len(apiKey), 20)]), // Log first 20 chars safely
				zap.String("clientBaseURL", baseURL),
			)
			completion, err := client.ChatCompletionNoStream(&params, &td)
			if err != nil {
				if logger != nil {
					logger.Error("Chat completion failed", zap.Error(err))
				}
				reject.Invoke(fmt.Sprintf("Chat completion failed: %v", err))
				return
			}

			// Convert response to JSON.
			responseJSON, err := json.Marshal(completion)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to marshal response: %v", err))
				return
			}

			resolve.Invoke(map[string]interface{}{
				"response": string(responseJSON),
				"status":   200,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// getServerPublicKey returns the server's public key if available.
func getServerPublicKey(this js.Value, args []js.Value) interface{} {
	// Since we create clients per-request, we can't retrieve the server public key
	// without making a request. The evllm-proxy handles key exchange internally
	// during the attestation process.
	return map[string]interface{}{
		"error": "Server public key is managed internally by evllm-proxy during attestation",
	}
}

// exportPublicKey exports the client's public key if using static keys.
func exportPublicKey(this js.Value, args []js.Value) interface{} {
	// This is only relevant if we're using static keys and need to share our public key.
	// With ephemeral keys, the library handles key exchange automatically.
	return map[string]interface{}{
		"message": "Public key export not needed - evllm-proxy handles key exchange",
	}
}

// main initializes the WASM module and exports functions to JavaScript.
func main() {
	// Export functions to JavaScript.
	js.Global().Set("sindri_initialize", js.FuncOf(initializeSindriClient))
	js.Global().Set("sindri_chatCompletion", js.FuncOf(chatCompletion))
	js.Global().Set("sindri_getServerPublicKey", js.FuncOf(getServerPublicKey))
	js.Global().Set("sindri_exportPublicKey", js.FuncOf(exportPublicKey))

	// Log that the module is ready.
	js.Global().Get("console").Call("log", "[WASM] Sindri WASM module loaded and ready")

	// Keep the program running.
	select {}
}
