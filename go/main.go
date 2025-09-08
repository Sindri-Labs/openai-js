//go:build wasm
// +build wasm

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"syscall/js"
	"time"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient"
	cm "github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/clientmodels"
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
	"github.com/cloudflare/circl/kem"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	clientPublicKey  kem.PublicKey
	clientPrivateKey kem.PrivateKey
	serverPublicKey  kem.PublicKey
	apiKey           string
	baseURL          string
	debugMode        bool
	globalClient     *sindriclient.SindriClient
	logger           *zap.Logger
)

// jsLog logs a message to the JavaScript console.
func jsLog(level, message string, fields ...interface{}) {
	if !debugMode && level == "DEBUG" {
		return
	}

	js.Global().Get("console").Call("log", fmt.Sprintf("[WASM %s] %s %v", level, message, fields))
}

// createJSLogger creates a zap logger that outputs to JavaScript console.
func createJSLogger(debug bool) *zap.Logger {
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

	// Set log level based on debug flag.
	logLevel := zapcore.InfoLevel
	if debug {
		logLevel = zapcore.DebugLevel
	}

	// Create the core.
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		writeSyncer,
		logLevel,
	)

	// Create the logger.
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger
}

// jsConsoleWriter implements io.Writer to write to JavaScript console.
type jsConsoleWriter struct{}

func (w *jsConsoleWriter) Write(p []byte) (n int, err error) {
	// Parse the JSON log message.
	var logEntry map[string]interface{}
	if err := json.Unmarshal(p, &logEntry); err != nil {
		// If we can't parse it, just log the raw message.
		js.Global().Get("console").Call("log", "[WASM LOG]", string(p))
		return len(p), nil
	}

	// Format the log message.
	level := "INFO"
	if l, ok := logEntry["level"].(string); ok {
		level = strings.ToUpper(l)
	}

	msg := ""
	if m, ok := logEntry["msg"].(string); ok {
		msg = m
	}

	// Log to JavaScript console with proper level.
	consoleMethod := "log"
	switch level {
	case "ERROR":
		consoleMethod = "error"
	case "WARN":
		consoleMethod = "warn"
	case "DEBUG":
		consoleMethod = "debug"
	}

	// Include the full log entry for debugging.
	js.Global().Get("console").Call(consoleMethod, fmt.Sprintf("[evllm-proxy %s] %s", level, msg), logEntry)

	return len(p), nil
}

// initializeKeys initializes encryption keys
func initializeKeys(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing required parameter: useEphemeral",
		}
	}

	useEphemeral := args[0].Bool()

	// Enable debug mode if passed (4th argument)
	if len(args) > 3 && !args[3].IsUndefined() {
		debugMode = args[3].Bool()
		jsLog("INFO", "Debug mode enabled", debugMode)

		// Create logger for evllm-proxy
		logger = createJSLogger(debugMode)
		logger.Info("Zap logger initialized for evllm-proxy")
		jsLog("INFO", "Created zap logger for evllm-proxy with debug =", debugMode)
	} else {
		jsLog("INFO", "No debug flag passed, using default")
	}

	if useEphemeral {
		pub, priv, err := cryptos.GenerateKeyPair()
		if err != nil {
			return map[string]interface{}{
				"error": fmt.Sprintf("Failed to generate keys: %v", err),
			}
		}
		clientPublicKey = pub
		clientPrivateKey = priv

		pubKeyBytes, _ := pub.MarshalBinary()
		return map[string]interface{}{
			"success":   true,
			"publicKey": base64.StdEncoding.EncodeToString(pubKeyBytes),
		}
	}

	return map[string]interface{}{
		"success": true,
		"message": "Static keys would be loaded here",
	}
}

// setCredentials sets the API key and base URL and initializes the SindriClient
func setCredentials(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"error": "Missing required parameters: apiKey, baseURL",
		}
	}

	apiKey = args[0].String()
	baseURL = args[1].String()

	// Initialize the SindriClient with proper logging
	if err := initializeSindriClient(); err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to initialize Sindri client: %v", err),
		}
	}

	return map[string]interface{}{
		"success": true,
	}
}

// initializeSindriClient creates and configures the SindriClient with logging
// setPrivateHTTPClient uses reflection to set the private httpClient field
func setPrivateHTTPClient(client *sindriclient.SindriClient, httpClient *http.Client) error {
	// Use reflection to access the private field
	rv := reflect.ValueOf(client).Elem()
	rf := rv.FieldByName("httpClient")

	if !rf.IsValid() {
		return fmt.Errorf("httpClient field not found")
	}

	if !rf.CanSet() {
		// Try using unsafe pointer if normal reflection doesn't work
		rf = reflect.NewAt(rf.Type(), rf.Addr().UnsafePointer()).Elem()
	}

	rf.Set(reflect.ValueOf(httpClient))

	// Also update verification manager's HTTP client if it exists
	vmField := rv.FieldByName("verificationMgr") // Note: field is called verificationMgr, not verificationManager
	if vmField.IsValid() && !vmField.IsNil() {
		jsLog("DEBUG", "Found verificationMgr field")
		// Get the verification manager pointer
		vmValue := vmField.Elem()

		// Try to find reportRequest field in verification manager
		reportRequestField := vmValue.FieldByName("reportRequest")
		if reportRequestField.IsValid() && !reportRequestField.IsNil() {
			jsLog("DEBUG", "Found reportRequest field")
			// Get the HttpRequest struct (it's a pointer)
			reportRequest := reportRequestField.Elem()

			// Update the Client field in HttpRequest
			clientField := reportRequest.FieldByName("Client")
			if clientField.IsValid() {
				jsLog("DEBUG", fmt.Sprintf("Found Client field, CanSet: %v", clientField.CanSet()))
				if !clientField.CanSet() {
					clientField = reflect.NewAt(clientField.Type(), clientField.Addr().UnsafePointer()).Elem()
				}
				clientField.Set(reflect.ValueOf(httpClient))
				jsLog("INFO", "Updated verification manager's HTTP client")

				// Verify the update worked
				updatedClient := clientField.Interface().(*http.Client)
				jsLog("DEBUG", fmt.Sprintf("Verification - updated client transport type: %T", updatedClient.Transport))
			} else {
				jsLog("WARN", "Client field not found in reportRequest")
			}
		} else {
			jsLog("WARN", "reportRequest field not found or is nil")
		}
	} else {
		jsLog("WARN", "verificationMgr field not found or is nil")
	}

	return nil
}

func initializeSindriClient() error {
	jsLog("INFO", "Initializing SindriClient...")
	jsLog("INFO", "BaseURL:", baseURL)
	jsLog("INFO", "Debug mode:", debugMode)

	// Ensure we have a logger
	if logger == nil {
		jsLog("INFO", "Creating logger in initializeSindriClient")
		logger = createJSLogger(debugMode)
	}

	// Create client options
	options := sindriclient.SindriClientOptions{
		BaseURL:                            baseURL,
		APIKey:                             apiKey,
		Logger:                             logger,
		RequestTimeoutSeconds:              30,   // Reduce timeout to 30 seconds
		EnableEncryption:                   true, // Enable encryption for TEE support
		UseEphemeralKeys:                   true, // Use ephemeral keys for security
		AttestationValidityPeriodMinutes:   60,
		AttestationRenewalThresholdSeconds: 30,
	}

	// Validate options
	if err := options.Validate(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// Create the client
	client, err := sindriclient.NewSindriClient(&options)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	globalClient = client

	// The default HTTP transport works in WASM! We don't need a custom transport.
	jsLog("INFO", "Using standard net/http transport (works in WASM)")

	// If encryption is enabled, note that we're using it but don't block on attestation
	if options.EnableEncryption {
		jsLog("INFO", "Encryption enabled, attestation will be fetched on first request")
		// Don't call GetServerPublicKey here as it hangs in WASM
		// The evllm-proxy will handle attestation on the first actual request
	}

	logger.Info("SindriClient initialized successfully",
		zap.String("baseURL", baseURL),
		zap.Bool("encryptionEnabled", options.EnableEncryption),
		zap.Bool("ephemeralKeys", clientPrivateKey != nil),
	)

	return nil
}

// fetchAttestation fetches the attestation report from the server
func fetchAttestation(this js.Value, args []js.Value) interface{} {
	// Create a promise handler
	handler := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			if baseURL == "" {
				reject.Invoke("Base URL not set")
				return
			}

			// Make request to attestation endpoint
			attestationURL := strings.TrimSuffix(baseURL, "/v1") + "/attestation/report"
			jsLog("INFO", "Fetching attestation from", attestationURL)

			req, err := http.NewRequest("GET", attestationURL, nil)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to create request: %v", err))
				return
			}

			// Add API key if available
			if apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to fetch attestation: %v", err))
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				reject.Invoke(fmt.Sprintf("Failed to read response: %v", err))
				return
			}

			if resp.StatusCode != 200 {
				reject.Invoke(fmt.Sprintf("Attestation request failed with status %d: %s", resp.StatusCode, string(body)))
				return
			}

			// Parse the attestation response to extract the server public key
			var attestation map[string]interface{}
			if err := json.Unmarshal(body, &attestation); err != nil {
				reject.Invoke(fmt.Sprintf("Failed to parse attestation: %v", err))
				return
			}

			// Extract server public key from attestation
			// For Sindri, it's in metadata.public_key
			var serverPubKey string
			if metadata, ok := attestation["metadata"].(map[string]interface{}); ok {
				if pk, ok := metadata["public_key"].(string); ok {
					serverPubKey = pk
					jsLog("INFO", "Found public key in metadata:", serverPubKey)
				}
			}

			// Fallback to other common fields
			if serverPubKey == "" {
				if pk, ok := attestation["publicKey"].(string); ok {
					serverPubKey = pk
				} else if pk, ok := attestation["serverPublicKey"].(string); ok {
					serverPubKey = pk
				} else if pk, ok := attestation["server_public_key"].(string); ok {
					serverPubKey = pk
				}
			}

			if serverPubKey != "" {
				// Set the server public key
				pubKey, err := cryptos.PublicKeyFromHexString(serverPubKey)
				if err != nil {
					// Try base64
					keyBytes, err2 := base64.StdEncoding.DecodeString(serverPubKey)
					if err2 == nil {
						pubKey, err = cryptos.PublicKeyFromBytes(keyBytes)
					}
				}

				if err == nil && pubKey != nil {
					serverPublicKey = pubKey
					jsLog("INFO", "Server public key extracted from attestation")
				}
			}

			resolve.Invoke(map[string]interface{}{
				"attestation":     attestation,
				"serverPublicKey": serverPubKey,
				"status":          resp.StatusCode,
			})
		}()

		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

// chatCompletion makes a chat completion request
func chatCompletion(this js.Value, args []js.Value) interface{} {
	jsLog("DEBUG", "chatCompletion called - using evllm-proxy SindriClient")

	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing request body",
		}
	}

	if globalClient == nil {
		return map[string]interface{}{
			"error": "SindriClient not initialized",
		}
	}

	requestBody := args[0].String()

	// Create a promise to handle the async operation properly
	handler := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			// Parse the request
			var params cm.ChatCompletionNewParams
			if err := json.Unmarshal([]byte(requestBody), &params); err != nil {
				reject.Invoke(fmt.Sprintf("Failed to parse request: %v", err))
				return
			}

			// Create trace metadata
			td := cm.TraceMetadata{
				"TraceId":   fmt.Sprintf("wasm-%d", time.Now().UnixNano()),
				"RequestId": fmt.Sprintf("req-%d", time.Now().UnixNano()),
			}

			jsLog("INFO", "Using evllm-proxy SindriClient for chat completion with encryption")

			// Use the evllm-proxy client with attestation and encryption
			completion, err := globalClient.ChatCompletionNoStream(&params, &td)
			if err != nil {
				jsLog("ERROR", "Chat completion failed:", err.Error())
				reject.Invoke(fmt.Sprintf("Chat completion failed: %v", err))
				return
			}

			// Convert response to JSON
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

// chatCompletionWithClient uses the SindriClient for chat completions
func chatCompletionWithClient(args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing request body",
		}
	}

	// Parse the request from JavaScript
	requestJSON := args[0].String()
	var params cm.ChatCompletionNewParams
	if err := json.Unmarshal([]byte(requestJSON), &params); err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to parse request: %v", err),
		}
	}

	// Create trace metadata
	td := cm.TraceMetadata{
		"TraceId":   fmt.Sprintf("wasm-%d", time.Now().UnixNano()),
		"RequestId": fmt.Sprintf("req-%d", time.Now().UnixNano()),
	}

	// Log the request
	if logger != nil {
		logger.Debug("Making chat completion request",
			zap.String("model", params.Model),
			zap.Bool("stream", params.Stream),
			zap.String("traceID", td["TraceId"]),
		)
	}

	// Handle non-streaming request (streaming not yet supported in WASM)
	completion, err := globalClient.ChatCompletionNoStream(&params, &td)
	if err != nil {
		if logger != nil {
			logger.Error("Chat completion failed", zap.Error(err))
		}
		return map[string]interface{}{
			"error": fmt.Sprintf("Chat completion failed: %v", err),
		}
	}

	// Convert response to JSON
	responseJSON, err := json.Marshal(completion)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to marshal response: %v", err),
		}
	}

	if logger != nil {
		logger.Debug("Chat completion successful", zap.String("traceID", td["TraceId"]))
	}

	return map[string]interface{}{
		"response": string(responseJSON),
	}
}

// makeHTTPRequest performs the actual HTTP request
func makeHTTPRequest(requestBody string) map[string]interface{} {
	jsLog("DEBUG", "Request body", requestBody)

	// Check if we have credentials
	if apiKey == "" || baseURL == "" {
		return map[string]interface{}{
			"error": "Credentials not set. Call sindri_setCredentials first.",
		}
	}

	// Prepare the request URL - baseURL should already have /v1 if needed
	url := strings.TrimSuffix(baseURL, "/") + "/chat/completions"
	jsLog("DEBUG", "Making request to", url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(requestBody)))
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to create request: %v", err),
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Make the request using standard HTTP client (with patched Go that uses Fetch in WASM)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		jsLog("ERROR", "Request failed", err.Error())
		return map[string]interface{}{
			"error": fmt.Sprintf("Request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to read response: %v", err),
		}
	}

	jsLog("DEBUG", "Response status", resp.StatusCode)
	jsLog("DEBUG", "Response body", string(body))

	return map[string]interface{}{
		"response": string(body),
		"status":   resp.StatusCode,
	}
}

// Additional helper functions...
func getPublicKey(this js.Value, args []js.Value) interface{} {
	if clientPublicKey == nil {
		return map[string]interface{}{
			"error": "No public key available",
		}
	}

	pubKeyBytes, _ := clientPublicKey.MarshalBinary()
	return map[string]interface{}{
		"publicKey": base64.StdEncoding.EncodeToString(pubKeyBytes),
	}
}

func setServerPublicKey(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing public key",
		}
	}

	keyStr := args[0].String()

	// Decode the base64 public key
	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to decode public key: %v", err),
		}
	}

	// Parse the public key using the PublicKeyFromBytes function
	pubKey, err := cryptos.PublicKeyFromBytes(keyBytes)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to parse public key: %v", err),
		}
	}

	serverPublicKey = pubKey
	jsLog("INFO", "Server public key set successfully")

	return map[string]interface{}{
		"success": true,
	}
}

func encryptMessage(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing message",
		}
	}

	message := args[0].String()

	// Check if we have server public key
	if serverPublicKey == nil {
		// For now, just base64 encode if no server key
		// This allows basic functionality without attestation
		encrypted := base64.StdEncoding.EncodeToString([]byte(message))
		return map[string]interface{}{
			"encrypted": encrypted,
			"warning":   "No server public key - using base64 only",
		}
	}

	// Generate ephemeral keys if not already present
	if clientPublicKey == nil || clientPrivateKey == nil {
		pub, priv, err := cryptos.GenerateKeyPair()
		if err != nil {
			return map[string]interface{}{
				"error": fmt.Sprintf("Failed to generate client keys: %v", err),
			}
		}
		clientPublicKey = pub
		clientPrivateKey = priv
		jsLog("INFO", "Generated ephemeral client keys for encryption")
	}

	// Use HPKE encryption with client keys for authentication
	keys := &cryptos.EncryptionKeys{
		ServerPublicKey:  serverPublicKey,
		ClientPublicKey:  clientPublicKey,
		ClientPrivateKey: clientPrivateKey,
	}

	bundle, err := cryptos.Encrypt([]byte(message), keys)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Encryption failed: %v", err),
		}
	}

	// Encode the bundle components
	encryptedData := base64.StdEncoding.EncodeToString(bundle.CipherText)
	ephemeralKey := base64.StdEncoding.EncodeToString(bundle.EncapsulatedKey)

	return map[string]interface{}{
		"encrypted":    encryptedData,
		"ephemeralKey": ephemeralKey,
	}
}

func decryptMessage(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing encrypted message",
		}
	}

	// TODO: Implement actual decryption
	return map[string]interface{}{
		"decrypted": "decrypted message",
	}
}

func encryptBundle(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return map[string]interface{}{
			"error": "Missing bundle",
		}
	}

	// TODO: Implement bundle encryption
	return map[string]interface{}{
		"encrypted": "encrypted bundle",
		"publicKey": "ephemeral public key",
	}
}

func generateKeyPair(this js.Value, args []js.Value) interface{} {
	pub, priv, err := cryptos.GenerateKeyPair()
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Failed to generate keys: %v", err),
		}
	}

	pubKeyBytes, _ := pub.MarshalBinary()
	privKeyBytes, _ := priv.MarshalBinary()

	return map[string]interface{}{
		"publicKey":  base64.StdEncoding.EncodeToString(pubKeyBytes),
		"privateKey": base64.StdEncoding.EncodeToString(privKeyBytes),
	}
}

func generateKeyPairPEM(this js.Value, args []js.Value) interface{} {
	// TODO: Implement PEM format key generation
	return map[string]interface{}{
		"publicKeyPEM":  "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
		"privateKeyPEM": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
	}
}

func main() {
	// With patched Go, http.DefaultTransport already uses Fetch API in WASM
	// No need for custom transport

	// Register all functions
	js.Global().Set("sindri_initializeKeys", js.FuncOf(initializeKeys))
	js.Global().Set("sindri_getPublicKey", js.FuncOf(getPublicKey))
	js.Global().Set("sindri_setServerPublicKey", js.FuncOf(setServerPublicKey))
	js.Global().Set("sindri_setCredentials", js.FuncOf(setCredentials))
	js.Global().Set("sindri_generateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("sindri_generateKeyPairPEM", js.FuncOf(generateKeyPairPEM))
	js.Global().Set("sindri_encryptMessage", js.FuncOf(encryptMessage))
	js.Global().Set("sindri_decryptMessage", js.FuncOf(decryptMessage))
	js.Global().Set("sindri_encryptBundle", js.FuncOf(encryptBundle))
	js.Global().Set("sindri_chatCompletion", js.FuncOf(chatCompletion))
	js.Global().Set("sindri_fetchAttestation", js.FuncOf(fetchAttestation))

	// Signal that the module is ready
	js.Global().Get("console").Call("log", "[WASM] Sindri WASM module loaded and ready")

	// Keep the Go program running
	select {}
}
