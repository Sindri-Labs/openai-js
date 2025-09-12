package sindriclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/attestation"
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
	"github.com/cloudflare/circl/kem"
	"go.uber.org/zap"
)

const (
	sseChanSize             = 32       // Size of the channel buffer for streaming responses
	ssePrefix               = "data: " // Prefix for event data in streaming responses
	sseEndOfStreamIndicator = "[DONE]" // Marker for the end of the stream
)

const (
	ErrUnsupportedPayload = "unsupported payload type: %T"
)

type Endpoint string

var (
	EndpointCompletion        Endpoint = "/v1/chat/completions"
	EndpointLegacyCompletion  Endpoint = "/v1/completions"
	EndpointAttestationReport Endpoint = "/attestation/report"

	Endpoints = []Endpoint{
		EndpointCompletion,
		EndpointLegacyCompletion,
		EndpointAttestationReport,
	}
)

// SindriClientOptions for configuring the SindriClient.
type SindriClientOptions struct {
	BaseURL                            string
	APIKey                             string
	Logger                             *zap.Logger
	RequestTimeoutSeconds              int
	EnableEncryption                   bool     // Optional, if true, Sindri encryption will be used
	UseEphemeralKeys                   bool     // Optional, if true, ephemeral keys will be used
	PrivateKeyPEMBytes                 []byte   // Optional, used if EnableEncryption is true
	PublicKeyPEMBytes                  []byte   // Optional, used if EnableEncryption is true
	AttestationValidityPeriodMinutes   int      // Optional, required if EnableEncryption is true
	AttestationRenewalThresholdSeconds int      // Optional, required if EnableEncryption is true
	AttestationVerifyRegisters         bool     // Optional, if true, attestation will verify registers
	AttestationApprovedRegister1       []string // Optional, used to specify approved registers for attestation
	AttestationApprovedRegister2       []string // Optional, used to specify approved registers for attestation
	AttestationApprovedRegister3       []string // Optional, used to specify approved registers for attestation
}

// Validate the SindriClientOptions
func (o *SindriClientOptions) Validate() error {
	if o.BaseURL == "" {
		return fmt.Errorf("BaseURL is required")
	}

	parsedURL, err := url.Parse(o.BaseURL)
	if err != nil {
		return fmt.Errorf("BaseURL is not a valid URL: %w", err)
	}

	if parsedURL.Scheme == "" {
		return fmt.Errorf("BaseURL must include a scheme (http:// or https://)")
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("BaseURL scheme must be http or https, got: %s", parsedURL.Scheme)
	}

	if o.APIKey == "" {
		return fmt.Errorf("APIKey is required")
	}

	if o.Logger == nil {
		return fmt.Errorf("Logger is required")
	}

	if o.EnableEncryption {
		if o.UseEphemeralKeys {
			if o.PrivateKeyPEMBytes != nil {
				return fmt.Errorf("PrivateKeyPEMBytes should not be set when UseEphemeralKeys is true")
			}
			if o.PublicKeyPEMBytes != nil {
				return fmt.Errorf("PublicKeyPEMBytes should not be set when UseEphemeralKeys is true")
			}
		} else {
			if o.PrivateKeyPEMBytes == nil {
				return fmt.Errorf("PrivateKeyPEMBytes is required when UseEphemeralKeys is false")
			}
			if o.PublicKeyPEMBytes == nil {
				return fmt.Errorf("PublicKeyPEMBytes is required when UseEphemeralKeys is false")
			}
		}
	}

	return nil
}

// SindriClient for interacting with the Sindri API.
type SindriClient struct {
	apiKey            string
	verificationMgr   *attestation.VerificationManager
	baseURL           string
	endpoints         map[Endpoint]string
	cancel            context.CancelFunc
	clientKeys        cryptos.KeyHolder
	ctx               context.Context
	encryptionEnabled bool
	httpClient        *http.Client
	logger            *zap.Logger
	requestTimeout    time.Duration
}

func (s *SindriClient) getKeys() (*cryptos.EncryptionKeys, error) {
	if !s.encryptionEnabled {
		return nil, errors.New("encryption is not enabled")
	}

	serverPublic, err := s.GetServerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve server public key: %w", err)
	}

	clientPublic, clientPrivate, err := s.clientKeys.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to get client keys: %w", err)
	}

	return &cryptos.EncryptionKeys{
		ServerPublicKey:  serverPublic,
		ClientPublicKey:  clientPublic,
		ClientPrivateKey: clientPrivate,
	}, nil
}

// APIKey returns the API key used for authentication.
func (s *SindriClient) APIKey() string {
	return s.apiKey
}

// ClientKeys returns the key holder used for encryption.
func (s *SindriClient) BaseURL() string {
	return s.baseURL
}

func (s *SindriClient) Endpoint(ep Endpoint) string {
	return s.endpoints[ep]
}

// GetServerPublicKey retrieves the server's public key from the current attestation.
func (s *SindriClient) GetServerPublicKey() (kem.PublicKey, error) {
	attestation := s.verificationMgr.GetServerAttestation()

	_, err := attestation.IsValid()
	if err != nil {
		return nil, err
	}

	publicKey := attestation.GetPublicKey()
	if publicKey == nil {
		return nil, errors.New("attestation does not contain a valid public key")
	}

	return publicKey, nil
}

// Stop the SindriClient, canceling any ongoing operations.
func (s *SindriClient) Stop() {
	s.cancel()
}

// NewSindriClient creates a new SindriClient with the provided options.
func NewSindriClient(opts *SindriClientOptions) (*SindriClient, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sindriClient := &SindriClient{
		ctx:               ctx,
		cancel:            cancel,
		baseURL:           opts.BaseURL,
		endpoints:         make(map[Endpoint]string),
		apiKey:            opts.APIKey,
		logger:            opts.Logger,
		requestTimeout:    time.Duration(opts.RequestTimeoutSeconds) * time.Second,
		encryptionEnabled: opts.EnableEncryption,
		httpClient:        &http.Client{},
	}

	for _, ep := range Endpoints {
		endpointURL, err := url.JoinPath(sindriClient.baseURL, string(ep))
		if err != nil {
			return nil, fmt.Errorf("failed to construct endpoint %s: %w", ep, err)
		}
		sindriClient.endpoints[ep] = endpointURL
	}

	if opts.EnableEncryption {
		if opts.UseEphemeralKeys {
			sindriClient.clientKeys = &cryptos.EphemeralKeyHolder{}
		} else {
			var publicKey kem.PublicKey
			var privateKey kem.PrivateKey
			var err error

			if privateKey, err = cryptos.PrivateKeyFromPEMBytes(opts.PrivateKeyPEMBytes); err != nil {
				return nil, fmt.Errorf("invalid private key: %w", err)
			}

			if publicKey, err = cryptos.PublicKeyFromPEMBytes(opts.PublicKeyPEMBytes); err != nil {
				return nil, fmt.Errorf("invalid public key: %w", err)
			}

			sindriClient.clientKeys = cryptos.NewClientKeyHolder(publicKey, privateKey)
		}

		manager, err := attestation.NewVerificationManager(attestation.VerificationManagerOptions{
			ManagerContext:                ctx,
			ReportRequestURL:              sindriClient.Endpoint(EndpointAttestationReport),
			ReportRequestAPIKey:           opts.APIKey,
			ReportRequestTimeout:          sindriClient.requestTimeout,
			ReportRenewalThresholdSeconds: opts.AttestationRenewalThresholdSeconds,
			ReportValidityPeriodMinutes:   opts.AttestationValidityPeriodMinutes,
			AttestationVerifyRegisters:    opts.AttestationVerifyRegisters,
			AttestationApprovedRegister1:  opts.AttestationApprovedRegister1,
			AttestationApprovedRegister2:  opts.AttestationApprovedRegister2,
			AttestationApprovedRegister3:  opts.AttestationApprovedRegister3,
			Logger:                        opts.Logger.Sugar(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create attestation manager: %w", err)
		}

		sindriClient.verificationMgr = manager
	}

	return sindriClient, nil
}
