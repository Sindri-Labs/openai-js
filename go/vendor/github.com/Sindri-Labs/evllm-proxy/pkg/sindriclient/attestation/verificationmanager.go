package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/httpclient"
	"github.com/cloudflare/circl/kem"
	"github.com/google/go-tdx-guest/proto/tdx"
	"go.uber.org/zap"
)

const (
	// The amount of time to wait before trying to renew an invalid server attestation.
	renewalRetryWaitSeconds int64 = 15
)

var (
	ErrExpired  = errors.New("server verification expired")
	ErrNoReport = errors.New("server verification report has not been acquired yet")
)

// ServerAttestation holds the details of a single attestation report for a server.
type ServerAttestation struct {
	report        *AttestationReport
	acquiredAt    int64
	expiresAt     int64
	invalidReason error
	publicKey     kem.PublicKey
	renewAfter    int64
}

// GetPublicKey returns the public key associated with the server attestation.
func (s *ServerAttestation) GetPublicKey() kem.PublicKey {
	return s.publicKey
}

// IsValid checks if the server attestation is still valid.
// The server attestation is considered invalid if:
// - it has an invalid reason set.
// - it has expired (current time is past expiresAt).
// If there is no invalid reason and it has not expired, it is considered valid.
func (s *ServerAttestation) IsValid() (bool, error) {
	switch {
	case s.report == nil:
		return false, ErrNoReport
	case s.invalidReason != nil:
		return false, s.invalidReason
	case s.expiresAt == 0:
		return true, nil
	case time.Now().Unix() < s.expiresAt:
		return true, nil
	default:
		return false, ErrExpired
	}
}

// ShouldRenew checks if the server attestation should be renewed.
func (s *ServerAttestation) ShouldRenew() bool {
	// If there is no report, we should renew.
	if s.report == nil {
		return true
	}

	// Renew if renewAfter is set and the current time is past the renewAfter time.
	if s.renewAfter > 0 && time.Now().Unix() >= s.renewAfter {
		return true
	}

	// Renew if the server attestation is expired.
	if s.expiresAt > 0 && time.Now().Unix() >= s.expiresAt {
		return true
	}

	if s.invalidReason != nil {
		// If the attestation is invalid, we should try to renew it after a delay
		tryAgainAfter := s.acquiredAt + renewalRetryWaitSeconds
		if tryAgainAfter <= time.Now().Unix() {
			return true
		}
	}

	return false
}

// VerificationManagerOptions for the VerificationManager.
type VerificationManagerOptions struct {
	// ManagerContext is a context used for maintaining the verification manager's lifecycle.
	ManagerContext context.Context
	// The URL at which the attestation report can be requested.
	ReportRequestURL string
	// ReportRequestAPIKey is the API key used to authenticate requests for the attestation report.
	ReportRequestAPIKey string
	// ReportRequestTimeout is the maximum time to wait for an attestation request to complete.
	ReportRequestTimeout time.Duration
	// ReportRenewalThresholdSeconds is the number of seconds before the report expires that it should be renewed.
	// Only used if ReportValidityPeriodMinutes is greater than 0.
	// A value of 0 means the report is renewed immediately before it expires.
	ReportRenewalThresholdSeconds int
	// ReportValidityPeriodMinutes is the number of minutes for which the attestation report is valid.
	// A value of 0 means the report never expires.
	ReportValidityPeriodMinutes int
	// AttestationVerifyRegisters indicates whether the attestation should verify registers.
	// If true, the attestation will verify registers.
	AttestationVerifyRegisters bool
	// AttestationApprovedRegister1 is an optional list of approved registers for attestation.
	AttestationApprovedRegister1 []string
	// AttestationApprovedRegister2 is an optional list of approved registers for attestation.
	AttestationApprovedRegister2 []string
	// AttestationApprovedRegister3 is an optional list of approved registers for attestation.
	AttestationApprovedRegister3 []string
	// Logger that will be used for logging within the verification manager.
	Logger *zap.SugaredLogger
}

// Validate checks if the VerificationManagerOptions are valid.
func (o *VerificationManagerOptions) Validate() error {
	if o.ManagerContext == nil {
		return errors.New("manager context cannot be nil")
	}
	if o.ReportRequestURL == "" {
		return errors.New("report request URL cannot be empty")
	}
	// ReportRequestAPIKey is now optional - if not set, will use passed Authorization header
	if o.ReportRequestTimeout < 0 {
		return errors.New("report request timeout must be greater than or equal to 0")
	}
	if o.ReportRenewalThresholdSeconds < 0 {
		return errors.New("report renewal threshold seconds cannot be negative")
	}
	if o.ReportValidityPeriodMinutes < 0 {
		return errors.New("report validity period minutes cannot be negative")
	}
	if o.Logger == nil {
		return errors.New("logger cannot be nil")
	}
	return nil
}

// VerificationManager is responsible for managing the attestation verification process.
// It will maintain a current attestation and handle renewals as needed.
type VerificationManager struct {
	reportRequest                 *httpclient.HttpRequest
	reportRequestTimeout          time.Duration
	reportRenewalThresholdSeconds int
	reportValidityPeriodMinutes   int
	verifyRegisters               bool
	rtmr1                         []string
	rtmr2                         []string
	rtmr3                         []string
	serverAttestation             *ServerAttestation
	mgrCtx                        context.Context
	logger                        *zap.SugaredLogger
	mutex                         sync.Mutex
}

// getNewReport retrieves a new attestation report from the server.
func (vm *VerificationManager) getNewReport() (*AttestationReport, error) {
	ctx, cancelRequest := context.WithTimeout(vm.mgrCtx, vm.reportRequestTimeout)
	defer cancelRequest()

	response, err := vm.reportRequest.Exec(ctx, nil, nil)
	if err != nil {
		vm.logger.Errorw("Failed to get new attestation report", "error", err)
		return nil, err
	}
	defer response.Body.Close()

	var report AttestationReport
	if err := json.NewDecoder(response.Body).Decode(&report); err != nil {
		vm.logger.Errorw("Failed to decode attestation report", "error", err)
		return nil, err
	}

	zap.S().Debugw("Received new attestation report", "report", report)

	return &report, nil
}

// getExpirationTime calculates the expiration time for the attestation report.
func (vm *VerificationManager) getExpirationTime(createdAt int64) int64 {
	if vm.reportValidityPeriodMinutes == 0 {
		return 0 // No expiration
	}
	return createdAt + int64(vm.reportValidityPeriodMinutes*60)
}

// getRenewalTime calculates the time at which the report should be renewed.
func (vm *VerificationManager) getRenewalTime(expiresAt int64) int64 {
	if vm.reportRenewalThresholdSeconds == 0 {
		return 0 // No renewal needed
	}
	return expiresAt - int64(vm.reportRenewalThresholdSeconds)
}

// getNewServerAttestation creates a new ServerAttestation instance.
func (vm *VerificationManager) getNewServerAttestation() *ServerAttestation {
	var invalidReason error

	// Get a new attestation report.
	report, err := vm.getNewReport()
	if err != nil {
		vm.logger.Errorw("Failed to get new attestation report", "error", err)
		invalidReason = err
	}

	// Perform offline verification of the attestation report.
	if invalidReason == nil {
		tdxQuote := &tdx.QuoteV4{
			Header:         report.Quote.Header,
			TdQuoteBody:    report.Quote.TdQuoteBody,
			SignedDataSize: report.Quote.QuoteSignature.SignedDataSize,
			SignedData:     report.Quote.QuoteSignature.SignedData,
			ExtraBytes:     report.Quote.QuoteSignature.ExtraBytes,
		}

		if err := verifyOffline(tdxQuote, &report.Collateral, report.Metadata.Fmspc, report.Metadata.CAType); err != nil {
			vm.logger.Errorw("Failed to verify attestation", "error", err)
			invalidReason = err
		}
	}

	// Verify the registers if verification is enabled.
	if invalidReason == nil && vm.verifyRegisters {
		allowedRegisters := [3][]string{vm.rtmr1, vm.rtmr2, vm.rtmr3}
		if err := validateRegisters(report.Quote.TdQuoteBody, allowedRegisters); err != nil {
			vm.logger.Errorw("RTMR validation failed", "error", err)
			invalidReason = err
		}
	}

	// Extract the public key from the report metadata.
	var publicKey kem.PublicKey
	if invalidReason == nil {
		if pk, err := report.Metadata.extractServerKey(); err != nil {
			vm.logger.Errorw("Failed to extract server key", "error", err)
			invalidReason = err
		} else {
			publicKey = pk
		}
	}

	// Create and return a new ServerAttestation instance.
	acquiredAt := time.Now().Unix()
	expiresAt := vm.getExpirationTime(acquiredAt)
	renewAfter := vm.getRenewalTime(expiresAt)

	newServerAttestation := &ServerAttestation{
		acquiredAt:    acquiredAt,
		expiresAt:     expiresAt,
		renewAfter:    renewAfter,
		invalidReason: invalidReason,
		report:        report,
		publicKey:     publicKey,
	}

	return newServerAttestation
}

// GetServerAttestation retrieves the current server attestation.
// If the attestation is invalid, it will attempt to renew it.
func (vm *VerificationManager) GetServerAttestation() *ServerAttestation {
	if vm.serverAttestation == nil {
		vm.Renew()
		return vm.serverAttestation
	}

	if isValid, _ := vm.serverAttestation.IsValid(); isValid {
		return vm.serverAttestation
	}

	vm.Renew()
	return vm.serverAttestation
}

// Renew attempts to renew the server attestation.
func (vm *VerificationManager) Renew() {
	vm.mutex.Lock()
	defer vm.mutex.Unlock()

	if vm.serverAttestation != nil && !vm.serverAttestation.ShouldRenew() {
		return
	}

	vm.serverAttestation = vm.getNewServerAttestation()

	isValid, invalidReason := vm.serverAttestation.IsValid()
	vm.logger.Infow("renewing server attestation",
		"valid", isValid,
		"invalidReason", invalidReason,
		"acquiredAt", vm.serverAttestation.acquiredAt,
		"expiresAt", vm.serverAttestation.expiresAt,
		"renewAfter", vm.serverAttestation.renewAfter,
	)
}

// StartEarlyRenewal will periodically check if the server attestation needs to be renewed.
func (vm *VerificationManager) StartEarlyRenewal() {
	for {
		select {
		case <-vm.mgrCtx.Done():
			return
		case <-time.After(time.Duration(5 * time.Second)):
			vm.Renew()
		}
	}
}

// NewVerificationManager creates a new VerificationManager instance with the provided options.
func NewVerificationManager(opts VerificationManagerOptions) (*VerificationManager, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}
	// Only set Authorization header if API key is provided
	if opts.ReportRequestAPIKey != "" {
		headers["Authorization"] = "Bearer " + opts.ReportRequestAPIKey
	}

	manager := &VerificationManager{
		reportRequest: &httpclient.HttpRequest{
			Client:  &http.Client{},
			Logger:  opts.Logger,
			Method:  http.MethodGet,
			URL:     opts.ReportRequestURL,
			Headers: headers,
		},
		reportRequestTimeout:          opts.ReportRequestTimeout,
		reportRenewalThresholdSeconds: opts.ReportRenewalThresholdSeconds,
		reportValidityPeriodMinutes:   opts.ReportValidityPeriodMinutes,
		verifyRegisters:               opts.AttestationVerifyRegisters,
		rtmr1:                         opts.AttestationApprovedRegister1,
		rtmr2:                         opts.AttestationApprovedRegister2,
		rtmr3:                         opts.AttestationApprovedRegister3,
		mgrCtx:                        opts.ManagerContext,
		logger:                        opts.Logger,
	}

	if manager.reportRenewalThresholdSeconds > 0 && manager.reportValidityPeriodMinutes > 0 {
		go manager.StartEarlyRenewal()
	}

	return manager, nil
}
