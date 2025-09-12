package attestation

import (
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// verifyOffline performs offline verification of a TDX quote using pre-fetched collateral data.
func verifyOffline(quote *tdx.QuoteV4, collateral *CollateralData, fmspc []byte, caType string) error {
	opts := &verify.Options{
		TrustedRoots:     nil,  // Use embedded Intel SGX Root CA.
		GetCollateral:    true, // Enable full verification with TCB checks.
		CheckRevocations: true, // Enable revocation checking using offline CRLs.
		Getter: &OfflineHTTPSGetter{
			collateral: collateral,
			fmspc:      fmspc,
			caType:     caType,
		},
		Now: time.Now(),
	}
	return verify.TdxQuote(quote, opts)
}

func validateRegisters(quote *tdx.TDQuoteBody, allowedRegisters [3][]string) error {
	for i := 1; i < 4; i++ {
		actual := hex.EncodeToString(quote.Rtmrs[i])
		allowed := allowedRegisters[i-1]
		if !slices.Contains(allowed, actual) {
			return fmt.Errorf("RTMR %d validation failed: expected one of %v, got %s", i, allowed, actual)
		}
	}

	return nil
}
