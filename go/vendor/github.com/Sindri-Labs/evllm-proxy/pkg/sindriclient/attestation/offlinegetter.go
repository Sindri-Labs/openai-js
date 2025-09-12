package attestation

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-tdx-guest/verify/trust"
)

var _ trust.HTTPSGetter = (*OfflineHTTPSGetter)(nil)

// OfflineHTTPSGetter implements trust.HTTPSGetter interface to provide
// pre-fetched collateral data instead of making actual HTTP requests.
// This enables completely offline attestation verification.
type OfflineHTTPSGetter struct {
	collateral *CollateralData
	fmspc      []byte
	caType     string
}

// Get implements trust.HTTPSGetter interface by returning pre-fetched collateral
// data based on the requested URL instead of making actual HTTP requests.
func (o *OfflineHTTPSGetter) Get(requestURL string) (map[string][]string, []byte, error) {
	if o.collateral == nil {
		return nil, nil, fmt.Errorf("no collateral data available")
	}

	// Parse the URL to determine what collateral to return
	switch {
	case strings.Contains(requestURL, "/tdx/certification/v4/tcb"):
		// TCB Info request
		if len(o.collateral.TCBInfo) == 0 {
			return nil, nil, fmt.Errorf("TCB info not available in collateral")
		}

		// Return TCB info with certificate chain in headers
		headers := make(map[string][]string)
		if o.collateral.TCBInfoCerts.Intermediate != "" && o.collateral.TCBInfoCerts.Root != "" {
			// Concatenate certificates with a single newline between them.
			// The upstream library expects the exact format as returned by Intel's API.
			certChain := o.collateral.TCBInfoCerts.Intermediate
			if !strings.HasSuffix(certChain, "\n") {
				certChain += "\n"
			}
			certChain += o.collateral.TCBInfoCerts.Root
			// URL encode the certificate chain as expected by upstream library
			encodedCertChain := url.QueryEscape(certChain)
			headers["Tcb-Info-Issuer-Chain"] = []string{encodedCertChain}
		}

		return headers, []byte(o.collateral.TCBInfo), nil

	case strings.Contains(requestURL, "/tdx/certification/v4/qe/identity"):
		// QE Identity request
		if len(o.collateral.QEIdentity) == 0 {
			return nil, nil, fmt.Errorf("QE identity not available in collateral")
		}

		// Return QE identity with certificate chain in headers
		headers := make(map[string][]string)
		if o.collateral.QEIdentityCerts.Intermediate != "" &&
			o.collateral.QEIdentityCerts.Root != "" {
			// Concatenate certificates with a single newline between them.
			// The upstream library expects the exact format as returned by Intel's API.
			certChain := o.collateral.QEIdentityCerts.Intermediate
			if !strings.HasSuffix(certChain, "\n") {
				certChain += "\n"
			}
			certChain += o.collateral.QEIdentityCerts.Root
			// URL encode the certificate chain as expected by upstream library
			encodedCertChain := url.QueryEscape(certChain)
			headers["Sgx-Enclave-Identity-Issuer-Chain"] = []string{encodedCertChain}
		}

		return headers, []byte(o.collateral.QEIdentity), nil

	case strings.Contains(requestURL, "/sgx/certification/v4/pckcrl"):
		// PCK CRL request
		if len(o.collateral.PCKCRL) == 0 {
			return nil, nil, fmt.Errorf("PCK CRL not available in collateral")
		}

		// Return PCK CRL with certificate chain in headers
		headers := make(map[string][]string)
		if o.collateral.PCKCRLCerts.Intermediate != "" && o.collateral.PCKCRLCerts.Root != "" {
			// Concatenate certificates with a single newline between them.
			// The upstream library expects the exact format as returned by Intel's API.
			certChain := o.collateral.PCKCRLCerts.Intermediate
			if !strings.HasSuffix(certChain, "\n") {
				certChain += "\n"
			}
			certChain += o.collateral.PCKCRLCerts.Root
			// URL encode the certificate chain as expected by upstream library
			encodedCertChain := url.QueryEscape(certChain)
			headers["Sgx-Pck-Crl-Issuer-Chain"] = []string{encodedCertChain}
		}

		return headers, o.collateral.PCKCRL, nil

	case strings.Contains(requestURL, "trustedservices.intel.com"):
		// Root CA CRL request
		if len(o.collateral.RootCACRL) == 0 {
			return nil, nil, fmt.Errorf("root CA CRL not available in collateral")
		}

		return nil, o.collateral.RootCACRL, nil

	default:
		return nil, nil, fmt.Errorf("unsupported URL for offline verification: %s", requestURL)
	}
}

// GetFMSPC returns the FMSPC value used for this getter.
func (o *OfflineHTTPSGetter) GetFMSPC() string {
	return hex.EncodeToString(o.fmspc)
}

// GetCAType returns the CA type used for this getter.
func (o *OfflineHTTPSGetter) GetCAType() string {
	return o.caType
}
