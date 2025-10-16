package attestation

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
	"github.com/cloudflare/circl/kem"
	"github.com/google/go-tdx-guest/proto/tdx"
)

// AttestationReport represents the complete attestation report structure
type AttestationReport struct {
	Metadata   AttestationMetadata `json:"metadata"`
	Quote      Quote               `json:"quote"`
	Collateral CollateralData      `json:"collateral"`
}

// AttestationMetadata contains metadata for the attestation report
type AttestationMetadata struct {
	Version     string    `json:"version"`
	CollectedAt time.Time `json:"collected_at"`
	Fmspc       HexBytes  `json:"fmspc"`
	CAType      string    `json:"ca_type"`
	PublicKey   *string   `json:"public_key,omitempty"`
}

// extractServerKey extracts the server's public key from the attestation metadata.
func (m *AttestationMetadata) extractServerKey() (kem.PublicKey, error) {
	if m.PublicKey == nil {
		return nil, fmt.Errorf("failed to decode public key: public key is nil")
	}
	if publicKeyBytes, err := hex.DecodeString(*m.PublicKey); err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	} else {
		serverPublicKey, err := cryptos.PublicKeyFromBytes(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to extract public key: %w", err)
		}
		return serverPublicKey, nil
	}
}

// Quote represents the complete TDX quote structure
type Quote struct {
	Header         *tdx.Header      `json:"header"`
	TdQuoteBody    *tdx.TDQuoteBody `json:"td_quote_body"`
	QuoteSignature *QuoteSignature  `json:"quote_signature"`
	Metadata       json.RawMessage  `json:"metadata"`
}

func (q *Quote) UnmarshalJSON(data []byte) error {
	var quoteRaw struct {
		Header *struct {
			Version            uint32   `json:"version,omitempty"`
			AttestationKeyType uint32   `json:"attestation_key_type,omitempty"`
			TeeType            uint32   `json:"tee_type,omitempty"`
			QeSvn              HexBytes `json:"qe_svn,omitempty"`
			PceSvn             HexBytes `json:"pce_svn,omitempty"`
			QeVendorId         HexBytes `json:"qe_vendor_id,omitempty"`
			UserData           HexBytes `json:"user_data,omitempty"`
		} `json:"header"`
		TdQuoteBody *struct {
			TeeTcbSvn      HexBytes   `json:"tee_tcb_svn,omitempty"`
			MrSeam         HexBytes   `json:"mr_seam,omitempty"`
			MrSignerSeam   HexBytes   `json:"mr_signer_seam,omitempty"`
			SeamAttributes HexBytes   `json:"seam_attributes,omitempty"`
			TdAttributes   HexBytes   `json:"td_attributes,omitempty"`
			Xfam           HexBytes   `json:"xfam,omitempty"`
			MrTd           HexBytes   `json:"mr_td,omitempty"`
			MrConfigId     HexBytes   `json:"mr_config_id,omitempty"`
			MrOwner        HexBytes   `json:"mr_owner,omitempty"`
			MrOwnerConfig  HexBytes   `json:"mr_owner_config,omitempty"`
			Rtmrs          []HexBytes `json:"rtmrs,omitempty"`
			ReportData     HexBytes   `json:"report_data,omitempty"`
		} `json:"td_quote_body"`
		QuoteSignature *QuoteSignature `json:"quote_signature"`
		Metadata       json.RawMessage `json:"metadata"`
	}

	if err := json.Unmarshal(data, &quoteRaw); err != nil {
		return fmt.Errorf("failed to unmarshal Quote: %w", err)
	}

	// Set teh metadata
	q.Metadata = quoteRaw.Metadata

	// Set the header to an instnce of tdx.Header
	if quoteRaw.Header != nil {
		q.Header = &tdx.Header{
			Version:            quoteRaw.Header.Version,
			AttestationKeyType: quoteRaw.Header.AttestationKeyType,
			TeeType:            quoteRaw.Header.TeeType,
			QeSvn:              quoteRaw.Header.QeSvn,
			PceSvn:             quoteRaw.Header.PceSvn,
			QeVendorId:         quoteRaw.Header.QeVendorId,
			UserData:           quoteRaw.Header.UserData,
		}
	}

	if quoteRaw.TdQuoteBody != nil {

		// Convert the []HexBytes to [][]byte for use in TDQuoteBody
		rtmrsBytes := make([][]byte, len(quoteRaw.TdQuoteBody.Rtmrs))
		for i, hexBytes := range quoteRaw.TdQuoteBody.Rtmrs {
			rtmrsBytes[i] = []byte(hexBytes)
		}

		q.TdQuoteBody = &tdx.TDQuoteBody{
			TeeTcbSvn:      quoteRaw.TdQuoteBody.TeeTcbSvn,
			MrSeam:         quoteRaw.TdQuoteBody.MrSeam,
			MrSignerSeam:   quoteRaw.TdQuoteBody.MrSignerSeam,
			SeamAttributes: quoteRaw.TdQuoteBody.SeamAttributes,
			TdAttributes:   quoteRaw.TdQuoteBody.TdAttributes,
			Xfam:           quoteRaw.TdQuoteBody.Xfam,
			MrTd:           quoteRaw.TdQuoteBody.MrTd,
			MrConfigId:     quoteRaw.TdQuoteBody.MrConfigId,
			MrOwner:        quoteRaw.TdQuoteBody.MrOwner,
			MrOwnerConfig:  quoteRaw.TdQuoteBody.MrOwnerConfig,
			Rtmrs:          rtmrsBytes,
			ReportData:     quoteRaw.TdQuoteBody.ReportData,
		}
	}

	if quoteRaw.QuoteSignature != nil {
		q.QuoteSignature = quoteRaw.QuoteSignature
	}

	return nil
}

// QuoteSignature contains quote signature information
type QuoteSignature struct {
	SignedDataSize uint32                          `json:"signed_data_size"`
	SignedData     *tdx.Ecdsa256BitQuoteV4AuthData `json:"signed_data"`
	ExtraBytes     HexBytes                        `json:"extra_bytes"`
}

func (q *QuoteSignature) UnmarshalJSON(data []byte) error {
	var quoteSigRaw struct {
		SignedDataSize uint32 `json:"signed_data_size"`
		SignedData     *struct {
			Signature         HexBytes `json:"signature"`
			AttestationKey    HexBytes `json:"attestation_key"`
			CertificationData *struct {
				CertificationDataType uint32 `json:"certification_data_type"`
				// Add the Size Back Later
				QEReport *struct {
					CpuSvn     HexBytes `json:"cpu_svn"`
					MiscSelect uint32   `json:"misc_select"`
					Reserved1  HexBytes `json:"reserved1"`
					Attributes HexBytes `json:"attributes"`
					MrEnclave  HexBytes `json:"mr_enclave"`
					Reserved2  HexBytes `json:"reserved2"`
					MrSigner   HexBytes `json:"mr_signer"`
					Reserved3  HexBytes `json:"reserved3"`
					IsvProdId  uint32   `json:"isv_prod_id"`
					IsvSvn     uint32   `json:"isv_svn"`
					Reserved4  HexBytes `json:"reserved4"`
					ReportData HexBytes `json:"report_data"`
				} `json:"qe_report"`
				QEReportSignature HexBytes `json:"qe_report_signature,omitempty"`
				QEAuthData        *struct {
					ParsedDataSize uint32   `json:"parsed_data_size"`
					Data           HexBytes `json:"data"`
				} `json:"qe_auth_data,omitempty"`
				PCKCertificateChain *PCKCertificateChainData `json:"pck_certificate_chain"`
			} `json:"certification_data"`
		} `json:"signed_data"`
		ExtraBytes HexBytes `json:"extra_bytes"`
	}

	if err := json.Unmarshal(data, &quoteSigRaw); err != nil {
		return fmt.Errorf("failed to unmarshal QuoteSignature: %w", err)
	}

	q.SignedDataSize = quoteSigRaw.SignedDataSize
	q.ExtraBytes = quoteSigRaw.ExtraBytes
	if quoteSigRaw.SignedData != nil {
		signedData := quoteSigRaw.SignedData
		qeReportCertificationData := &tdx.QEReportCertificationData{
			QeReport: &tdx.EnclaveReport{
				CpuSvn:     signedData.CertificationData.QEReport.CpuSvn,
				MiscSelect: signedData.CertificationData.QEReport.MiscSelect,
				Reserved1:  signedData.CertificationData.QEReport.Reserved1,
				Attributes: signedData.CertificationData.QEReport.Attributes,
				MrEnclave:  signedData.CertificationData.QEReport.MrEnclave,
				Reserved2:  signedData.CertificationData.QEReport.Reserved2,
				MrSigner:   signedData.CertificationData.QEReport.MrSigner,
				Reserved3:  signedData.CertificationData.QEReport.Reserved3,
				IsvProdId:  signedData.CertificationData.QEReport.IsvProdId,
				IsvSvn:     signedData.CertificationData.QEReport.IsvSvn,
				Reserved4:  signedData.CertificationData.QEReport.Reserved4,
				ReportData: signedData.CertificationData.QEReport.ReportData,
			},
			QeReportSignature: signedData.CertificationData.QEReportSignature,
			QeAuthData: &tdx.QeAuthData{
				ParsedDataSize: signedData.CertificationData.QEAuthData.ParsedDataSize,
				Data:           signedData.CertificationData.QEAuthData.Data,
			},
			PckCertificateChainData: signedData.CertificationData.PCKCertificateChain.PCKCertificateChainData,
		}
		q.SignedData = &tdx.Ecdsa256BitQuoteV4AuthData{
			Signature:           signedData.Signature,
			EcdsaAttestationKey: signedData.AttestationKey,
			CertificationData: &tdx.CertificationData{
				CertificateDataType:       signedData.CertificationData.CertificationDataType,
				Size:                      calculateCertificationDataSize(qeReportCertificationData),
				QeReportCertificationData: qeReportCertificationData,
			},
		}
	}

	return nil
}

type PCKCertificateChainData struct {
	*tdx.PCKCertificateChainData
}

func (p *PCKCertificateChainData) UnmarshalJSON(data []byte) error {
	var certStr string
	if err := json.Unmarshal(data, &certStr); err != nil {
		return fmt.Errorf("failed to unmarshal PCKCertificateChainData: %w", err)
	}
	certBytes := []byte(certStr)

	p.PCKCertificateChainData = &tdx.PCKCertificateChainData{
		CertificateDataType: 5,
		Size:                uint32(len(certBytes)),
		PckCertChain:        certBytes,
	}

	return nil
}

type CollateralData struct {
	// TCB Info related.
	TCBInfo      string           `json:"tcb_info"`       // Raw TCB info JSON from PCS (exact bytes preserved).
	TCBInfoCerts CertificateChain `json:"tcb_info_certs"` // TCB info issuer chain.

	// QE Identity related.
	QEIdentity      string           `json:"qe_identity"`       // Raw QE identity JSON from PCS (exact bytes preserved).
	QEIdentityCerts CertificateChain `json:"qe_identity_certs"` // QE identity issuer chain.

	// CRL related.
	PCKCRL      []byte           `json:"pck_crl"`       // DER-encoded PCK CRL (in-memory: raw bytes, JSON: base64).
	PCKCRLCerts CertificateChain `json:"pck_crl_certs"` // PCK CRL issuer chain.
	RootCACRL   []byte           `json:"root_ca_crl"`   // DER-encoded Root CA CRL (in-memory: raw bytes, JSON: base64).
}

// CertificateChain contains PEM-encoded certificates.
type CertificateChain struct {
	Intermediate string `json:"intermediate"` // PEM-encoded intermediate cert.
	Root         string `json:"root"`         // PEM-encoded root cert.
}

// HexBytes is a custom type for unmarshalling hex-encoded byte arrays from JSON.
type HexBytes []byte

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var hexStr string
	if err := json.Unmarshal(data, &hexStr); err != nil {
		return err
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}

	*h = decoded
	return nil
}

// calculateCertificationDataSize calculates the total size of the certification data
func calculateCertificationDataSize(qeReport *tdx.QEReportCertificationData) uint32 {
	if qeReport == nil {
		return 0
	}

	size := uint32(0)

	// Enclave report is always 384 bytes (0x180)
	if qeReport.GetQeReport() != nil {
		size += 384
	}

	// QE report signature is always 64 bytes (0x40)
	if len(qeReport.GetQeReportSignature()) > 0 {
		size += 64
	}

	// QE auth data: 2 bytes for size + actual data
	if qeAuthData := qeReport.GetQeAuthData(); qeAuthData != nil {
		size += 2 + qeAuthData.GetParsedDataSize()
	}

	// PCK certificate chain: 2 bytes type + 4 bytes size + actual certificate chain
	if pckData := qeReport.GetPckCertificateChainData(); pckData != nil {
		size += 6 + pckData.GetSize()
	}

	return size
}
