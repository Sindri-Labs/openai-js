package clientmodels

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
	"github.com/cloudflare/circl/kem"
)

type SindriEncryption struct {
	EncryptedPayload []byte        `json:"encrypted_payload,omitempty" validate:"required"`
	ServerPublicKey  kem.PublicKey `json:"server_public_key,omitzero" validate:"required"`
	ClientPublicKey  kem.PublicKey `json:"client_public_key,omitzero"`
	EncapsulatedKey  []byte        `json:"encapsulated_key,omitempty" validate:"required"`
}

// MarshalJSON implements json.Marshaler interface
func (s SindriEncryption) MarshalJSON() ([]byte, error) {
	type Alias struct {
		EncryptedPayload string `json:"encrypted_payload,omitempty"`
		ServerPublicKey  string `json:"server_public_key,omitempty"`
		ClientPublicKey  string `json:"client_public_key,omitempty"`
		EncapsulatedKey  string `json:"encapsulated_key,omitempty"`
	}

	alias := Alias{}

	if len(s.EncryptedPayload) > 0 {
		alias.EncryptedPayload = hex.EncodeToString(s.EncryptedPayload)
	}

	if s.ServerPublicKey != nil {
		serverPublic, err := cryptos.HexStringFromPublicKey(s.ServerPublicKey)
		if err != nil {
			return nil, err
		}
		alias.ServerPublicKey = serverPublic
	}

	if s.ClientPublicKey != nil {
		clientPublic, err := cryptos.HexStringFromPublicKey(s.ClientPublicKey)
		if err != nil {
			return nil, err
		}
		alias.ClientPublicKey = clientPublic
	}

	if len(s.EncapsulatedKey) > 0 {
		alias.EncapsulatedKey = hex.EncodeToString(s.EncapsulatedKey)
	}

	return json.Marshal(alias)
}

// UnmarshalJSON implements json.Unmarshaler interface
func (s *SindriEncryption) UnmarshalJSON(data []byte) error {
	type Alias struct {
		EncryptedPayload string `json:"encrypted_payload,omitempty"`
		ServerPublicKey  string `json:"server_public_key,omitempty"`
		ClientPublicKey  string `json:"client_public_key,omitempty"`
		EncapsulatedKey  string `json:"encapsulated_key,omitempty"`
	}

	var alias Alias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	if alias.EncryptedPayload != "" {
		if encryptedPayload, err := hex.DecodeString(alias.EncryptedPayload); err != nil {
			return err
		} else {
			s.EncryptedPayload = encryptedPayload
		}
	}

	if alias.EncapsulatedKey != "" {
		if encapsulatedKey, err := hex.DecodeString(alias.EncapsulatedKey); err != nil {
			return err
		} else {
			s.EncapsulatedKey = encapsulatedKey
		}
	}

	if alias.ServerPublicKey != "" {
		if serverPublic, err := cryptos.PublicKeyFromHexString(alias.ServerPublicKey); err != nil {
			return err
		} else {
			s.ServerPublicKey = serverPublic
		}
	}

	if alias.ClientPublicKey != "" {
		if clientPublic, err := cryptos.PublicKeyFromHexString(alias.ClientPublicKey); err != nil {
			return err
		} else {
			s.ClientPublicKey = clientPublic
		}
	}

	return validate.Struct(s)
}

func EncryptPrivateFields(privateFields any, keys *cryptos.EncryptionKeys) (*cryptos.EncryptionBundle, error) {
	privateFieldsBytes, err := json.Marshal(privateFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private fields: %w", err)
	}

	bundle, err := cryptos.Encrypt(privateFieldsBytes, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private fields: %w", err)
	}

	return bundle, nil
}
