package clientmodels

import (
	"encoding/json"
	"fmt"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
)

// ChatCompletionPrivateFields contains fields that are specific to the encrypted chat completion response.
type ChatCompletionPrivateFields struct {
	Choices           []any  `json:"choices,omitempty"`
	ServiceTier       string `json:"service_tier,omitempty"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
}

// ChatCompletionSharedFields contains fields that are common to all chat completion responses.
type ChatCompletionSharedFields struct {
	Created int64  `json:"created,omitempty"`
	ID      string `json:"id,omitempty"`
	Model   string `json:"model,omitempty"`
	Object  string `json:"object,omitempty"`
	Usage   any    `json:"usage,omitzero"`
}

// Represents a chat completion response returned by model, based on the provided input.
type ChatCompletion struct {
	ChatCompletionPrivateFields
	ChatCompletionSharedFields
}

type EncryptedChatCompletion struct {
	ChatCompletionSharedFields
	Sindri *SindriEncryption `json:"sindri,omitzero" validate:"required"`
}

func (c *EncryptedChatCompletion) UnmarshalJSON(data []byte) error {
	type Alias EncryptedChatCompletion
	alias := &struct {
		*Alias
	}{
		Alias: (*Alias)(c),
	}

	if err := json.Unmarshal(data, alias); err != nil {
		return err
	}

	return validate.Struct(c)
}

// Decrypts an encrypted chat completion using the provided keys
func (e *EncryptedChatCompletion) Decrypt(keys *cryptos.EncryptionKeys) (*ChatCompletion, error) {
	bundle := &cryptos.EncryptionBundle{
		CipherText:      e.Sindri.EncryptedPayload,
		EncapsulatedKey: e.Sindri.EncapsulatedKey,
	}

	decryptKeys := &cryptos.EncryptionKeys{
		ServerPublicKey:  e.Sindri.ServerPublicKey,
		ClientPublicKey:  keys.ClientPublicKey,
		ClientPrivateKey: keys.ClientPrivateKey,
	}

	decryptedBytes, err := cryptos.Decrypt(bundle, decryptKeys)
	if err != nil {
		return nil, err
	}

	var privateFields ChatCompletionPrivateFields
	if err := json.Unmarshal(decryptedBytes, &privateFields); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted private fields: %w", err)
	}

	completion := &ChatCompletion{
		ChatCompletionPrivateFields: privateFields,
		ChatCompletionSharedFields:  e.ChatCompletionSharedFields,
	}

	return completion, nil
}
