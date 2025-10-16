package clientmodels

import (
	"encoding/json"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
)

type ChatCompletionChunkPrivateFields struct {
	Choices           []any  `json:"choices,omitempty"`
	ServiceTier       string `json:"service_tier,omitempty"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
}

type ChatCompletionChunkSharedFields struct {
	ID      string `json:"id,omitempty"`
	Created int64  `json:"created,omitempty"`
	Model   string `json:"model,omitempty"`
	Object  any    `json:"object,omitzero"`
	Usage   any    `json:"usage,omitzero"`
}

type ChatCompletionChunk struct {
	ChatCompletionChunkPrivateFields
	ChatCompletionChunkSharedFields
}

type EncryptedChatCompletionChunk struct {
	ChatCompletionChunkSharedFields
	Sindri *SindriEncryption `json:"sindri,omitempty" validate:"required"`
}

func (c *EncryptedChatCompletionChunk) UnmarshalJSON(data []byte) error {
	type Alias EncryptedChatCompletionChunk
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

// Decrypts an encrypted chat completion chunk using the provided keys
func (c *EncryptedChatCompletionChunk) Decrypt(keys *cryptos.EncryptionKeys) (*ChatCompletionChunk, error) {
	bundle := &cryptos.EncryptionBundle{
		CipherText:      c.Sindri.EncryptedPayload,
		EncapsulatedKey: c.Sindri.EncapsulatedKey,
	}

	decryptKeys := &cryptos.EncryptionKeys{
		ServerPublicKey:  c.Sindri.ServerPublicKey,
		ClientPublicKey:  keys.ClientPublicKey,
		ClientPrivateKey: keys.ClientPrivateKey,
	}

	decryptedBytes, err := cryptos.Decrypt(bundle, decryptKeys)
	if err != nil {
		return nil, err
	}

	var privateFields ChatCompletionChunkPrivateFields
	if err := json.Unmarshal(decryptedBytes, &privateFields); err != nil {
		return nil, err
	}

	chunk := &ChatCompletionChunk{
		ChatCompletionChunkPrivateFields: privateFields,
		ChatCompletionChunkSharedFields:  c.ChatCompletionChunkSharedFields,
	}

	return chunk, nil
}
