package clientmodels

import (
	"encoding/json"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
)

type LegacyCompletionParamsPrivateFields struct {
	Prompt           string           `json:"prompt,omitempty"`
	BestOf           string           `json:"best_of,omitempty"`
	Echo             bool             `json:"echo,omitempty"`
	FrequencyPenalty float64          `json:"frequency_penalty,omitempty"`
	LogitBias        map[string]int64 `json:"logit_bias,omitempty"`
	Logprobs         int64            `json:"logprobs,omitempty"`
	MaxTokens        int64            `json:"max_tokens,omitempty"`
	N                int64            `json:"n,omitempty"`
	PresencePenalty  float64          `json:"presence_penalty,omitempty"`
	Seed             int64            `json:"seed,omitempty"`
	Stop             []string         `json:"stop,omitempty"`
	Suffix           string           `json:"suffix,omitempty"`
	Temperature      float64          `json:"temperature,omitempty"`
	TopP             float64          `json:"top_p,omitempty"`
}

type LegacyCompletionParamsSharedFields struct {
	Stream        bool   `json:"stream,omitempty"`
	StreamOptions any    `json:"stream_options,omitzero"`
	Model         string `json:"model,omitempty"`
	User          string `json:"user,omitempty"`
}

type LegacyCompletionParams struct {
	LegacyCompletionParamsPrivateFields
	LegacyCompletionParamsSharedFields
}

func (p *LegacyCompletionParams) Encrypt(keys *cryptos.EncryptionKeys) (*EncryptedLegacyCompletionParams, error) {
	bundle, err := EncryptPrivateFields(p.LegacyCompletionParamsPrivateFields, keys)
	if err != nil {
		return nil, err
	}

	encrypted := &EncryptedLegacyCompletionParams{
		LegacyCompletionParamsSharedFields: p.LegacyCompletionParamsSharedFields,
		Sindri: &SindriEncryption{
			EncryptedPayload: bundle.CipherText,
			EncapsulatedKey:  bundle.EncapsulatedKey,
			ServerPublicKey:  keys.ServerPublicKey,
			ClientPublicKey:  keys.ClientPublicKey,
		},
	}

	return encrypted, nil
}

type EncryptedLegacyCompletionParams struct {
	LegacyCompletionParamsSharedFields
	Sindri *SindriEncryption `json:"sindri,omitzero" validate:"required"`
}

func (c *EncryptedLegacyCompletionParams) UnmarshalJSON(data []byte) error {
	type Alias EncryptedLegacyCompletionParams
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
