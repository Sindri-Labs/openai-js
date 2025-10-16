package clientmodels

import (
	"encoding/json"

	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
)

type LegacyCompletionLogprobs struct {
	TextOffset    []int                `json:"text_offset,omitempty"`
	TokenLogprobs []float64            `json:"token_logprobs,omitempty"`
	Tokens        []string             `json:"tokens,omitempty"`
	TopLogprobs   []map[string]float64 `json:"top_logprobs,omitempty"`
}

type LegacyCompletionChoice struct {
	FinishReason string                    `json:"finish_reason,omitempty"`
	Index        int                       `json:"index,omitempty"`
	Text         string                    `json:"text,omitempty"`
	Logprobs     *LegacyCompletionLogprobs `json:"logprobs,omitzero"`
}

type LegacyCompletionPrivateFields struct {
	Choices []LegacyCompletionChoice `json:"choices,omitempty"`
}

type LegacyCompletionSharedFields struct {
	Created           int64  `json:"created,omitempty"`
	ID                string `json:"id,omitempty"`
	Model             string `json:"model,omitempty"`
	Object            string `json:"object,omitempty"`
	SystemFingerprint string `json:"system_fingerprint,omitempty"`
	Usage             any    `json:"usage,omitzero"`
}

type LegacyCompletion struct {
	LegacyCompletionPrivateFields
	LegacyCompletionSharedFields
}

type EncryptedLegacyCompletion struct {
	LegacyCompletionSharedFields
	Sindri *SindriEncryption `json:"sindri,omitzero"`
}

func (e *EncryptedLegacyCompletion) Decrypt(keys *cryptos.EncryptionKeys) (*LegacyCompletion, error) {
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

	var privateFields LegacyCompletionPrivateFields
	if err := json.Unmarshal(decryptedBytes, &privateFields); err != nil {
		return nil, err
	}

	legacyCompletion := &LegacyCompletion{
		LegacyCompletionPrivateFields: privateFields,
		LegacyCompletionSharedFields:  e.LegacyCompletionSharedFields,
	}

	return legacyCompletion, nil
}
