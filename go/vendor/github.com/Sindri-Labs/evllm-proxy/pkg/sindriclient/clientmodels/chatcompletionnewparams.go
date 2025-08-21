package clientmodels

import (
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
)

// ChatCompletionNewParamsPrivateFields represents the fields of the ChatCompletionNewParams
// that are considered private and should be encrypted when used in a private context.
type ChatCompletionNewParamsPrivateFields struct {
	Messages            any              `json:"messages,omitempty"`
	FrequencyPenalty    float64          `json:"frequency_penalty,omitempty"`
	Logprobs            bool             `json:"logprobs,omitempty"`
	MaxCompletionTokens int64            `json:"max_completion_tokens,omitempty"`
	MaxTokens           int64            `json:"max_tokens,omitempty"`
	N                   int64            `json:"n,omitempty"`
	PresencePenalty     float64          `json:"presence_penalty,omitempty"`
	Seed                int64            `json:"seed,omitempty"`
	Store               bool             `json:"store,omitempty"`
	Temperature         float64          `json:"temperature,omitempty"`
	TopLogprobs         int64            `json:"top_logprobs,omitempty"`
	TopP                float64          `json:"top_p,omitempty"`
	ParallelToolCalls   bool             `json:"parallel_tool_calls,omitempty"`
	Audio               any              `json:"audio,omitzero"`
	LogitBias           map[string]int64 `json:"logit_bias,omitempty"`
	Metadata            map[string]int64 `json:"metadata,omitempty"`
	Modalities          []string         `json:"modalities,omitempty"`
	ReasoningEffort     string           `json:"reasoning_effort,omitempty"`
	ServiceTier         string           `json:"service_tier,omitempty"`
	Stop                any              `json:"stop,omitzero"`
	FunctionCall        any              `json:"function_call,omitzero"`
	Functions           []any            `json:"functions,omitempty"` //nolint
	Prediction          any              `json:"prediction,omitzero"`
	ResponseFormat      any              `json:"response_format,omitzero"`
	ToolChoice          any              `json:"tool_choice,omitzero"`
	Tools               []any            `json:"tools,omitempty"`
	WebSearchOptions    any              `json:"web_search_options,omitzero"`
}

// ChatCompletionNewParamsSharedFields contains fields that are shared between public and private chat completions.
// These fields are not encrypted
type ChatCompletionNewParamsSharedFields struct {
	Model         string `json:"model,omitempty"`
	Stream        bool   `json:"stream,omitempty"`
	StreamOptions any    `json:"stream_options,omitzero"`
	User          string `json:"user,omitempty"`
}

// ChatCompletionNewParams shadows the openai.ChatCompletionNewParams struct
// to allow for custom modifications and additional fields.
type ChatCompletionNewParams struct {
	ChatCompletionNewParamsPrivateFields
	ChatCompletionNewParamsSharedFields
}

func (c *ChatCompletionNewParams) Encrypt(keys *cryptos.EncryptionKeys) (*EncryptedChatCompletionNewParams, error) {
	bundle, err := EncryptPrivateFields(c.ChatCompletionNewParamsPrivateFields, keys)
	if err != nil {
		return nil, err
	}

	encrypted := &EncryptedChatCompletionNewParams{
		ChatCompletionNewParamsSharedFields: c.ChatCompletionNewParamsSharedFields,
		Sindri: &SindriEncryption{
			EncryptedPayload: bundle.CipherText,
			EncapsulatedKey:  bundle.EncapsulatedKey,
			ServerPublicKey:  keys.ServerPublicKey,
			ClientPublicKey:  keys.ClientPublicKey,
		},
	}

	return encrypted, nil
}

// EncryptedChatCompletionNewParams moves the private fields from
// openai.ChatCompletionNewParams to a separate struct and encrypts them.
// This is used for private chat completions where sensitive data needs to be handled securely.
type EncryptedChatCompletionNewParams struct {
	ChatCompletionNewParamsSharedFields
	Sindri *SindriEncryption `json:"sindri,omitzero"`
}
