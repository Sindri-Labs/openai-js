package sindriclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	cm "github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/clientmodels"
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/cryptos"
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/httpclient"
)

// ChatCompletionNoStream sends a chat completion request to the Sindri API and returns the response.
// Pass an empty string for endpoint to use the default endpoint.
func (s *SindriClient) ChatCompletionNoStream(
	params *cm.ChatCompletionNewParams,
	td *cm.TraceMetadata,
	authHeader string,
	endpoint string,
) (*cm.ChatCompletion, error) {
	slogger := s.logger.Sugar().With("trace_metadata", td)

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Use configured API key if available, otherwise use passed auth header.
	if s.apiKey != "" {
		headers["Authorization"] = "Bearer " + s.apiKey
	} else if authHeader != "" {
		headers["Authorization"] = authHeader
	}

	// Use provided endpoint if available, otherwise use default.
	url := s.Endpoint(EndpointCompletion)
	if endpoint != "" {
		url = endpoint
	}

	request := httpclient.HttpRequest{
		Client:  s.httpClient,
		Logger:  slogger,
		Method:  http.MethodPost,
		URL:     url,
		Headers: headers,
	}

	var keys *cryptos.EncryptionKeys
	var payload any

	slogger.Debugw("chat completion request", "payload", params, "stream", false)
	if s.encryptionEnabled {
		if encKeys, err := s.getKeys(); err != nil {
			h := errHandler{err: fmt.Errorf("failed to get encryption keys: %w", err)}
			return nil, h.handleWith(slogger)
		} else {
			keys = encKeys
		}

		sealedRequest, err := params.Encrypt(keys)
		if err != nil {
			h := errHandler{err: fmt.Errorf("failed to encrypt chat completion request: %w", err)}
			return nil, h.handleWith(slogger)
		}

		slogger.Debugw("encrypted chat completion request", "payload", sealedRequest, "stream", false)
		payload = sealedRequest

	} else {
		payload = params
	}

	ctx, cancelRequest := context.WithTimeout(s.ctx, s.requestTimeout)
	defer cancelRequest()

	response, err := request.Exec(ctx, payload, nil)
	if err != nil {
		h := errHandler{err: err, meta: map[string]any{"url": request.URL, "method": request.Method}}
		return nil, h.handleWith(slogger)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		h := errHandler{err: fmt.Errorf("failed to read response body: %w", err)}
		return nil, h.handleWith(slogger)
	}

	var completion *cm.ChatCompletion
	if s.encryptionEnabled {
		var sealed cm.EncryptedChatCompletion
		if err := json.Unmarshal(responseBody, &sealed); err != nil {
			h := errHandler{err: fmt.Errorf("failed to unmarshal encrypted chat completion: %w", err)}
			return nil, h.handleWith(slogger)
		}

		slogger.Debugw("encrypted chat completion response", "payload", sealed, "stream", false)

		unsealed, err := sealed.Decrypt(keys)
		if err != nil {
			h := errHandler{err: fmt.Errorf("failed to decrypt chat completion: %w", err)}
			return nil, h.handleWith(slogger)
		}
		completion = unsealed

	} else {
		if err := json.Unmarshal(responseBody, &completion); err != nil {
			h := errHandler{err: fmt.Errorf("failed to unmarshal response body: %w", err)}
			return nil, h.handleWith(slogger)
		}
	}

	slogger.Debugw("chat completion response", "payload", completion, "stream", false)

	return completion, nil
}

// ChatCompletionStream streams chat completion events from the Sindri API.
// Pass an empty string for endpoint to use the default endpoint.
func (s *SindriClient) ChatCompletionStream(
	params *cm.ChatCompletionNewParams,
	meta *cm.TraceMetadata,
	authHeader string,
	endpoint string,
) (<-chan *cm.ChatCompletionChunk, <-chan error, error) {
	slogger := s.logger.Sugar().With("trace_metadata", meta)

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	// Use configured API key if available, otherwise use passed auth header.
	if s.apiKey != "" {
		headers["Authorization"] = "Bearer " + s.apiKey
	} else if authHeader != "" {
		headers["Authorization"] = authHeader
	}

	// Use provided endpoint if available, otherwise use default.
	url := s.Endpoint(EndpointCompletion)
	if endpoint != "" {
		url = endpoint
	}

	request := httpclient.HttpRequest{
		Client:  s.httpClient,
		Logger:  slogger,
		Method:  http.MethodPost,
		URL:     url,
		Headers: headers,
	}

	var keys *cryptos.EncryptionKeys
	var payload any

	slogger.Debugw("chat completion request", "payload", params, "stream", true)
	if s.encryptionEnabled {
		if encKeys, err := s.getKeys(); err != nil {
			h := errHandler{err: fmt.Errorf("failed to get encryption keys: %w", err)}
			return nil, nil, h.handleWith(slogger)
		} else {
			keys = encKeys
		}

		sealedRequest, err := params.Encrypt(keys)
		if err != nil {
			h := errHandler{err: fmt.Errorf("failed to encrypt chat completion request: %w", err)}
			return nil, nil, h.handleWith(slogger)
		}
		payload = sealedRequest

		slogger.Debugw("encrypted chat completion request", "payload", sealedRequest, "stream", false)
	} else {
		payload = params
	}

	// cancelRequest called in the goroutine below
	ctx, cancelRequest := context.WithTimeout(s.ctx, s.requestTimeout)

	response, err := request.Exec(ctx, payload, nil)
	if err != nil {
		defer cancelRequest()
		h := errHandler{err: err, meta: map[string]any{"url": request.URL, "method": request.Method}}
		return nil, nil, h.handleWith(slogger)
	}

	eventStream := make(chan *cm.ChatCompletionChunk, sseChanSize)
	errorStream := make(chan error, 1)

	go func() {
		defer cancelRequest()
		defer response.Body.Close()
		defer close(errorStream)
		defer close(eventStream)

		slogger.Debugw("Processing chat completion stream")

		// Scan the response body and send each line to the events channel
		scanner := bufio.NewScanner(response.Body)
		for scanner.Scan() {
			line := scanner.Text()

			if after, ok := strings.CutPrefix(line, ssePrefix); ok {
				data := strings.TrimSpace(after)

				if data != sseEndOfStreamIndicator {
					var chunk *cm.ChatCompletionChunk

					if s.encryptionEnabled {
						var sealedChunk *cm.EncryptedChatCompletionChunk
						if err := json.Unmarshal([]byte(data), &sealedChunk); err != nil {
							h := errHandler{
								err: fmt.Errorf("failed to unmarshal encrypted chat completion chunk: %w", err),
							}
							errorStream <- h.handleWith(slogger)
							return
						} else {
							slogger.Debugw("encrypted chat completion response", "payload", sealedChunk, "stream", true)

							unsealedChunk, err := sealedChunk.Decrypt(keys)
							if err != nil {
								h := errHandler{err: fmt.Errorf("failed to decrypt chat completion chunk: %w", err)}
								errorStream <- h.handleWith(slogger)
								return
							}
							chunk = unsealedChunk
						}
					} else {
						if err := json.Unmarshal([]byte(data), &chunk); err != nil {
							h := errHandler{
								err: fmt.Errorf("failed to unmarshal chat completion chunk: %w", err),
							}
							errorStream <- h.handleWith(slogger)
							return
						}
					}
					slogger.Debugw("chat completion response", "payload", chunk, "stream", true)

					eventStream <- chunk
				}
			}
		}

		slogger.Debugw("Chat completion stream ended")
	}()

	return eventStream, errorStream, nil
}
