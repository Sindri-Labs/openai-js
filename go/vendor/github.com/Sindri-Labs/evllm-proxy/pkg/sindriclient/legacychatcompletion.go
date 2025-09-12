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
func (s *SindriClient) LegacyChatCompletionNoStream(
	params *cm.LegacyCompletionParams,
	td *cm.TraceMetadata,
) (*cm.LegacyCompletion, error) {
	slogger := s.logger.Sugar().With("trace_metadata", td)

	request := httpclient.HttpRequest{
		Client: s.httpClient,
		Logger: slogger,
		Method: http.MethodPost,
		URL:    s.Endpoint(EndpointLegacyCompletion),
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.apiKey,
		},
	}

	var keys *cryptos.EncryptionKeys
	var payload any

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

	var completion *cm.LegacyCompletion
	if s.encryptionEnabled {
		var sealed cm.EncryptedLegacyCompletion
		if err := json.Unmarshal(responseBody, &sealed); err != nil {
			h := errHandler{err: fmt.Errorf("failed to unmarshal encrypted chat completion: %w", err)}
			return nil, h.handleWith(slogger)
		}
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

	return completion, nil
}

// ChatCompletionStream streams chat completion events from the Sindri API.
func (s *SindriClient) LegacyChatCompletionStream(
	params *cm.LegacyCompletionParams,
	meta *cm.TraceMetadata,
) (<-chan *cm.LegacyCompletion, <-chan error, error) {
	slogger := s.logger.Sugar().With("trace_metadata", meta)

	request := httpclient.HttpRequest{
		Client: s.httpClient,
		Logger: slogger,
		Method: http.MethodPost,
		URL:    s.Endpoint(EndpointLegacyCompletion),
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.apiKey,
		},
	}

	var keys *cryptos.EncryptionKeys
	var payload any

	if s.encryptionEnabled {
		if encKeys, err := s.getKeys(); err != nil {
			h := errHandler{err: fmt.Errorf("failed to get encryption options: %w", err)}
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

	eventStream := make(chan *cm.LegacyCompletion, sseChanSize)
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
					var chunk *cm.LegacyCompletion

					if s.encryptionEnabled {
						var sealedChunk *cm.EncryptedLegacyCompletion
						if err := json.Unmarshal([]byte(data), &sealedChunk); err != nil {
							h := errHandler{
								err: fmt.Errorf("failed to unmarshal encrypted chat completion chunk: %w", err),
							}
							errorStream <- h.handleWith(slogger)
							return
						} else {
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
							h := errHandler{err: fmt.Errorf("failed to unmarshal chat completion chunk: %w", err)}
							errorStream <- h.handleWith(slogger)
							return
						}
					}
					eventStream <- chunk
				}
			}
		}
		slogger.Debugw("Chat completion stream ended")
	}()

	return eventStream, errorStream, nil
}
