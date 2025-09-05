package httpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"
)

type HttpRequest struct {
	Client  *http.Client // HTTP client to execute requests
	Logger  *zap.SugaredLogger
	Method  string
	URL     string // Full URL including scheme, host, and path
	Headers map[string]string
}

// Exec executes the HTTP request and returns the response or an error.
// Non-2xx responses are handled as errors, and the response body is parsed to extract the error details.
func (r *HttpRequest) Exec(ctx context.Context, body any, queryParams map[string]string) (*http.Response, error) {
	slogger := r.Logger.With(
		"url", r.URL,
		"method", r.Method,
	)

	var requestBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			newErr := &HttpRequestError{err, http.StatusInternalServerError, nil}
			slogger.Errorw("Failed to marshal request body", "error", newErr)
			return nil, newErr
		}
		requestBody = bytes.NewReader(bodyBytes)
	}

	// Create the HTTP Request
	request, err := http.NewRequestWithContext(ctx, r.Method, r.URL, requestBody)
	if err != nil {
		newErr := &HttpRequestError{err, http.StatusInternalServerError, nil}
		slogger.Errorw("Failed to create HTTP request", "error", newErr.Error())
		return nil, newErr
	}

	// Set the Request Headers
	for key, value := range r.Headers {
		request.Header.Set(key, value)
	}

	// Add Query Parameters if any
	if len(queryParams) > 0 {
		query := request.URL.Query()
		for key, value := range queryParams {
			query.Set(key, value)
		}
		request.URL.RawQuery = query.Encode()
	}

	response, err := r.Client.Do(request)
	if err != nil {
		newErr := &HttpRequestError{err, http.StatusInternalServerError, nil}
		slogger.Errorw("Failed to make HTTP request", "error", newErr.Error())
		return nil, newErr
	}

	// Handle any non-2xx HTTP status codes
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		slogger.Debugw("Non-2xx HTTP response", "status_code", response.StatusCode)

		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			newErr := &HttpRequestError{err, response.StatusCode, nil}
			slogger.Errorw("Failed to read error response", "error", newErr.Error())
			return nil, newErr
		}

		newErr := &HttpRequestError{
			BaseError:    fmt.Errorf("HTTP request failed with status %d", response.StatusCode),
			StatusCode:   response.StatusCode,
			ResponseBody: responseBody,
		}
		slogger.Errorw(newErr.Error(), "status_code", response.StatusCode, "response_body", responseBody)
		return nil, newErr
	}

	return response, nil
}
