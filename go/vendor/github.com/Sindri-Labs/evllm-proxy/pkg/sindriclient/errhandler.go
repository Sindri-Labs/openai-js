package sindriclient

import (
	"encoding/json"
	"net/http"

	cm "github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/clientmodels"
	"github.com/Sindri-Labs/evllm-proxy/pkg/sindriclient/httpclient"
	"go.uber.org/zap"
)

type errHandler struct {
	code int
	err  error
	meta map[string]any
}

func (e *errHandler) handleWith(logger *zap.SugaredLogger) *cm.ClientError {
	if e.err == nil {
		panic("logAndReturnError called with nil error")
	}

	clientErr := &cm.ClientError{
		BaseError: e.err,
		Context:   &cm.ErrorContext{},
	}

	// If the error is of type *httpclient.HttpRequestError, then this error originated
	// from an outgoing HTTP request and we should use it to populate the ClientError.
	if httpErr, ok := e.err.(*httpclient.HttpRequestError); ok {
		clientErr.StatusCode = httpErr.StatusCode
		clientErr.Context.Code = httpErr.StatusCode
		clientErr.Context.Type = http.StatusText(httpErr.StatusCode)
		if httpErr.ResponseBody != nil {
			if err := json.Unmarshal(httpErr.ResponseBody, &clientErr.Context); err != nil {
				clientErr.Context.Code = httpErr.StatusCode
				clientErr.Context.Message = string(httpErr.ResponseBody)
			}
		} else {
			clientErr.Context.Code = httpErr.StatusCode
			clientErr.Context.Message = http.StatusText(httpErr.StatusCode)
		}
	} else {
		if e.code == 0 {
			// If no specific code is set, default to Internal Server Error
			clientErr.StatusCode = http.StatusInternalServerError
		} else {
			clientErr.StatusCode = e.code
		}
		clientErr.Context.Code = clientErr.StatusCode
		clientErr.Context.Message = http.StatusText(clientErr.StatusCode)
		clientErr.Context.Type = http.StatusText(clientErr.StatusCode)
	}

	if e.meta == nil {
		e.meta = make(map[string]any)
	}
	e.meta["client_error"] = clientErr.Context

	logger.Errorw(e.err.Error(),
		"client_error", clientErr,
		"context", e.meta,
	)

	return clientErr
}
