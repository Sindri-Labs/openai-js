package clientmodels

import "encoding/json"

var _ error = &ClientError{}

type ErrorContext struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Param   string `json:"param"`
	Type    string `json:"type"`
}

type ClientError struct {
	BaseError  error
	StatusCode int
	Context    *ErrorContext `json:"context"`
}

func (e *ClientError) Error() string {
	return e.BaseError.Error()
}

func (e *ClientError) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Error *ErrorContext `json:"error"`
	}{
		Error: e.Context,
	})
}
