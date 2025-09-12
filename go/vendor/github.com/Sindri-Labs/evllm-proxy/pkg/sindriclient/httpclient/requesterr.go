package httpclient

import "fmt"

var _ error = &HttpRequestError{}

type HttpRequestError struct {
	BaseError    error
	StatusCode   int
	ResponseBody []byte
}

func (e *HttpRequestError) Error() string {
	return fmt.Sprintf("HTTP request failed with status code %d: %s", e.StatusCode, e.BaseError.Error())
}
