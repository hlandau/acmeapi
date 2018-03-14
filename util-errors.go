package acmeapi

import (
	"fmt"
	denet "github.com/hlandau/goutils/net"
	"io/ioutil"
	"net/http"
)

// Error returned when the terms of service URI is not one which the calling
// code has nominated as an acceptable terms of service URI in its call to
// UpsertAccount.
type AgreementError struct {
	URI string // The required ToS agreement URI.
}

func (e *AgreementError) Error() string {
	return fmt.Sprintf("Account requires agreement with the following terms of service document: %#v", e.URI)
}

// Error returned when an HTTP request results in a valid response, but which
// has an unexpected failure status code. Used so that the response can still
// be examined if desired.
//
// When this error is returned, Res.Body is no longer available.
type HTTPError struct {
	Res *http.Response

	// If the response had an application/problem+json response body, this is
	// that JSON data.
	ProblemBody string
}

// Summarises the response status, headers, and the JSON problem body if available.
func (he *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error: %v\n%v\n%v", he.Res.Status, he.Res.Header, he.ProblemBody)
}

func newHTTPError(res *http.Response) error {
	defer res.Body.Close()

	he := &HTTPError{
		Res: res,
	}

	if res.Header.Get("Content-Type") == "application/problem+json" {
		b, err := ioutil.ReadAll(denet.LimitReader(res.Body, 512*1024))
		if err == nil {
			he.ProblemBody = string(b)
		}
	}

	return he
}
