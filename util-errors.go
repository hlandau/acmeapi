package acmeapi

import (
	"encoding/json"
	"fmt"
	denet "github.com/hlandau/goutils/net"
	"io/ioutil"
	"net/http"
)

// Error returned when an HTTP request results in a valid response, but which
// has an unexpected failure status code. Used so that the response can still
// be examined if desired.
type HTTPError struct {
	// The HTTP response which was an error. Res.Body is no longer available
	// by the time the HTTPError is returned.
	Res *http.Response

	// If the response had an application/problem+json response body, this is
	// the parsed problem. nil if the problem document was unparseable.
	Problem *Problem

	// If the response had an application/problem+json response body, this is
	// that JSON data.
	ProblemRaw json.RawMessage
}

// Summarises the response status, headers, and the JSON problem body if available.
func (he *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error: %v\n%v\n%v", he.Res.Status, he.Res.Header, he.ProblemRaw)
}

func newHTTPError(res *http.Response) error {
	defer res.Body.Close()

	he := &HTTPError{
		Res: res,
	}

	if res.Header.Get("Content-Type") == "application/problem+json" {
		b, err := ioutil.ReadAll(denet.LimitReader(res.Body, 512*1024))
		if err == nil {
			he.ProblemRaw = b
			json.Unmarshal([]byte(he.ProblemRaw), &he.Problem) // ignore errors
		}
	}

	return he
}
