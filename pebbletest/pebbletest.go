// Package pebbletest provides facilities for using Pebble during testing.
package pebbletest

import (
	"crypto/tls"
	"net/http"
)

// HTTP client which can be used to talk to Pebble. Disables certificate
// checks, etc. as necessary. You must call Init() before using this.
var HTTPClient *http.Client

func init() {
	httpTransport := *http.DefaultTransport.(*http.Transport)
	httpTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	HTTPClient = &http.Client{
		Transport: &httpTransport,
	}
}
