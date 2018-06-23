// Package acmeendpoints provides information on known ACME servers.
package acmeendpoints

import (
	"fmt"
	"regexp"
	"sync"
)

// Provides information on a known ACME endpoint.
type Endpoint struct {
	// Friendly name for the provider. Should be a short, single-line, title case
	// human readable description of the endpoint.
	Title string

	// Short unique endpoint identifier. Must match ^[a-zA-Z][a-zA-Z0-9_]*$ and
	// should use CamelCase.
	Code string

	// The ACME directory URL. Must be an HTTPS URL and typically ends in
	// "/directory".
	DirectoryURL string

	// If this is not "", this is a regexp which must be matched iff an OCSP
	// endpoint URL as found in a certificate implies that a certificate was
	// issued by this endpoint.
	OCSPURLRegexp string
	ocspURLRegexp *regexp.Regexp

	// Whether the endpoint gives live certificates.
	Live bool

	// If not "", this is a regexp matching deprecated directory URLs which this
	// endpoint supercedes. We use this to upgrade seamlessly to ACMEv2 without
	// requiring server administrators to change their ACME directory URLs.
	DeprecatedDirectoryURLRegexp string
	deprecatedDirectoryURLRegexp *regexp.Regexp

	initOnce sync.Once
}

func (e *Endpoint) String() string {
	return fmt.Sprintf("Endpoint(%v)", e.DirectoryURL)
}

func (e *Endpoint) init() {
	e.initOnce.Do(func() {
		if e.OCSPURLRegexp != "" {
			e.ocspURLRegexp = regexp.MustCompile(e.OCSPURLRegexp)
		}

		//if e.CertificateURLRegexp != "" {
		//	e.certificateURLRegexp = regexp.MustCompile(e.CertificateURLRegexp)
		//}

		//if e.CertificateURLTemplate != "" {
		//	e.certificateURLTemplate = template.Must(template.New("certificate-url").Parse(e.CertificateURLTemplate))
		//}

		if e.DeprecatedDirectoryURLRegexp != "" {
			e.deprecatedDirectoryURLRegexp = regexp.MustCompile(e.DeprecatedDirectoryURLRegexp)
		}
	})
}

var endpoints []*Endpoint

// Visit all registered endpoints.
func Visit(f func(p *Endpoint) error) error {
	for _, p := range endpoints {
		err := f(p)
		if err != nil {
			return err
		}
	}

	return nil
}

// Register a new endpoint.
func RegisterEndpoint(p *Endpoint) {
	p.init()
	endpoints = append(endpoints, p)
}

func init() {
	for _, p := range builtinEndpoints {
		RegisterEndpoint(p)
	}
}
