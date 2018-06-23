package acmeendpoints

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"git.devever.net/hlandau/xlog"
)

var log, Log = xlog.New("acme.endpoints")

// Returned when no matching endpoint can be found.
var ErrNotFound = errors.New("no corresponding endpoint found")

// Finds an endpoint with the given directory URL. If no such endpoint is
// found, returns ErrNotFound.
func ByDirectoryURL(directoryURL string) (*Endpoint, error) {
	for _, e := range endpoints {
		if directoryURL == e.DirectoryURL {
			return e, nil
		}

		if e.deprecatedDirectoryURLRegexp != nil && e.deprecatedDirectoryURLRegexp.MatchString(directoryURL) {
			return e, nil
		}
	}

	return nil, ErrNotFound
}

// If an endpoint exists with the given directory URL, returns it.
//
// Otherwise, tries to create a new endpoint for the directory URL.  Where
// possible, endpoint parameters are guessed. Currently boulder is supported.
// Non-boulder based endpoints will not have any parameters set other than the
// directory URL, which means some operations on the endpoint will not succeed.
//
// It is acceptable to change the fields of the returned endpoint.
// By default, the title of the endpoint is the directory URL.
func CreateByDirectoryURL(directoryURL string) (*Endpoint, error) {
	e, err := ByDirectoryURL(directoryURL)
	if err == nil {
		return e, nil
	}

	// Make a code for the endpoint by hashing the directory URL...
	h := sha256.New()
	h.Write([]byte(directoryURL))
	code := fmt.Sprintf("Temp%08x", h.Sum(nil)[0:4])

	e = &Endpoint{
		Title:        directoryURL,
		DirectoryURL: directoryURL,
		Code:         code,
	}

	return e, nil
}
