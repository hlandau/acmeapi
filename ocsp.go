package acmeapi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	denet "github.com/hlandau/goutils/net"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

// Checks OCSP for a certificate. The immediate issuer must be specified. If
// the certificate does not support OCSP, (nil, nil) is returned.  Uses HTTP
// GET rather than POST. The response is verified. The caller must check the
// response status. The raw OCSP response is also returned, even if parsing
// failed and err is non-nil.
//
// This method is realm-independent.
func (c *RealmClient) CheckOCSP(ctx context.Context, crt, issuer *x509.Certificate) (parsedResponse *ocsp.Response, rawResponse []byte, err error) {
	if len(crt.OCSPServer) == 0 {
		return
	}

	b, err := ocsp.CreateRequest(crt, issuer, nil)
	if err != nil {
		return
	}

	b64 := base64.StdEncoding.EncodeToString(b)
	path := crt.OCSPServer[0] + "/" + b64

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/ocsp-response")

	res, err := c.doReqActual(ctx, req)
	if err != nil {
		return
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		err = fmt.Errorf("OCSP response has status %#v", res.Status)
		return
	}

	if res.Header.Get("Content-Type") != "application/ocsp-response" {
		err = fmt.Errorf("response to OCSP request had unexpected content type")
		return
	}

	// Read response, limiting response to 1MiB.
	rawResponse, err = ioutil.ReadAll(denet.LimitReader(res.Body, 1*1024*1024))
	if err != nil {
		return
	}

	parsedResponse, err = ocsp.ParseResponse(rawResponse, issuer)
	return
}
