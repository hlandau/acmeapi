package acmeapi

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hlandau/acmeapi/acmeutils"
	denet "github.com/hlandau/goutils/net"
	"io/ioutil"
	"mime"
	"net/http"
	"time"
)

type postAccount struct {
	TermsOfServiceAgreed bool          `json:"termsOfServiceAgreed,omitempty"`
	ContactURIs          []string      `json:"contact,omitempty"`
	Status               AccountStatus `json:"status,omitempty"`
	OnlyReturnExisting   bool          `json:"onlyReturnExisting,omitempty"`
}

func (c *RealmClient) postAccount(ctx context.Context, acct *Account, onlyReturnExisting bool) error {
	postAcct := &postAccount{
		ContactURIs:          acct.ContactURIs,
		TermsOfServiceAgreed: acct.TermsOfServiceAgreed,
		OnlyReturnExisting:   onlyReturnExisting,
	}
	if acct.Status == AccountDeactivated {
		postAcct.Status = acct.Status
	}

	endp := acct.URL
	expectCode := updateAccountCodes
	updating := true

	if endp == "" {
		di, err := c.getDirectory(ctx)
		if err != nil {
			return err
		}

		endp = di.NewAccount
		expectCode = newAccountCodes
		updating = false
	}

	acctU := acct
	if !updating {
		acctU = &noAccountNeeded
	}

	res, err := c.doReq(ctx, "POST", endp, acctU, acct.PrivateKey, postAcct, acct)
	if res == nil {
		return err
	}

	if !isStatusCode(res, expectCode) {
		if err != nil {
			return err
		}

		return fmt.Errorf("unexpected status code: %d: %q", res.StatusCode, endp)
	}

	loc := res.Header.Get("Location")
	if !updating {
		if !ValidURL(loc) {
			return fmt.Errorf("invalid URL: %q", loc)
		}
		acct.URL = loc
	} else {
		if loc != "" {
			return fmt.Errorf("unexpected Location header: %q", loc)
		}
	}

	return nil
}

func (c *RealmClient) registerAccount(ctx context.Context, acct *Account, onlyReturnExisting bool) error {
	if acct.URL != "" {
		return fmt.Errorf("cannot register account which already has an URL")
	}

	return c.postAccount(ctx, acct, onlyReturnExisting)
}

// Registers a new account. acct.URL must be empty and TermsOfServiceAgreed must
// be true.
//
// The only fields of acct used for requests (that is, the only fields of an
// account modifiable by the client) are the ContactURIs field, the
// TermsOfServiceAgreed field and the Status field. The Status field is only sent
// if it is set to AccountDeactivated ("deactivated"); no other transition can be
// manually requested by the client.
func (c *RealmClient) RegisterAccount(ctx context.Context, acct *Account) error {
	return c.registerAccount(ctx, acct, false)
}

// Tries to find an existing account by key if the URL is not yet known.
// acct.URL must be empty. Fails if the account does not exist.
func (c *RealmClient) LocateAccount(ctx context.Context, acct *Account) error {
	return c.registerAccount(ctx, acct, true)
}

// Updates an existing account. acct.URL must be set.
func (c *RealmClient) UpdateAccount(ctx context.Context, acct *Account) error {
	if acct.URL == "" {
		return fmt.Errorf("cannot update account for which URL is unknown")
	}

	return c.postAccount(ctx, acct, false)
}

var newAccountCodes = []int{201 /* Created */, 200 /* OK */}
var updateAccountCodes = []int{200 /* OK */}

func isStatusCode(res *http.Response, codes []int) bool {
	for _, c := range codes {
		if c == res.StatusCode {
			return true
		}
	}
	return false
}

const defaultPollTime = 10 * time.Second

// AUTHORIZATIONS

// Load or reload the details of an authorization via its URI.
//
// You can load an authorization from only the URI by creating an Authorization
// with the URI set and then calling this method.
func (c *RealmClient) LoadAuthorization(ctx context.Context, acct *Account, az *Authorization) error {
	res, err := c.doReq(ctx, "GET", az.URL, acct, nil, nil, az)
	if err != nil {
		return err
	}

	err = az.validate()
	if err != nil {
		return err
	}

	az.retryAt = retryAtDefault(res.Header, defaultPollTime)
	return nil
}

// Like LoadAuthorization, but waits the retry time if this is not the first attempt
// to load this authorization. To be used when polling.
//
// The retry delay will not work if you recreate the object; use the same
// Authorization struct between calls.
func (c *RealmClient) WaitLoadAuthorization(ctx context.Context, acct *Account, az *Authorization) error {
	err := waitUntil(ctx, az.retryAt)
	if err != nil {
		return err
	}

	return c.LoadAuthorization(ctx, acct, az)
}

func (az *Authorization) validate() error {
	if len(az.Challenges) == 0 {
		return errors.New("no challenges offered")
	}

	return nil
}

// Create a new authorization for the given hostname.
//
// IDN hostnames must be in punycoded form.
//
// Use of this method facilitates preauthentication, which is rarely necessary.
// Consider simply using NewOrder instead.
func (c *RealmClient) NewAuthorization(ctx context.Context, acct *Account, ident Identifier) (*Authorization, error) {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return nil, err
	}

	az := &Authorization{
		Identifier: ident,
	}

	res, err := c.doReq(ctx, "POST", di.NewAuthz, acct, nil, az, az)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 201 {
		return nil, fmt.Errorf("expected status code 201, got %v", res.StatusCode)
	}

	loc := res.Header.Get("Location")
	if !ValidURL(loc) {
		return nil, fmt.Errorf("expected valid location, got %q", loc)
	}

	az.URL = loc

	err = az.validate()
	if err != nil {
		return nil, err
	}

	return az, nil
}

type postOrder struct {
	Identifiers []Identifier `json:"identifiers,omitempty"`
	NotBefore   *time.Time   `json:"notBefore,omitempty"`
	NotAfter    *time.Time   `json:"notAfter,omitempty"`
}

// Creates a new order. You must set at least the Identifiers field of Order.
// The NotBefore and NotAfter fields may also optionally be set. The other
// fields, including URI, will be filled in when the method returns.
func (c *RealmClient) NewOrder(ctx context.Context, acct *Account, order *Order) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	po := &postOrder{
		Identifiers: order.Identifiers,
		NotBefore:   &order.NotBefore,
		NotAfter:    &order.NotAfter,
	}
	if po.NotBefore.IsZero() {
		po.NotBefore = nil
	}
	if po.NotAfter.IsZero() {
		po.NotAfter = nil
	}

	res, err := c.doReq(ctx, "POST", di.NewOrder, acct, nil, po, order)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	if res.StatusCode != 201 {
		return fmt.Errorf("expected status code 201, got %v", res.StatusCode)
	}

	loc := res.Header.Get("Location")
	if !ValidURL(loc) {
		return fmt.Errorf("invalid URI: %#v", loc)
	}

	order.URL = loc
	return nil
}

// Load or reload an order.
//
// You can load an order from its URI by creating an Order with the URI set and
// then calling this.
func (c *RealmClient) LoadOrder(ctx context.Context, order *Order) error {
	res, err := c.doReq(ctx, "GET", order.URL, nil, nil, nil, order)
	if err != nil {
		return err
	}

	err = order.validate()
	if err != nil {
		return err
	}

	order.retryAt = retryAtDefault(res.Header, defaultPollTime)
	return nil
}

// Like LoadOrder, but waits the retry time if this is not the first attempt to load
// this certificate. To be used when polling.
//
// The retry delay will not work if you recreate the object; use the same Challenge
// struct between calls.
func (c *RealmClient) WaitLoadOrder(ctx context.Context, order *Order) error {
	err := waitUntil(ctx, order.retryAt)
	if err != nil {
		return err
	}

	return c.LoadOrder(ctx, order)
}

// Wait for an order to finish processing. The order must be in the
// "processing" state and the method returns once this ceases to be the case.
// Only the URI is required to be set.
func (c *RealmClient) WaitForOrder(ctx context.Context, order *Order) error {
	for {
		if order.Status != "" && order.Status != OrderProcessing {
			return nil
		}

		err := c.WaitLoadOrder(ctx, order)
		if err != nil {
			return err
		}
	}
}

func (c *RealmClient) LoadCertificate(ctx context.Context, cert *Certificate) error {
	// Check input.
	if !ValidURL(cert.URL) {
		return fmt.Errorf("invalid request URL: %q", cert.URL)
	}

	// Make request.
	req, err := http.NewRequest("GET", cert.URL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/pem-certificate-chain")

	res, err := c.doReqServer(ctx, req)
	if err != nil {
		return err
	}

	defer res.Body.Close()
	mimeType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return err
	}

	err = validateContentType(mimeType, params, "application/pem-certificate-chain")
	if err != nil {
		return err
	}

	b, err := ioutil.ReadAll(denet.LimitReader(res.Body, 512*1024))
	if err != nil {
		return err
	}

	cert.CertificateChain, err = acmeutils.LoadCertificates(b)
	if err != nil {
		return err
	}

	return nil
}

// This is a rather kludgy method needed for backwards compatibility with
// old-ACME URLs. If it is not known whether an URL is to a certificate or an
// order, this method can be used to load the URL. Returns with isCertificate
// == true if the URL appears to address a certificate (in which case the
// passed cert structure is populated), and isCertificate == false if the URL
// appears to address an order (in which case the passed order structure is
// populated). If the URL does not appear to address either type of resource,
// an error is returned.
func (c *RealmClient) LoadOrderOrCertificate(ctx context.Context, url string, order *Order, cert *Certificate) (isCertificate bool, err error) {
	// Check input.
	if !ValidURL(url) {
		err = fmt.Errorf("invalid request URL: %q", url)
		return
	}

	// Make request.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Accept", "application/json, application/pem-certificate-chain")

	res, err := c.doReqServer(ctx, req)
	if err != nil {
		return
	}

	defer res.Body.Close()
	mimeType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	err = validateContentType(mimeType, params, mimeType) // check params only
	if err != nil {
		return
	}

	switch mimeType {
	case "application/json":
		order.URL = url
		err = json.NewDecoder(res.Body).Decode(order)
		if err != nil {
			return
		}

		err = order.validate()
		if err != nil {
			return
		}

		order.retryAt = retryAtDefault(res.Header, defaultPollTime)
		return

	case "application/pem-certificate-chain":
		var b []byte
		b, err = ioutil.ReadAll(denet.LimitReader(res.Body, 512*1024))
		cert.URL = url
		cert.CertificateChain, err = acmeutils.LoadCertificates(b)
		isCertificate = true
		return
	}

	err = fmt.Errorf("response was not an order or certificate (unexpected content type %q)", mimeType)
	return
}

type finalizeReq struct {
	// Required. The CSR to be used for issuance.
	CSR denet.Base64up `json:"csr"`
}

// Finalize the order. This will only work if the order has the "ready" status.
func (c *RealmClient) Finalize(ctx context.Context, acct *Account, order *Order, csr []byte) error {
	req := finalizeReq{
		CSR: csr,
	}
	_, err := c.doReq(ctx, "POST", order.FinalizeURL, acct, nil, &req, order)
	if err != nil {
		return err
	}

	return nil
}

type revokeReq struct {
	Certificate []byte `json:"certificate"`
	Reason      int    `json:"reason,omitempty"`
}

// Requests revocation of a certificate. The certificate must be provided in
// DER form. If revocationKey is non-nil, the revocation request is signed with
// the given key; otherwise, the request is signed with the account key.
//
// In general, you should expect to be able to revoke any certificate if a
// request to do so is signed using that certificate's key. You should also
// expect to be able to revoke a certificate if the request is signed with the
// account key of the account for which the certificate was issued, or where
// the request is signed with the account key of an account for which presently
// valid authorizations are held for all DNS names on the certificate.
//
// The reason is a CRL reason code, or 0 if no explicit reason code is to be
// given.
func (c *RealmClient) Revoke(ctx context.Context, acct *Account, certificateDER []byte, revocationKey crypto.PrivateKey, reason int) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	if di.RevokeCert == "" {
		return fmt.Errorf("endpoint does not support revocation")
	}

	req := &revokeReq{
		Certificate: certificateDER,
		Reason:      reason,
	}

	res, err := c.doReq(ctx, "POST", di.RevokeCert, nil, revocationKey, req, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func (ord *Order) validate() error {
	return nil
}

// Submit a challenge response. Only the challenge URL is required to be set in
// the Challenge object. The account need only have the URL set.
func (c *RealmClient) RespondToChallenge(ctx context.Context, acct *Account, ch *Challenge, response json.RawMessage) error {
	_, err := c.doReq(ctx, "POST", ch.URL, acct, nil, &response, ch)
	if err != nil {
		return err
	}

	return nil
}

// Submit a key change request. The acct specified is used to authorize the
// change; the key for the account identified by acct.URL is changed from
// acct.PrivateKey/acct.Key to the key specified by newKey.
//
// When this method returns nil error, the key has been successfully changed.
// The acct object's Key and PrivateKey fields will also be changed to newKey.
func (c *RealmClient) ChangeKey(ctx context.Context, acct *Account, newKey crypto.PrivateKey) error {
	panic("not yet implemented")
}
