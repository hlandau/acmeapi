package acmeapi

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	denet "github.com/hlandau/goutils/net"
	"net/http"
	"time"
)

type postAccount struct {
	TermsOfServiceAgreed bool          `json:"termsOfServiceAgreed,omitempty"`
	ContactURIs          []string      `json:"contact,omitempty"`
	Status               AccountStatus `json:"status,omitempty"`
}

// Registers a new account or modifies an existing one. If acct.URL is set,
// then that account is updated, and the operation fails if the account does
// not exist. If acct.URL is not set, the account key is registered (if it has
// not already been) or updated (if it has) and in either case the account URL
// is discovered and set in acct.URL. In either case, the contents of the
// account object returned by the server is loaded into the fields of acct.
//
// The only fields of acct used for requests (that is, the only fields of an
// account modifiable by the client) are the ContactURIs and the Status field.
// The Status field is only sent if it is set to AccountDeactivated
// ("deactivated"); no other transition can be manually requested by the
// client.
//
// Terms of Service assent is not based on the TermsOfServiceAgreed field of
// acct, which is updated by responses but ignored when making requests.
// Instead, pass the set of strings acceptableTermsOfServiceURIs and ensure
// that the URI expressed in the directory metadata is set within it. This is
// not necessary if it is certain the account already exists (for example, if
// acct.URL is set).
func (c *RealmClient) UpsertAccount(ctx context.Context, acct *Account, acceptableTermsOfServiceURIs map[string]struct{}) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	// Determine whether we need to get the registration URI.
	endp := acct.URL
	expectCode := updateAccountCodes
	updating := true
	postAcct := &postAccount{
		ContactURIs: acct.ContactURIs,
	}
	if acct.Status == AccountDeactivated {
		postAcct.Status = acct.Status
	}

	if endp == "" {
		endp = di.NewAccount
		expectCode = newAccountCodes
		updating = false

		if di.Meta.TermsOfServiceURL != "" {
			if _, ok := acceptableTermsOfServiceURIs[di.Meta.TermsOfServiceURL]; ok {
				postAcct.TermsOfServiceAgreed = true
			}
		}
	}

	// Make request.
	acctU := acct
	if !updating {
		acctU = nil
	}

	res, err := c.doReq(ctx, "POST", endp, acctU, acct.Key, postAcct, acct)
	if res == nil {
		return err
	}

	if !isStatusCode(res, expectCode) {
		if err != nil {
			return err
		}

		return fmt.Errorf("unexpected status code: %d: %v", res.StatusCode, endp)
	}

	loc := res.Header.Get("Location")
	if loc != "" && updating {
		// Updating existing account, so we already have the URL and shouldn't be
		// redirected anywhere.
		return fmt.Errorf("unexpected Location header: %q", loc)
	}

	if !ValidURL(loc) {
		return fmt.Errorf("invalid URL: %q", loc)
	}
	acct.URL = loc
	return nil
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
	NotBefore   time.Time    `json:"notBefore,omitempty"`
	NotAfter    time.Time    `json:"notAfter,omitempty"`
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
		NotBefore:   order.NotBefore,
		NotAfter:    order.NotAfter,
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
func (c *RealmClient) LoadOrder(ctx context.Context, acct *Account, order *Order) error {
	res, err := c.doReq(ctx, "GET", order.URL, acct, nil, nil, order)
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
func (c *RealmClient) WaitLoadOrder(ctx context.Context, acct *Account, order *Order) error {
	err := waitUntil(ctx, order.retryAt)
	if err != nil {
		return err
	}

	return c.LoadOrder(ctx, acct, order)
}

// Wait for an order to finish processing. The order must be in the
// "processing" state and the method returns once this ceases to be the case.
// Only the URI is required to be set.
func (c *RealmClient) WaitForOrder(ctx context.Context, acct *Account, order *Order) error {
	for {
		if order.Status != "" && order.Status != OrderProcessing {
			return nil
		}

		err := c.WaitLoadOrder(ctx, acct, order)
		if err != nil {
			return err
		}
	}
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
