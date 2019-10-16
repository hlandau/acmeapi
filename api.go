// Package acmeapi provides an API for accessing ACME servers.
//
// See type RealmClient for introductory documentation.
package acmeapi // import "gopkg.in/hlandau/acmeapi.v2"

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	gnet "github.com/hlandau/goutils/net"
	"github.com/hlandau/xlog"
	"github.com/peterhellberg/link"
	"golang.org/x/net/context/ctxhttp"
	"gopkg.in/square/go-jose.v2"
	"io"
	"mime"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var log, Log = xlog.NewQuiet("acmeapi")

// Sentinel value for doReq.
var noAccountNeeded = Account{}

// Internal use only. All ACME URLs must use "https" and not "http". However,
// for testing purposes, if this is set, "http" URLs will be allowed. This is useful
// for testing when a test ACME server doesn't have TLS configured.
var TestingAllowHTTP = false

// You should set this to a string identifying the code invoking this library.
// Optional.
//
// You can alternatively set the user agent on a per-Client basis via
// Client.UserAgent, but usually a user agent is set at program scope and it
// makes more sense to set it here.
var UserAgent string

// Returns true if the URL given is (potentially) a valid ACME resource URL.
//
// The URL must be an HTTPS URL.
func ValidURL(u string) bool {
	ur, err := url.Parse(u)
	return err == nil && (ur.Scheme == "https" || (TestingAllowHTTP && ur.Scheme == "http"))
}

// Configuration data used to instantiate a RealmClient.
type RealmClientConfig struct {
	// Optional but usually necessary. The Directory URL for the ACME realm (ACME
	// server). This must be an HTTPS URL. This will usually be provided via
	// out-of-band means; it is the root from which all other ACME resources are
	// accessed.
	//
	// Specifying the directory URL is usually necessary, but it can be omitted
	// in some cases; see the documentation for RealmClient.
	DirectoryURL string

	// Optional. HTTP client used to make HTTP requests. If this is nil, the
	// default net/http Client is used, which will suffice in the vast majority
	// of cases.
	HTTPClient *http.Client

	// Optional. Custom User-Agent string. If not specified, uses the global
	// User-Agent string configured at acmeapi package level (UserAgent var).
	UserAgent string
}

// Client used to access and mutate resources provided by an ACME server.
//
//
// REALM TERMINOLOGY
//
// A “realm” means an ACME server, including all resources provided by it (e.g.
// accounts, orders, nonces). A nonce can be used to issue a signed request
// against a resource in a given realm if and only if it that nonce was issued
// by the same realm. (This term is specific to this client, and not a general
// ACME term. It is coined here to aid clarity in understanding the scope of
// ACME resources.)
//
// You instantiate a RealmClient to consume the services of a realm. If you
// want to consume the services of multiple ACME servers — that is, multiple
// realms — you must create one RealmClient for each such realm. For example,
// if you wanted to use both the ExampleCA Live ACME server (which issues live
// certificates) and the ExampleCA Staging ACME server (which issues non-live
// certificates), you would need to create one RealmClient for each, and make
// any calls to the right RealmClient. Calling a method on the wrong
// RealmClient will fail under most circumstances.
//
//
// INSTANTIATION
//
// Call NewRealmClient to create a new RealmClient. When you create a RealmClient,
// you begin by passing the realm's (ACME server's) directory URL as part of
// the client configuration. This is the entrypoint for the consumption of the
// services provided by an ACME server realm. See RealmClientConfig for details.
//
//
// DIRECTORY AUTO-DISCOVERY
//
// It is possible to instantiate a RealmClient without passing a directory URL.
// If you do this, it is still possible to access some resources, where their
// particular URL is explicitly known. Moreover, a RealmClient which has no
// particular directory URL configured will automatically ascertain the
// appropriate directory URL when it (if ever) first loads a resource where the
// response from the server states the directory URL for the realm of which
// that resource is a member. Once this occurs, that RealmClient is thereafter
// specific to that realm, and must not be used for other purposes.
//
// This directory auto-discovery mechanic is useful when you have an URL for a
// specific resource of an ACME realm but don't know the directory URL or the
// identity of the realm or any other information about the realm. This allows
// e.g. a certificate to be revoked knowing only its URL and private key. (The
// revocation endpoint is discoverable from the directory resource, which is
// itself discoverable by a link provided at the certificate resource, which is
// addressed via the certificate URL.)
//
//
// CONCURRENCY
//
// All methods of RealmClient are concurrency-safe. This means you can make
// multiple in-flight requests. This is useful, for example, when you create a
// new order and wish to retrieve all the authorizations created as part of it,
// which are referenced by URL and not serialized inline as part of the order
// object.
//
//
// STANDARD METHOD ARGUMENTS
//
// All methods which involve network I/O, or which may involve network I/O,
// take a context, to facilitate timeouts and cancellations.
//
// All methods which involve making signed requests take an *Account argument.
// This is used to provide the URL and private key for the account; the other
// fields of *Account arguments are only used by methods which work directly
// with account resources.
//
// The URL and PrivateKey fields of a provided *Account are mandatory in most cases.
// They are optional only in the following cases:
//
// When calling UpsertAccount, the account URL may be omitted. (If the URL of
// an existing account is not known, this method may (and must) be used to
// discover the URL of the account before methods requiring an URL may be
// called.)
//
// When calling Revoke, the account URL and account private key may be omitted,
// but only if the revocation request is being authorized on the basis of
// possession of the certificate's corresponding private key. All other
// revocation requests require an account URL and account private key.
type RealmClient struct {
	cfg               RealmClientConfig
	directoryURLMutex sync.RWMutex // Protects cfg.DirectoryURL.

	nonceSource nonceSource

	dir      atomic.Value // *directoryInfo
	dirMutex sync.Mutex   // Ensures single flight for directory requests.
}

// Directory resource structure.
type directoryInfo struct {
	NewNonce   string    `json:"newNonce"`
	NewAccount string    `json:"newAccount"`
	NewOrder   string    `json:"newOrder"`
	NewAuthz   string    `json:"newAuthz"`
	RevokeCert string    `json:"revokeCert"`
	KeyChange  string    `json:"keyChange"`
	Meta       RealmMeta `json:"meta"`
}

// Metadata for a realm, retrieved from the directory resource.
type RealmMeta struct {
	// (Sent by server; optional.) If the CA requires agreement to certain terms of
	// service, this is set to an URL for the terms of service document.
	TermsOfServiceURL string `json:"termsOfService,omitempty"`

	// (Sent by server; optional.) A website pertaining to the CA.
	WebsiteURL string `json:"website,omitempty"`

	// (Sent by server; optional.) List of domain names which the CA recognises as
	// referring to itself for the purposes of CAA record validation.
	CAAIdentities []string `json:"caaIdentities,omitempty"`

	// (Sent by server; optional.) As per specification.
	ExternalAccountRequired bool `json:"externalAccountRequired,omitempty"`
}

// Instantiates a new RealmClient.
func NewRealmClient(cfg RealmClientConfig) (*RealmClient, error) {
	rc := &RealmClient{
		cfg: cfg,
	}

	if rc.cfg.DirectoryURL != "" && !ValidURL(rc.cfg.DirectoryURL) {
		return nil, fmt.Errorf("not a valid directory URL: %q", rc.cfg.DirectoryURL)
	}

	rc.nonceSource.GetNonceFunc = rc.obtainNewNonce

	return rc, nil
}

func (c *RealmClient) getDirectoryURL() string {
	c.directoryURLMutex.RLock()
	defer c.directoryURLMutex.RUnlock()

	return c.cfg.DirectoryURL
}

// Directory Retrieval

// Returns the directory information for the realm accessed by the RealmClient.
//
// This may return instantly (if the directory information has already been
// retrieved and cached), or may cause a request to be made to retrieve and
// cache the information, hence the context argument.
//
// Multiple concurrent calls to getDirectory with no directory information
// cached result only in a single request being made; all of the callers to
// getDirectory wait for the single request.
func (c *RealmClient) getDirectory(ctx context.Context) (*directoryInfo, error) {
	dir := c.getDirp()
	if dir != nil {
		return dir, nil
	}

	c.dirMutex.Lock()
	defer c.dirMutex.Unlock()

	if dir := c.getDirp(); dir != nil {
		return dir, nil
	}

	dir, err := c.getDirectoryActual(ctx)
	if err != nil {
		return nil, err
	}

	c.setDirp(dir)
	return dir, nil
}

func (c *RealmClient) getDirp() *directoryInfo {
	v, _ := c.dir.Load().(*directoryInfo)
	return v
}

func (c *RealmClient) setDirp(d *directoryInfo) {
	c.dir.Store(d)
}

// Error returned when directory URL was needed for an operation but it is unknown.
var ErrUnknownDirectoryURL = errors.New("unable to retrieve directory because the directory URL is unknown")

// Error returned if directory does not provide endpoints required by the specification.
var ErrMissingEndpoints = errors.New("directory does not provide required endpoints")

// Make actual request to retrieve directory.
func (c *RealmClient) getDirectoryActual(ctx context.Context) (*directoryInfo, error) {
	directoryURL := c.getDirectoryURL()
	if directoryURL == "" {
		return nil, ErrUnknownDirectoryURL
	}

	var dir *directoryInfo
	_, err := c.doReq(ctx, "GET", directoryURL, nil, nil, nil, &dir)
	if err != nil {
		return nil, err
	}

	if !ValidURL(dir.NewNonce) || !ValidURL(dir.NewAccount) || !ValidURL(dir.NewOrder) {
		return nil, ErrMissingEndpoints
	}

	return dir, nil
}

// Returns the directory metadata for the realm.
//
// This method must be used to retrieve the realm's current Terms of Service
// URI when calling UpsertAccount.
func (c *RealmClient) GetMeta(ctx context.Context) (RealmMeta, error) {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return RealmMeta{}, err
	}

	return di.Meta, nil
}

// This method is configured as the GetNewNonce function for the nonceSource
// which constitutes part of the RealmClient. It is called if the nonceSource's
// cache of nonces is empty, meaning that an HTTP request must be made to
// retrieve a new nonce.
func (c *RealmClient) obtainNewNonce(ctx context.Context) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	// We don't need to cache the nonce explicitly; doReq automatically caches
	// any fresh nonces provided in a reply.
	res, err := c.doReq(ctx, "HEAD", di.NewNonce, nil, nil, nil, nil)
	if res != nil {
		res.Body.Close()
	}

	return err
}

// Request Methods

// Makes an ACME request.
//
// method: HTTP method in uppercase.
//
// url: Absolute HTTPS URL.
//
// requestData: If non-nil, signed and sent as request body.
//
// responseData: If non-nil, response, if JSON, is unmarshalled into this.
//
// acct: Mandatory if requestData is non-nil. This is used to determine the
// account URL, which is used for signing requests. If key is nil, acct.PrivateKey
// is used to sign the request. If the request should be signed with an embedded JWK
// rather than an URL account reference, pass the special sentinel value
// &noAccountNeeded.
//
// key: Overrides the private key used; used instead of acct.PrivateKey if non-nil.
// The HTTP response structure is returned; the state of the Body stream is undefined,
// but need not be manually closed if err is non-nil or if responseData is non-nil.
func (c *RealmClient) doReq(ctx context.Context, method, url string, acct *Account, key crypto.PrivateKey, requestData, responseData interface{}) (*http.Response, error) {
	return c.doReqAccept(ctx, method, url, "application/json", acct, key, requestData, responseData)
}

func (c *RealmClient) doReqAccept(ctx context.Context, method, url, accepts string, acct *Account, key crypto.PrivateKey, requestData, responseData interface{}) (*http.Response, error) {
	backoff := gnet.Backoff{
		MaxTries:           20,
		InitialDelay:       100 * time.Millisecond,
		MaxDelay:           1 * time.Second,
		MaxDelayAfterTries: 4,
		Jitter:             0.10,
	}

	for {
		res, err := c.doReqOneTry(ctx, method, url, accepts, acct, key, requestData, responseData)
		if err == nil {
			return res, nil
		}

		// If the error is specifically a "bad nonce" error, we are supposed to
		// retry.
		if he, ok := err.(*HTTPError); ok && he.Problem != nil && he.Problem.Type == "urn:ietf:params:acme:error:badNonce" {
			if backoff.Sleep() {
				log.Debugf("retrying after bad nonce: %v\n", he)
				continue
			}
		}

		// Other error, return.
		return res, err
	}
}

func (c *RealmClient) doReqOneTry(ctx context.Context, method, url, accepts string, acct *Account, key crypto.PrivateKey, requestData, responseData interface{}) (*http.Response, error) {
	// Check input.
	if !ValidURL(url) {
		return nil, fmt.Errorf("invalid request URL: %q", url)
	}

	// Request marshalling and signing.
	var rdr io.Reader
	if requestData != nil {
		if acct == nil {
			return nil, fmt.Errorf("must provide account object when making signed requests")
		}

		if key == nil {
			key = acct.PrivateKey
		}

		if key == nil {
			return nil, fmt.Errorf("account key must be specified")
		}

		var b []byte
		var err error
		if s, ok := requestData.(string); ok && s == "" {
			b = []byte{}
		} else {
			b, err = json.Marshal(requestData)
			if err != nil {
				return nil, err
			}
		}

		kalg, err := algorithmFromKey(key)
		if err != nil {
			return nil, err
		}

		signKey := jose.SigningKey{
			Algorithm: kalg,
			Key:       key,
		}
		extraHeaders := map[jose.HeaderKey]interface{}{
			"url": url,
		}
		useInlineKey := (acct == &noAccountNeeded)
		if !useInlineKey {
			accountURL := acct.URL
			if !ValidURL(accountURL) {
				return nil, fmt.Errorf("acct must have a valid URL, not %q", accountURL)
			}

			extraHeaders["kid"] = accountURL
		}

		signOptions := jose.SignerOptions{
			NonceSource:  c.nonceSource.WithContext(ctx),
			EmbedJWK:     useInlineKey,
			ExtraHeaders: extraHeaders,
		}

		signer, err := jose.NewSigner(signKey, &signOptions)
		if err != nil {
			return nil, err
		}

		sig, err := signer.Sign(b)
		if err != nil {
			return nil, err
		}

		s := sig.FullSerialize()
		if err != nil {
			return nil, err
		}

		rdr = strings.NewReader(s)
	}

	// Make request.
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", accepts)
	if method != "GET" && method != "HEAD" {
		req.Header.Set("Content-Type", "application/jose+json")
	}

	res, err := c.doReqServer(ctx, req)
	if err != nil {
		return res, err
	}

	// Otherwise, if we are expecting response data, unmarshal into the provided
	// struct.
	if responseData != nil {
		defer res.Body.Close()

		mimeType, params, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
		if err != nil {
			return res, err
		}

		err = validateContentType(mimeType, params, "application/json")
		if err != nil {
			return res, err
		}

		err = json.NewDecoder(res.Body).Decode(responseData)
		if err != nil {
			return res, err
		}
	}

	// Done.
	return res, nil
}

func validateContentType(mimeType string, params map[string]string, expectedMimeType string) error {
	if mimeType != expectedMimeType {
		return fmt.Errorf("unexpected response content type: %q", mimeType)
	}

	if ch, ok := params["charset"]; ok && ch != "" && strings.ToLower(ch) != "utf-8" {
		return fmt.Errorf("content type charset is not UTF-8: %q, %q", mimeType, ch)
	}

	return nil
}

// Make an HTTP request to an ACME endpoint.
func (c *RealmClient) doReqServer(ctx context.Context, req *http.Request) (*http.Response, error) {
	res, err := c.doReqActual(ctx, req)
	if err != nil {
		return nil, err
	}

	// If the response includes a nonce, add it to our cache of nonces.
	if n := res.Header.Get("Replay-Nonce"); n != "" {
		c.nonceSource.AddNonce(n)
	}

	// Autodiscover directory URL if it we didn't prevously know it and it's
	// specified in the response.
	if c.getDirectoryURL() == "" {
		func() {
			c.directoryURLMutex.Lock()
			defer c.directoryURLMutex.Unlock()

			if c.cfg.DirectoryURL != "" {
				return
			}

			if link := link.ParseResponse(res)["index"]; link != nil && ValidURL(link.URI) {
				c.cfg.DirectoryURL = link.URI
			}
		}()
	}

	// If the response was an error, parse the response body as an error and return.
	if res.StatusCode >= 400 && res.StatusCode < 600 {
		defer res.Body.Close()
		return res, newHTTPError(res)
	}

	return res, err
}

// Make an HTTP request. This is used by doReq and can also be used for
// non-ACME requests (e.g. OCSP).
func (c *RealmClient) doReqActual(ctx context.Context, req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", formUserAgent(c.cfg.UserAgent))

	return ctxhttp.Do(ctx, c.cfg.HTTPClient, req)
}

func algorithmFromKey(key crypto.PrivateKey) (jose.SignatureAlgorithm, error) {
	switch v := key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		name := v.Curve.Params().Name
		switch name {
		case "P-256":
			return jose.ES256, nil
		case "P-384":
			return jose.ES384, nil
		case "P-521":
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", name)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", key)
	}
}

func formUserAgent(userAgent string) string {
	if userAgent == "" {
		userAgent = UserAgent
	}

	if userAgent != "" {
		userAgent += " "
	}

	return fmt.Sprintf("%sacmeapi/2a Go-http-client/1.1 %s/%s", userAgent, runtime.GOOS, runtime.GOARCH)
}
