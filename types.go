package acmeapi

import (
	"crypto"
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"time"
)

// RFC7807 problem document. These structures are used by an ACME endpoint to
// return error information.
type Problem struct {
	// URI representing the problem type. Typically an URN.
	Type string `json:"type,omitempty"`
	// One-line summary of the error.
	Title string `json:"title,omitempty"`
	// HTTP status code (optional). If present, this should match the actual HTTP
	// status code returned. Advisory use only.
	Status int `json:"status,omitempty"`
	// More detailed explanation of the error.
	Detail string `json:"detail,omitempty"`
	// Optional, potentially relative URI identifying the specific problem.
	// May refer to an object which relates to the problem, etc.
	Instance string `json:"instance,omitempty"`

	// ACME-specific. Optional. List of problems which constitute components of
	// this problem.
	Subproblem []*Problem `json:"subproblems,omitempty"`

	// ACME-specific. Optional. Identifier relating to this problem.
	Identifier *Identifier `json:"identifier,omitempty"`
}

// Represents an identifier for a resource for which authorization is required.
type Identifier struct {
	// The type of the identifier.
	Type IdentifierType `json:"type"`

	// The identifier string. The format is determined by Type.
	Value string `json:"value"`
}

// A type of Identifier. Currently, the only supported value is "dns".
type IdentifierType string

const (
	// Indicates that the identifier value is a DNS name.
	IdentifierTypeDNS IdentifierType = "dns"
)

// ---------------------------------------------------------------------------------------------------------

// Represents an account.
type Account struct {
	// The URL of the account.
	URL string `json:"-"`

	// Private key used to authorize requests. This is never sent to any server,
	// but is used to sign requests when passed as an argument to RealmClient
	// methods.
	PrivateKey crypto.PrivateKey `json:"-"`

	// Account public key.
	//
	// Always sent by the server; cannot be modified directly by client (use the
	// ChangeKey method).
	Key *jose.JSONWebKey `json:"key,omitempty"`

	// Account status.
	//
	// Always sent by server. Cannot be directly modified by client in general,
	// except that a client may set this to AccountDeactivated ("deactivated") to
	// request deactivation. This is the only client-initiated change to this
	// field allowed.
	Status AccountStatus `json:"status,omitempty"`

	// Contact URIs which may be used to contact the accountholder.
	//
	// Most realms will accept e. mail addresses expressed as “mailto:” URIs
	// here. Some realms may accept “tel:” URIs. Acceptance of other URIs is in
	// practice unlikely, and may result in rejection by the server.
	//
	// Always sent by the server, and may be sent by client to modify the current
	// value. If this field is not specified when registering, the account will
	// have no contact URIs, and if the field is not specified when updating the
	// account, the current set of contact URIs will be left unchanged.
	ContactURIs []string `json:"contact,omitempty"`

	// Whether the client agrees/has agreed to the terms of service.
	//
	// Always sent by the server, and may be sent by client to indicate assent.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitempty"`

	// URL at which the orders attached to the account can be enumerated.
	//
	// Always sent by server, if enumeration is supported. Read only.
	OrdersURL string `json:"orders,omitempty"`
}

// Specifies a current account status.
type AccountStatus string

const (
	// The account is usable. This is the initial state.
	AccountValid AccountStatus = "valid"
	// The account is no longer usable, by accountholder request. This is a final
	// state. This is the only state which can be explicitly requested by the
	// client by setting it as the Status field.
	AccountDeactivated = "deactivated"
	// The account is no longer usable, due to administrative action.
	// This is a final state.
	AccountRevoked = "revoked"
)

// Returns true iff the account status is a recognised account status value.
func (s AccountStatus) IsWellFormed() bool {
	switch s {
	case "valid", "deactivated", "revoked":
		return true
	default:
		return false
	}
}

// Returns true iff the account status is a final status.
func (s AccountStatus) IsFinal() bool {
	switch s {
	case "deactivated", "revoked":
		return true
	default:
		return false
	}
}

// Implements encoding/json.Unmarshaler.
func (s *AccountStatus) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !AccountStatus(ss).IsWellFormed() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = AccountStatus(ss)
	return nil
}

// ---------------------------------------------------------------------------------------------------------

// Represents a request for a certificate.
type Order struct {
	// The URL of the order.
	URL string `json:"-"`

	// Order status.
	//
	// Always sent by server; read-only.
	Status OrderStatus `json:"status,omitempty"`

	// Time at which the order expires.
	//
	// Sent by server if status is "pending" or "valid". Read only.
	Expires time.Time `json:"expires,omitempty"` // RFC 3339

	// The identifiers that the order pertains to.
	Identifiers []Identifier `json:"identifiers,omitempty"`

	// DER-encoded X.509 CSR.
	//
	// Must be sent by client at resource creation time. Always sent by server
	// and is immutable after resource creation.
	//CSR denet.Base64up `json:"csr,omitempty"`

	// Optionally sent by client at order creation time to constrain certificate
	// validity period.
	//
	// Always sent by server and is immutable after resource creation.
	NotBefore time.Time `json:"notBefore,omitempty"` // RFC 3339
	NotAfter  time.Time `json:"notAfter,omitempty"`  // RFC 3339

	// An error which occurred during the processing of the order, if any.
	Error *Problem `json:"error,omitempty"` // RFC7807

	// List of URLs to authorization objects. All of the authorizations must be
	// completed to cause issuance. Issuance will commence as soon as all
	// authorizations are completed. Some authorizations may already be completed
	// when the order is created.
	//
	// Always sent by server. Read only.
	AuthorizationURLs []string `json:"authorizations,omitempty"`

	// An URL for submitting a CSR.
	FinalizeURL string `json:"finalize,omitempty"`

	// URL from which the certificate can be downloaded.
	//
	// Sent by server, but only when state is "valid". Read only.
	CertificateURL string `json:"certificate,omitempty"`

	retryAt time.Time
}

// Specifies an order status.
type OrderStatus string

const (
	// The order is waiting for one or more client actions before issuance
	// occurs. This is the initial state.
	OrderPending OrderStatus = "pending"
	// All preconditions to order fulfilment have been completed, and now the
	// order is simply waiting for a client to invoke the finalize operation. The
	// order will then transition to "processing".
	OrderReady = "ready"
	// Issuance is underway, and the state will transition to "valid" or
	// "invalid" automatically.
	OrderProcessing = "processing"
	// The order is valid. The certificate has been issued and can be retrieved.
	// This is a final state.
	OrderValid = "valid"
	// The certificate issuance request has failed.
	// This is a final state.
	OrderInvalid = "invalid"
)

// Returns true iff the order status is a recognised order status value.
func (s OrderStatus) IsWellFormed() bool {
	switch s {
	case "pending", "ready", "processing", "valid", "invalid":
		return true
	default:
		return false
	}
}

// Returns true iff the order status is a final status.
func (s OrderStatus) IsFinal() bool {
	switch s {
	case "valid", "invalid": // TODO
		return true
	default:
		return false
	}
}

// Implements encoding/json.Unmarshaler.
func (s *OrderStatus) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !OrderStatus(ss).IsWellFormed() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = OrderStatus(ss)
	return nil
}

// ---------------------------------------------------------------------------------------------------------

// Represents an authorization which must be completed to enable certificate
// issuance.
type Authorization struct {
	// The URL of the authorization.
	URL string `json:"-"`

	// The identifier for which authorization is required.
	//
	// Sent by server. Read only.
	Identifier Identifier `json:"identifier,omitempty"`

	// The status of the authorization.
	//
	// Sent by server. Read only.
	Status AuthorizationStatus `json:"status,omitempty"`

	// The expiry time of the authorization.
	//
	// May be sent by server; always sent if status is "valid". Read only.
	Expires time.Time `json:"expires,omitempty"`

	// True if the authorization is for a wildcard domain name.
	Wildcard bool `json:"wildcard,omitempty"`

	// Array of Challenge objects. Any one challenge in the array must be
	// completed to complete the authorization.
	//
	// Always sent by server. Read only.
	Challenges []Challenge `json:"challenges,omitempty"`

	retryAt time.Time
}

// Specifies an authorization status.
type AuthorizationStatus string

const (
	// The authorization is waiting for one or more client actions before
	// it becomes valid. This is the initial state.
	AuthorizationPending AuthorizationStatus = "pending"
	// The authorization is valid.
	// The only state transition possible is to "revoked".
	AuthorizationValid = "valid"
	// The authorization is invalid.
	// This is a final state.
	AuthorizationInvalid = "invalid"
	// The authorization is deactivated.
	// This is a final state.
	AuthorizationDeactivated = "deactivated"
	// The authorization has been revoked.
	// This is a final state.
	AuthorizationRevoked = "revoked"
)

// Returns true iff the authorization status is a recognised authorization
// status value.
func (s AuthorizationStatus) IsWellFormed() bool {
	switch s {
	case "pending", "valid", "invalid", "deactivated", "revoked":
		return true
	default:
		return false
	}
}

// Returns true iff the authorization status is a final status.
func (s AuthorizationStatus) IsFinal() bool {
	switch s {
	case "valid", "invalid", "deactivated", "revoked":
		return true
	default:
		return false
	}
}

// Implements encoding/json.Unmarshaler.
func (s *AuthorizationStatus) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !AuthorizationStatus(ss).IsWellFormed() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = AuthorizationStatus(ss)
	return nil
}

// ---------------------------------------------------------------------------------------------------------

// Represents a challenge which may be completed to satisfy an authorization
// requirement.
type Challenge struct {
	// The URL of the challenge object.
	//
	// Always sent by server. Read only.
	URL string `json:"url,omitempty"`

	// The challenge type.
	//
	// Always sent by server. Read only.
	Type string `json:"type,omitempty"`

	// The challenge status. Always sent by the server.
	Status ChallengeStatus `json:"status,omitempty"`

	// The time at which the challenge was successfully validated. Optional
	// unless Status is ChallengeValid.
	Validated time.Time `json:"validated,omitempty"` // RFC 3339

	// Error that occurred while the server was validating the challenge, if any.
	// Multiple errors are indicated using subproblems. This should (but is not
	// guaranteed to) be present if Status is StatusInvalid.
	Error *Problem `json:"error,omitempty"`

	// Sent for http-01, tls-sni-02, dns-01.
	Token string `json:"token,omitempty"`

	retryAt time.Time
}

// Specifies a challenge status.
type ChallengeStatus string

const (
	// The challenge is waiting to be initiated by client action before
	// verification occurs. This is the initial state.
	ChallengePending ChallengeStatus = "pending"
	// The challenge moves from the pending state to the processing state once
	// the client has initiated the challenge. The status will autonomously
	// advance to ChallengeValid or ChallengeInvalid.
	ChallengeProcessing = "processing"
	// Verification has succeeded. This is a final state.
	ChallengeValid = "valid"
	// Verification has failed. This is a final state.
	ChallengeInvalid = "invalid"
)

// Returns true iff the challenge status is a recognised challenge status
// value.
func (s ChallengeStatus) IsWellFormed() bool {
	switch s {
	case "pending", "processing", "valid", "invalid":
		return true
	default:
		return false
	}
}

// Returns true iff the challenge status is a final status.
func (s ChallengeStatus) IsFinal() bool {
	switch s {
	case "valid", "invalid":
		return true
	default:
		return false
	}
}

// Implements encoding/json.Unmarshaler.
func (s *ChallengeStatus) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !ChallengeStatus(ss).IsWellFormed() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = ChallengeStatus(ss)
	return nil
}

// ---------------------------------------------------------------------------------------------------------

// Represents a certificate which has been issued.
type Certificate struct {
	// The URL of the certificate resource.
	URL string `json:"-"`

	// The chain of certificates which a TLS server should send to a client in
	// order to facilitate client verification. A slice of DER-encoded
	// certificates. The first certificate is the end-entity certificate, the
	// second certificate if any is the issuing intermediate certificate, etc.
	//
	// Does not generally include the root certificate. If you need it (e.g.
	// because you are using DANE) you must append it yourself.
	CertificateChain [][]byte `json:"-"`

	// An URL from which the root certificate can be obtained. This is the
	// certificate in the chain which comes after the last certificate in
	// CertificateChain, and it usually should not be sent by TLS servers.
	RootCertificateURL string `json:"-"`
}
