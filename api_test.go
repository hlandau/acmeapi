// +build integration

package acmeapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"git.devever.net/hlandau/acmeapi/pebbletest"
	"testing"
)

func TestRealmClient(t *testing.T) {
	rc, err := NewRealmClient(RealmClientConfig{
		DirectoryURL: "https://localhost:14000/dir",
		HTTPClient:   pebbletest.HTTPClient,
	})
	if err != nil {
		t.Fatalf("couldn't instantiate realm client: %v", err)
	}

	meta, err := rc.GetMeta(context.TODO())
	if err != nil {
		t.Fatalf("couldn't get metadata: %v", err)
	}

	t.Logf("metadata: %#v", meta)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate key: %v", err)
	}

	acct := &Account{
		PrivateKey:           privKey,
		TermsOfServiceAgreed: true,
	}

	err = rc.LocateAccount(context.TODO(), acct)
	if err == nil {
		t.Fatalf("locate account did NOT fail: %v", err)
	}
	t.Logf("locate account failed as expected: %v", err)

	err = rc.RegisterAccount(context.TODO(), acct)
	if err != nil {
		t.Fatalf("error while registering account: %v", err)
	}

	acct2 := &Account{
		PrivateKey: privKey,
	}
	err = rc.LocateAccount(context.TODO(), acct2)
	if err != nil {
		t.Fatalf("locate account failed: %v", err)
	}

	acct.ContactURIs = []string{"mailto:foo@example.com"}
	err = rc.UpdateAccount(context.TODO(), acct)
	if err != nil {
		t.Fatalf("update account failed: %v", err)
	}

	// CHECK: NewOrder
	order := &Order{
		Identifiers: []Identifier{
			{Type: IdentifierTypeDNS, Value: "example.com"},
		},
	}
	err = rc.NewOrder(context.TODO(), acct, order)
	if err != nil {
		t.Fatalf("error creating order: %v", err)
	}

	// CHECK: LoadAuthorization
	t.Logf("order: %#v", order)
	var authorizations []*Authorization
	for _, authURL := range order.AuthorizationURLs {
		authz := &Authorization{
			URL: authURL,
		}
		err = rc.LoadAuthorization(context.TODO(), acct, authz)
		if err != nil {
			t.Fatalf("cannot load authorization: %v", err)
		}
		authorizations = append(authorizations, authz)
	}

	// CHECK: LoadOrder
	order2 := &Order{
		URL: order.URL,
	}
	err = rc.LoadOrder(context.TODO(), order2)
	if err != nil {
		t.Fatalf("cannot load order: %v", err)
	}

	// CHECK: LoadOrderOrCertificate (order case)
	var order3 Order
	var dummyCert Certificate
	isCert, err := rc.LoadOrderOrCertificate(context.TODO(), order.URL, &order3, &dummyCert)
	if err != nil {
		t.Fatalf("cannot load order/certificate: %v", err)
	}
	if isCert || dummyCert.URL != "" || order3.URL == "" {
		t.Fatalf("unexpected certificate")
	}

	err = rc.RespondToChallenge(context.TODO(), acct, &authorizations[0].Challenges[0], json.RawMessage("{}"))
	if err != nil {
		t.Fatalf("failed to respond to challenge: %v", err)
	}

	err = rc.WaitLoadAuthorization(context.TODO(), acct, authorizations[0])
	if err != nil {
		t.Fatalf("failed to wait for authorization: %v", err)
	}

	// We don't care if it succeeded or not, that's not our job. We're just
	// testing the client functionality.
	if !authorizations[0].Status.IsFinal() {
		t.Fatalf("authorization is not final")
	}

	// Test loading a resource where the directory URL is unknown.
	rc2, err := NewRealmClient(RealmClientConfig{
		HTTPClient: pebbletest.HTTPClient,
	})
	if err != nil {
		t.Fatalf("couldn't instantiate second realm client: %v", err)
	}

	order4 := &Order{
		URL: order.URL,
	}
	err = rc2.LoadOrder(context.TODO(), order4)
	if err != nil {
		t.Fatalf("couldn't load order with second client: %v", err)
	}
}
