package acmeapi

import (
	"context"
	"errors"
	"sync"
)

// Stores a pool of nonces used to make replay-proof requests.
type nonceSource struct {
	// If set, called when the nonce store is exhausted and a nonce is requested.
	// This function should add nonces to the nonceSource by calling AddNonce one
	// or more times. If this is not set, or if the function returns an error or
	// does not call AddNonce when called, an error is returned when attempting
	// to retrieve a nonce.
	GetNonceFunc func(ctx context.Context) error

	initOnce  sync.Once
	pool      map[string]struct{}
	poolMutex sync.Mutex
}

func (ns *nonceSource) init() {
	ns.initOnce.Do(func() {
		ns.pool = map[string]struct{}{}
	})
}

// Retrieves a new nonce. If no nonces remain in the pool, GetNonceFunc is used
// if possible to retrieve a new one. This may result in network I/O, hence the
// ctx parameter.
func (ns *nonceSource) Nonce(ctx context.Context) (string, error) {
	ns.init()

	k := ns.tryPop()
	if k != "" {
		return k, nil
	}

	err := ns.obtainNonce(ctx)
	if err != nil {
		return "", err
	}

	k = ns.tryPop()
	if k != "" {
		return k, nil
	}

	return "", errors.New("failed to retrieve additional nonce")
}

func (ns *nonceSource) tryPop() string {
	ns.poolMutex.Lock()
	defer ns.poolMutex.Unlock()

	for k := range ns.pool {
		delete(ns.pool, k)
		return k
	}

	return ""
}

func (ns *nonceSource) obtainNonce(ctx context.Context) error {
	if ns.GetNonceFunc == nil {
		return errors.New("out of nonces - this should never happen")
	}

	return ns.GetNonceFunc(ctx)
}

// Add a nonce to the pool. This is a no-op if the nonce is already in the
// pool.
func (ns *nonceSource) AddNonce(nonce string) {
	ns.init()
	ns.poolMutex.Lock()
	defer ns.poolMutex.Unlock()
	ns.pool[nonce] = struct{}{}
}

// Returns a struct with a single method, Nonce() which can be called to obtain
// a nonce. This adapts a nonceSource to an interface without a ctx parameter,
// which some libraries may expect, while allowing calls made by that library
// to still be made under a context.
func (ns *nonceSource) WithContext(ctx context.Context) *nonceSourceWithCtx {
	return &nonceSourceWithCtx{ns, ctx}
}

type nonceSourceWithCtx struct {
	nonceSource *nonceSource
	ctx         context.Context
}

// Obtain a nonce, using a context known by the object.
func (nc *nonceSourceWithCtx) Nonce() (string, error) {
	return nc.nonceSource.Nonce(nc.ctx)
}
