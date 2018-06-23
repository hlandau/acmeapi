// Package pebbletest provides functions for launching and managing Pebble
// during testing.
package pebbletest

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

var pebbleCmd *exec.Cmd

// HTTP client which can be used to talk to Pebble. Disables certificate
// checks, etc. as necessary. You must call Init() before using this.
var HTTPClient *http.Client

type writerFunc func(p []byte) (n int, err error)

func (wf writerFunc) Write(p []byte) (n int, err error) {
	return wf(p)
}

// Launches pebble. Tests are terminated fatally if launching pebble fails. If
// pebble has already been launched, does nothing.
func Init(t *testing.T) {
	if pebbleCmd != nil {
		return
	}

	httpTransport := *http.DefaultTransport.(*http.Transport)
	httpTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	HTTPClient = &http.Client{
		Transport: &httpTransport,
	}

	os.Setenv("PEBBLE_WFE_NONCEREJECT", "80")

	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		t.Fatalf("No $GOPATH set; in order to run the acmeapi test suite, please set $GOPATH and run `go get github.com/letsencrypt/pebble/cmd/pebble`.")
	}

	pebblePath := filepath.Join(gopath, "bin/pebble")
	_, err := os.Stat(pebblePath)
	if err != nil {
		t.Fatalf("Could not stat %q (%v); in order to run the acmeapi test suite, `pebble` must be installed in $GOPATH/bin. Please run `go get github.com/letsencrypt/pebble/cmd/pebble`.", pebblePath, err)
	}

	listening := false
	listenChan := make(chan struct{})
	cmd := exec.Command(pebblePath, "-strict")
	cmd.Dir = filepath.Join(gopath, "src/github.com/letsencrypt/pebble")
	cmd.Stderr = os.Stderr
	cmd.Stdout = writerFunc(func(p []byte) (n int, err error) {
		n, err = os.Stdout.Write(p)
		if bytes.Index(p, []byte("listening on:")) >= 0 && !listening {
			close(listenChan)
			listening = true
		}
		return
	})
	err = cmd.Start()
	if err != nil {
		t.Fatalf("could not start pebble: %v", err)
	}

	<-listenChan
	pebbleCmd = cmd
}

// Ensures that Pebble is killed after a function returns. Call Init inside the
// closure passed. The return value is passed through.
func With(f func() int) int {
	defer func() {
		if pebbleCmd != nil {
			pebbleCmd.Process.Signal(syscall.SIGINT)
			pebbleCmd.Wait()
		}
	}()

	return f()
}
