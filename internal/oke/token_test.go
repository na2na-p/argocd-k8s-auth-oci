package oke_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/oke"
)

func TestOKETokenGenerator_Generate(t *testing.T) {
	t.Parallel()

	// Setup: generate a real RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair for test setup: %v", err)
	}

	const (
		testRegion    = "us-ashburn-1"
		testClusterID = "ocid1.cluster.oc1.iad.aaaaaaaaexample"
		testUPST      = "test-upst-token-value"
		tokenLifetime = 4 * time.Minute
		tolerance     = 5 * time.Second
	)

	gen := oke.NewTokenGenerator(testRegion, testClusterID, tokenLifetime)

	before := time.Now().UTC()
	token, expiry, err := gen.Generate(context.Background(), testUPST, privateKey)
	after := time.Now().UTC()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the token is valid URL-safe base64.
	if token == "" {
		t.Fatal("token is empty")
	}
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token is not valid URL-safe base64: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded token is empty")
	}

	// Parse the decoded token as a URL for subsequent assertions.
	parsedURL, err := url.Parse(string(decoded))
	if err != nil {
		t.Fatalf("decoded token is not a valid URL: %v", err)
	}

	// Verify URL scheme, host, and path.
	wantScheme := "https"
	if diff := cmp.Diff(wantScheme, parsedURL.Scheme); diff != "" {
		t.Errorf("URL scheme mismatch (-want +got):\n%s", diff)
	}

	wantHost := "containerengine." + testRegion + ".oraclecloud.com"
	if diff := cmp.Diff(wantHost, parsedURL.Host); diff != "" {
		t.Errorf("URL host mismatch (-want +got):\n%s", diff)
	}

	wantPath := "/cluster_request/" + testClusterID
	if diff := cmp.Diff(wantPath, parsedURL.Path); diff != "" {
		t.Errorf("URL path mismatch (-want +got):\n%s", diff)
	}

	// Verify authorization query parameter contains "ST$" prefix.
	query := parsedURL.Query()
	authParam := query.Get("authorization")
	if authParam == "" {
		t.Error("decoded URL missing 'authorization' query parameter")
	}
	wantKeyIDPrefix := "ST$" + testUPST
	if !strings.Contains(authParam, wantKeyIDPrefix) {
		t.Errorf("authorization parameter does not contain keyId with ST$ prefix\ngot: %s\nwant to contain: %s", authParam, wantKeyIDPrefix)
	}

	// Verify date query parameter exists.
	if query.Get("date") == "" {
		t.Error("decoded URL missing 'date' query parameter")
	}

	// Verify expiry is approximately now + tokenLifetime.
	wantEarliestExpiry := before.Add(tokenLifetime).Add(-tolerance)
	wantLatestExpiry := after.Add(tokenLifetime).Add(tolerance)

	if expiry.Before(wantEarliestExpiry) {
		t.Errorf("expiry too early: got %v, want >= %v", expiry, wantEarliestExpiry)
	}
	if expiry.After(wantLatestExpiry) {
		t.Errorf("expiry too late: got %v, want <= %v", expiry, wantLatestExpiry)
	}

	gotDuration := expiry.Sub(before)
	diff := gotDuration - tokenLifetime
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("expiry duration mismatch: got %v from before, want ~%v (diff: %v)", gotDuration, tokenLifetime, diff)
	}
}

func TestOKETokenGenerator_Generate_NilPrivateKey(t *testing.T) {
	t.Parallel()

	const (
		testRegion    = "us-ashburn-1"
		testClusterID = "ocid1.cluster.oc1.iad.aaaaaaaaexample"
		testUPST      = "test-upst-token-value"
		tokenLifetime = 4 * time.Minute
	)

	gen := oke.NewTokenGenerator(testRegion, testClusterID, tokenLifetime)

	token, expiry, err := gen.Generate(context.Background(), testUPST, nil)

	if err == nil {
		t.Fatal("expected error for nil privateKey but got nil")
	}
	if !strings.Contains(err.Error(), "privateKey must not be nil") {
		t.Errorf("unexpected error message: %v", err)
	}
	if token != "" {
		t.Errorf("expected empty token on error, got: %s", token)
	}
	if !expiry.IsZero() {
		t.Errorf("expected zero expiry on error, got: %v", expiry)
	}
}
