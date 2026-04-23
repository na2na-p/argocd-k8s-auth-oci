// Package oke provides OKE (Oracle Kubernetes Engine) token generation.
package oke

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// TokenGenerator generates OKE bearer tokens from UPST credentials.
type TokenGenerator interface {
	Generate(ctx context.Context, upstToken string, privateKey *rsa.PrivateKey) (token string, expiry time.Time, err error)
}

// NewTokenGenerator creates a new TokenGenerator.
// The tokenLifetime parameter controls the reported expiry of the generated token.
func NewTokenGenerator(region string, clusterID string, tokenLifetime time.Duration) TokenGenerator {
	return &ociTokenGenerator{
		region:        region,
		clusterID:     clusterID,
		tokenLifetime: tokenLifetime,
	}
}

// upstKeyProvider implements common.KeyProvider for UPST-based signing.
// KeyID returns "ST$" + upstToken as required by OCI session token authentication.
type upstKeyProvider struct {
	privateKey *rsa.PrivateKey
	upstToken  string
}

// PrivateRSAKey returns the RSA private key for signing.
func (p *upstKeyProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return p.privateKey, nil
}

// KeyID returns the key identifier in "ST$<upstToken>" format.
func (p *upstKeyProvider) KeyID() (string, error) {
	return "ST$" + p.upstToken, nil
}

// ociTokenGenerator implements TokenGenerator using OCI HTTP signature signing.
type ociTokenGenerator struct {
	region        string
	clusterID     string
	tokenLifetime time.Duration
}

// Generate creates an OKE bearer token by:
//  1. Constructing a GET request to the OKE cluster_request endpoint
//  2. Signing it with the OCI HTTP signature scheme using the UPST credentials
//  3. Encoding the signed URL (with authorization and date as query parameters) in URL-safe base64
func (g *ociTokenGenerator) Generate(_ context.Context, upstToken string, privateKey *rsa.PrivateKey) (string, time.Time, error) {
	if privateKey == nil {
		return "", time.Time{}, fmt.Errorf("privateKey must not be nil")
	}

	endpoint := fmt.Sprintf("https://containerengine.%s.oraclecloud.com/cluster_request/%s", g.region, g.clusterID)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Date header before signing (required by OCI HTTP signature).
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	keyProvider := &upstKeyProvider{
		privateKey: privateKey,
		upstToken:  upstToken,
	}
	signer := common.DefaultRequestSigner(keyProvider)

	if err := signer.Sign(req); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign request: %w", err)
	}

	// Build the signed URL string following the OKE token format:
	// {endpoint}?{date=...&authorization=...}
	// Using url.Values for proper encoding, with date before authorization
	// to match the established OKE CLI convention.
	params := url.Values{}
	params.Add("date", req.Header.Get("Date"))
	params.Add("authorization", req.Header.Get("Authorization"))

	token := base64.StdEncoding.EncodeToString([]byte(endpoint + "?" + params.Encode()))
	expiry := time.Now().UTC().Add(g.tokenLifetime)

	return token, expiry, nil
}
