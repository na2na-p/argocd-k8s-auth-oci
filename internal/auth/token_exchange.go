package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ExchangeResult holds the result of a token exchange.
type ExchangeResult struct {
	UPSTToken  string
	PrivateKey *rsa.PrivateKey
}

// TokenExchanger exchanges a subject token for a UPST via OCI Identity Domain.
type TokenExchanger interface {
	Exchange(ctx context.Context, saToken string) (*ExchangeResult, error)
}

// tokenExchangeResponse represents the JSON response from the OCI token endpoint.
type tokenExchangeResponse struct {
	Token string `json:"token"`
}

// ociTokenExchanger implements TokenExchanger using OCI Identity Domain's OAuth2 endpoint.
type ociTokenExchanger struct {
	identityDomainURL string
	clientID          string
	keyGenerator      KeyGenerator
	httpClient        *http.Client
}

// NewTokenExchanger creates a new TokenExchanger.
// The httpClient parameter allows injection of a custom HTTP client for testing.
// If httpClient is nil, http.DefaultClient is used.
func NewTokenExchanger(
	identityDomainURL string,
	clientID string,
	keyGenerator KeyGenerator,
	httpClient *http.Client,
) TokenExchanger {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &ociTokenExchanger{
		identityDomainURL: identityDomainURL,
		clientID:          clientID,
		keyGenerator:      keyGenerator,
		httpClient:        httpClient,
	}
}

// Exchange performs RFC 8693 token exchange, sending a SA token to the OCI Identity Domain
// and returning a UPST token along with the ephemeral private key.
func (e *ociTokenExchanger) Exchange(ctx context.Context, saToken string) (*ExchangeResult, error) {
	keyPair, err := e.keyGenerator.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	tokenEndpoint := e.identityDomainURL + "/oauth2/v1/token"

	formData := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:oci:token-type:oci-upst"},
		"subject_token":        {saToken},
		"subject_token_type":   {"jwt"},
		"public_key":           {keyPair.PublicKeyBase64},
	}

	// 5xx errors: retry once immediately. 4xx errors: no retry.
	const maxAttempts = 2
	for attempt := range maxAttempts {
		result, retryable, err := e.doExchange(ctx, tokenEndpoint, formData, keyPair.PrivateKey)
		if err == nil {
			return result, nil
		}
		if !retryable || attempt == maxAttempts-1 {
			return nil, err
		}
	}

	// Unreachable, but satisfies the compiler.
	return nil, fmt.Errorf("token exchange failed: exhausted all attempts")
}

// doExchange performs a single token exchange HTTP request.
// It returns the result, whether the error is retryable, and any error.
func (e *ociTokenExchanger) doExchange(
	ctx context.Context,
	tokenEndpoint string,
	formData url.Values,
	privateKey *rsa.PrivateKey,
) (*ExchangeResult, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Basic auth with client_id as username and empty password per OCI UPST spec.
	basicAuth := base64.StdEncoding.EncodeToString([]byte(e.clientID + ":"))
	req.Header.Set("Authorization", "Basic "+basicAuth)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to send token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 500 {
		return nil, true, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenExchangeResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, false, fmt.Errorf("failed to decode token exchange response: %w", err)
	}

	if tokenResp.Token == "" {
		return nil, false, fmt.Errorf("token exchange response contains empty token")
	}

	return &ExchangeResult{
		UPSTToken:  tokenResp.Token,
		PrivateKey: privateKey,
	}, false, nil
}
