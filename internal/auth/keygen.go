// Package auth provides authentication utilities for OCI Identity Domain integration.
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
)

// KeyPair holds an ephemeral RSA key pair with the public key encoded as DER SPKI base64.
type KeyPair struct {
	PrivateKey      *rsa.PrivateKey
	PublicKeyBase64 string
}

// KeyGenerator generates ephemeral RSA key pairs for token exchange.
type KeyGenerator interface {
	GenerateKeyPair() (*KeyPair, error)
}

// rsaKeyGenerator implements KeyGenerator using RSA 2048-bit keys.
type rsaKeyGenerator struct {
	randReader io.Reader
}

// NewKeyGenerator creates a new KeyGenerator.
// If randReader is nil, crypto/rand.Reader is used.
func NewKeyGenerator(randReader io.Reader) KeyGenerator {
	if randReader == nil {
		randReader = rand.Reader
	}
	return &rsaKeyGenerator{randReader: randReader}
}

// GenerateKeyPair generates an ephemeral RSA 2048-bit key pair.
// The public key is returned as a DER SPKI base64-encoded string.
func (g *rsaKeyGenerator) GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(g.randReader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to PKIX DER: %w", err)
	}

	publicKeyBase64 := base64.StdEncoding.EncodeToString(derBytes)

	return &KeyPair{
		PrivateKey:      privateKey,
		PublicKeyBase64: publicKeyBase64,
	}, nil
}
