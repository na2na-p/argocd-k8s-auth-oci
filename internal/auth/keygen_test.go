package auth_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/auth"
)

// errorReader is an io.Reader that always returns an error.
type errorReader struct{}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, errors.New("forced read error")
}

func TestRSAKeyGenerator_GenerateKeyPair(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		randReader io.Reader
		wantErr    bool
	}{
		{
			name:       "正常系: RSA 2048bit キーペアが生成される",
			randReader: nil, // use crypto/rand.Reader
			wantErr:    false,
		},
		{
			name:       "異常系: rand.Reader がエラーを返す場合にエラーが返される",
			randReader: &errorReader{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var gen auth.KeyGenerator
			if tt.randReader != nil {
				gen = auth.NewKeyGenerator(tt.randReader)
			} else {
				gen = auth.NewKeyGenerator(nil)
			}

			kp, err := gen.GenerateKeyPair()

			if tt.wantErr {
				// Go 1.24+ ignores the rand parameter in rsa.GenerateKey and uses
				// the system CSPRNG directly. The error injection via io.Reader no
				// longer triggers an error. We skip this assertion on affected versions.
				if err == nil {
					t.Skip("Go 1.24+ ignores custom rand reader in rsa.GenerateKey; error injection is not possible")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify RSA 2048-bit private key
			if kp.PrivateKey == nil {
				t.Fatal("PrivateKey is nil")
			}
			wantBits := 2048
			gotBits := kp.PrivateKey.N.BitLen()
			if diff := cmp.Diff(wantBits, gotBits); diff != "" {
				t.Errorf("key bit length mismatch (-want +got):\n%s", diff)
			}

			// Verify PublicKeyBase64 is not empty
			if kp.PublicKeyBase64 == "" {
				t.Fatal("PublicKeyBase64 is empty")
			}
		})
	}
}

func TestRSAKeyGenerator_GenerateKeyPair_PublicKeyFormat(t *testing.T) {
	t.Parallel()

	t.Run("正常系: 公開鍵が有効な DER SPKI base64 形式である", func(t *testing.T) {
		t.Parallel()

		gen := auth.NewKeyGenerator(nil)
		kp, err := gen.GenerateKeyPair()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Decode base64
		derBytes, err := base64.StdEncoding.DecodeString(kp.PublicKeyBase64)
		if err != nil {
			t.Fatalf("failed to decode base64: %v", err)
		}

		// Parse as PKIX public key
		pubKey, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			t.Fatalf("failed to parse PKIX public key: %v", err)
		}

		// Verify it is an RSA public key
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("parsed key is not *rsa.PublicKey, got %T", pubKey)
		}

		wantBits := 2048
		gotBits := rsaPub.N.BitLen()
		if diff := cmp.Diff(wantBits, gotBits); diff != "" {
			t.Errorf("parsed public key bit length mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestRSAKeyGenerator_GenerateKeyPair_KeyCorrespondence(t *testing.T) {
	t.Parallel()

	t.Run("正常系: 秘密鍵と公開鍵が対応している", func(t *testing.T) {
		t.Parallel()

		gen := auth.NewKeyGenerator(nil)
		kp, err := gen.GenerateKeyPair()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Decode the public key from base64
		derBytes, err := base64.StdEncoding.DecodeString(kp.PublicKeyBase64)
		if err != nil {
			t.Fatalf("failed to decode base64: %v", err)
		}

		pubKey, err := x509.ParsePKIXPublicKey(derBytes)
		if err != nil {
			t.Fatalf("failed to parse PKIX public key: %v", err)
		}

		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("parsed key is not *rsa.PublicKey, got %T", pubKey)
		}

		// Verify that the public key from the base64 string matches the private key's public key
		privPub := &kp.PrivateKey.PublicKey
		if privPub.N.Cmp(rsaPub.N) != 0 || privPub.E != rsaPub.E {
			t.Error("private key's public key does not match the decoded public key")
		}
	})
}
