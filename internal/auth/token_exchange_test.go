package auth_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/auth"
)

// fakeKeyGenerator implements auth.KeyGenerator for testing.
type fakeKeyGenerator struct {
	keyPair *auth.KeyPair
	err     error
}

func (f *fakeKeyGenerator) GenerateKeyPair() (*auth.KeyPair, error) {
	return f.keyPair, f.err
}

func TestTokenExchanger_Exchange(t *testing.T) {
	t.Parallel()

	// Generate a real key pair for tests that need valid keys.
	realGen := auth.NewKeyGenerator(nil)
	realKP, err := realGen.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair for test setup: %v", err)
	}

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		keyGenerator  auth.KeyGenerator
		saToken       string
		wantToken     string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name: "正常系: UPST トークンが返却される",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method and content type.
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
					t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
				}
				// Verify Authorization header exists with Basic scheme.
				authHeader := r.Header.Get("Authorization")
				if authHeader == "" {
					t.Error("Authorization header is missing")
				}

				if err := r.ParseForm(); err != nil {
					t.Errorf("failed to parse form: %v", err)
				}
				if got := r.FormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
					t.Errorf("unexpected grant_type: %s", got)
				}
				if got := r.FormValue("requested_token_type"); got != "urn:oci:token-type:oci-upst" {
					t.Errorf("unexpected requested_token_type: %s", got)
				}
				if got := r.FormValue("subject_token"); got != "test-sa-token" {
					t.Errorf("unexpected subject_token: %s", got)
				}
				if got := r.FormValue("subject_token_type"); got != "jwt" {
					t.Errorf("unexpected subject_token_type: %s", got)
				}
				if got := r.FormValue("public_key"); got == "" {
					t.Error("public_key is empty")
				}

				w.Header().Set("Content-Type", "application/json")
				resp := map[string]string{"token": "upst-token-value"}
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					t.Errorf("failed to encode response: %v", err)
				}
			}),
			keyGenerator: &fakeKeyGenerator{
				keyPair: realKP,
			},
			saToken:   "test-sa-token",
			wantToken: "upst-token-value",
			wantErr:   false,
		},
		{
			name: "異常系: 401 Unauthorized でリトライなしにエラーが返される",
			handler: func() http.HandlerFunc {
				var callCount atomic.Int32
				return func(w http.ResponseWriter, _ *http.Request) {
					callCount.Add(1)
					if callCount.Load() > 1 {
						t.Error("should not retry on 401")
					}
					w.WriteHeader(http.StatusUnauthorized)
					resp := map[string]string{"error": "unauthorized"}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Errorf("failed to encode response: %v", err)
					}
				}
			}(),
			keyGenerator:  &fakeKeyGenerator{keyPair: realKP},
			saToken:       "test-sa-token",
			wantErr:       true,
			wantErrSubstr: "401",
		},
		{
			name: "異常系: 400 Bad Request でリトライなしにエラーが返される",
			handler: func() http.HandlerFunc {
				var callCount atomic.Int32
				return func(w http.ResponseWriter, _ *http.Request) {
					callCount.Add(1)
					if callCount.Load() > 1 {
						t.Error("should not retry on 400")
					}
					w.WriteHeader(http.StatusBadRequest)
					resp := map[string]string{"error": "bad_request"}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Errorf("failed to encode response: %v", err)
					}
				}
			}(),
			keyGenerator:  &fakeKeyGenerator{keyPair: realKP},
			saToken:       "test-sa-token",
			wantErr:       true,
			wantErrSubstr: "400",
		},
		{
			name: "異常系: 500 Internal Server Error で1回リトライ後に成功する",
			handler: func() http.HandlerFunc {
				var callCount atomic.Int32
				return func(w http.ResponseWriter, _ *http.Request) {
					n := callCount.Add(1)
					if n == 1 {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					resp := map[string]string{"token": "upst-after-retry"}
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						t.Errorf("failed to encode response: %v", err)
					}
				}
			}(),
			keyGenerator: &fakeKeyGenerator{keyPair: realKP},
			saToken:      "test-sa-token",
			wantToken:    "upst-after-retry",
			wantErr:      false,
		},
		{
			name: "異常系: 500 が2回続くとエラーが返される",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
			keyGenerator:  &fakeKeyGenerator{keyPair: realKP},
			saToken:       "test-sa-token",
			wantErr:       true,
			wantErrSubstr: "500",
		},
		{
			name: "異常系: コンテキストキャンセルでエラーが返される",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				// This handler should never be called because context is already cancelled.
				w.WriteHeader(http.StatusOK)
			}),
			keyGenerator:  &fakeKeyGenerator{keyPair: realKP},
			saToken:       "test-sa-token",
			wantErr:       true,
			wantErrSubstr: "context canceled",
		},
		{
			name:    "異常系: KeyGenerator がエラーを返す場合にエラーが返される",
			handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
			keyGenerator: &fakeKeyGenerator{
				err: errors.New("key generation failed"),
			},
			saToken:       "test-sa-token",
			wantErr:       true,
			wantErrSubstr: "key generation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			exchanger := auth.NewTokenExchanger(
				srv.URL,
				"test-client-id",
				tt.keyGenerator,
				srv.Client(),
			)

			ctx := context.Background()
			if tt.name == "異常系: コンテキストキャンセルでエラーが返される" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel() // Cancel immediately.
			}

			result, err := exchanger.Exchange(ctx, tt.saToken)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.wantErrSubstr != "" {
					if !containsSubstring(err.Error(), tt.wantErrSubstr) {
						t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.wantToken, result.UPSTToken); diff != "" {
				t.Errorf("UPSTToken mismatch (-want +got):\n%s", diff)
			}
			if result.PrivateKey == nil {
				t.Error("PrivateKey is nil")
			}
		})
	}
}

func TestTokenExchanger_Exchange_PrivateKeyReturned(t *testing.T) {
	t.Parallel()

	t.Run("正常系: ExchangeResult に秘密鍵が含まれる", func(t *testing.T) {
		t.Parallel()

		realGen := auth.NewKeyGenerator(nil)
		realKP, err := realGen.GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{"token": "upst-token"}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		t.Cleanup(srv.Close)

		exchanger := auth.NewTokenExchanger(
			srv.URL,
			"test-client-id",
			&fakeKeyGenerator{keyPair: realKP},
			srv.Client(),
		)

		result, err := exchanger.Exchange(context.Background(), "sa-token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the returned private key is a valid RSA key.
		if result.PrivateKey == nil {
			t.Fatal("PrivateKey is nil")
		}
		if _, ok := interface{}(result.PrivateKey).(*rsa.PrivateKey); !ok {
			t.Errorf("PrivateKey is not *rsa.PrivateKey, got %T", result.PrivateKey)
		}
	})
}

// containsSubstring reports whether s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
