package oke_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/oke"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// writeTestKeyPEM はテスト用 RSA 鍵を PKCS#1 PEM 形式で生成し、
// PEM 内容文字列を返す。OCI SDK の NewRawConfigurationProvider は
// 第 5 引数に PEM 内容文字列を要求するため (auth.Config.Provider 側で
// os.ReadFile してから渡している)、本テストでは Provider 構築だけを
// 検証する目的でファイル化は省略し PEM 文字列を直接組み立てる。
func writeTestKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return string(pemBytes)
}

func TestOciTokenGenerator_Generate(t *testing.T) {
	t.Parallel()

	const (
		testRegion      = "us-ashburn-1"
		testClusterID   = "ocid1.cluster.oc1.iad.aaaaaaaaexample"
		testTenancy     = "ocid1.tenancy.oc1..aaaaaaaaexample"
		testUser        = "ocid1.user.oc1..aaaaaaaaexample"
		testFingerprint = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
		tokenLifetime   = 4 * time.Minute
		tolerance       = 5 * time.Second
	)

	cases := []struct {
		name          string
		provider      func(t *testing.T) common.ConfigurationProvider
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name: "API キー Provider で署名トークンを生成する",
			provider: func(t *testing.T) common.ConfigurationProvider {
				t.Helper()
				keyPEM := writeTestKeyPEM(t)
				return common.NewRawConfigurationProvider(
					testTenancy,
					testUser,
					testRegion,
					testFingerprint,
					keyPEM,
					nil,
				)
			},
		},
		{
			name: "provider が nil ならエラー",
			provider: func(_ *testing.T) common.ConfigurationProvider {
				return nil
			},
			wantErr:       true,
			wantErrSubstr: "provider must not be nil",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gen := oke.NewTokenGenerator(testRegion, testClusterID, tokenLifetime)
			provider := tc.provider(t)

			before := time.Now().UTC()
			token, expiry, err := gen.Generate(context.Background(), provider)
			after := time.Now().UTC()

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("unexpected error message: got %q, want substring %q", err.Error(), tc.wantErrSubstr)
				}
				if token != "" {
					t.Errorf("expected empty token on error, got: %s", token)
				}
				if !expiry.IsZero() {
					t.Errorf("expected zero expiry on error, got: %v", expiry)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if token == "" {
				t.Fatal("token is empty")
			}

			// OKE は standard base64 を要求するため StdEncoding で decode できることを検証。
			decoded, err := base64.StdEncoding.DecodeString(token)
			if err != nil {
				t.Fatalf("token is not valid standard base64: %v", err)
			}
			parsedURL, err := url.Parse(string(decoded))
			if err != nil {
				t.Fatalf("decoded token is not a valid URL: %v", err)
			}

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

			query := parsedURL.Query()
			authParam := query.Get("authorization")
			if authParam == "" {
				t.Fatal("decoded URL missing 'authorization' query parameter")
			}
			// API キー認証では keyId が <tenancy>/<user>/<fingerprint> 形式になることを保証する。
			wantKeyIDFragment := testTenancy + "/" + testUser + "/" + testFingerprint
			if !strings.Contains(authParam, wantKeyIDFragment) {
				t.Errorf("authorization parameter does not contain API key keyId\ngot: %s\nwant to contain: %s", authParam, wantKeyIDFragment)
			}
			// 旧 UPST 仕様 (ST$ prefix) が残っていないことの回帰確認。
			if strings.Contains(authParam, "ST$") {
				t.Errorf("authorization parameter unexpectedly contains UPST 'ST$' prefix: %s", authParam)
			}

			if query.Get("date") == "" {
				t.Error("decoded URL missing 'date' query parameter")
			}

			wantEarliestExpiry := before.Add(tokenLifetime).Add(-tolerance)
			wantLatestExpiry := after.Add(tokenLifetime).Add(tolerance)
			if expiry.Before(wantEarliestExpiry) {
				t.Errorf("expiry too early: got %v, want >= %v", expiry, wantEarliestExpiry)
			}
			if expiry.After(wantLatestExpiry) {
				t.Errorf("expiry too late: got %v, want <= %v", expiry, wantLatestExpiry)
			}
		})
	}
}
