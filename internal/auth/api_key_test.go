package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/auth"
)

// writeTestKeyPEM はテスト用 RSA 鍵を PKCS#1 PEM 形式で TempDir に書き出し、
// そのファイルパスを返す。Config.Provider() の E2E 検証 (PEM 読込 → SDK の
// PrivateRSAKey()) で利用する。
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
	path := filepath.Join(t.TempDir(), "oci_api_key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	return path
}

// newLookup はテスト用に map ベースの環境変数 lookup を生成する。
func newLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// fullEnv は必須キーすべてが揃った baseline env を返す。
// 各 case は本関数の戻り値を起点に欠落 / 上書きを表現する。
func fullEnv() map[string]string {
	return map[string]string{
		auth.EnvKeyTenancy:     "ocid1.tenancy.oc1..t",
		auth.EnvKeyUser:        "ocid1.user.oc1..u",
		auth.EnvKeyRegion:      "ap-tokyo-1",
		auth.EnvKeyFingerprint: "aa:bb:cc:dd:ee",
		auth.EnvKeyKeyFile:     "/etc/oci/key.pem",
	}
}

func ptr(s string) *string { return &s }

func TestConfigFromEnv(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		env        map[string]string
		want       *auth.Config
		wantErr    error
		wantErrKey string // 期待されるエラー文字列に含まれる env キー (sentinel と併用)
	}{
		{
			name: "全必須環境変数を設定すると成功",
			env:  fullEnv(),
			want: &auth.Config{
				Tenancy:     "ocid1.tenancy.oc1..t",
				User:        "ocid1.user.oc1..u",
				Region:      "ap-tokyo-1",
				Fingerprint: "aa:bb:cc:dd:ee",
				KeyFile:     "/etc/oci/key.pem",
			},
		},
		{
			name: "OCI_PASSPHRASE を設定するとポインタが入る",
			env: func() map[string]string {
				e := fullEnv()
				e[auth.EnvKeyPassphrase] = "s3cret"
				return e
			}(),
			want: &auth.Config{
				Tenancy:     "ocid1.tenancy.oc1..t",
				User:        "ocid1.user.oc1..u",
				Region:      "ap-tokyo-1",
				Fingerprint: "aa:bb:cc:dd:ee",
				KeyFile:     "/etc/oci/key.pem",
				Passphrase:  ptr("s3cret"),
			},
		},
		{
			name: "OCI_PASSPHRASE が空文字なら absent 扱い",
			env: func() map[string]string {
				e := fullEnv()
				e[auth.EnvKeyPassphrase] = ""
				return e
			}(),
			want: &auth.Config{
				Tenancy:     "ocid1.tenancy.oc1..t",
				User:        "ocid1.user.oc1..u",
				Region:      "ap-tokyo-1",
				Fingerprint: "aa:bb:cc:dd:ee",
				KeyFile:     "/etc/oci/key.pem",
			},
		},
		{
			name: "OCI_TENANCY 未設定でエラー",
			env: func() map[string]string {
				e := fullEnv()
				delete(e, auth.EnvKeyTenancy)
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyTenancy,
		},
		{
			name: "OCI_USER 未設定でエラー",
			env: func() map[string]string {
				e := fullEnv()
				delete(e, auth.EnvKeyUser)
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyUser,
		},
		{
			name: "OCI_REGION 未設定でエラー",
			env: func() map[string]string {
				e := fullEnv()
				delete(e, auth.EnvKeyRegion)
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyRegion,
		},
		{
			name: "OCI_FINGERPRINT 未設定でエラー",
			env: func() map[string]string {
				e := fullEnv()
				delete(e, auth.EnvKeyFingerprint)
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyFingerprint,
		},
		{
			name: "OCI_KEY_FILE 未設定でエラー",
			env: func() map[string]string {
				e := fullEnv()
				delete(e, auth.EnvKeyKeyFile)
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyKeyFile,
		},
		{
			name: "必須キーが空文字なら未設定扱いでエラー",
			env: func() map[string]string {
				e := fullEnv()
				e[auth.EnvKeyRegion] = ""
				return e
			}(),
			wantErr:    auth.ErrRequiredEnvMissing,
			wantErrKey: auth.EnvKeyRegion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := auth.ConfigFromEnv(newLookup(tc.env))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("errors.Is mismatch: got %v, want sentinel %v", err, tc.wantErr)
				}
				if tc.wantErrKey != "" && !strings.Contains(err.Error(), tc.wantErrKey) {
					t.Errorf("error message: got %q, want substring %q", err.Error(), tc.wantErrKey)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfig_Provider(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		buildCfg      func(t *testing.T) *auth.Config
		wantErr       error
		wantErrSubstr string
	}{
		{
			name: "Passphrase なしで PEM ファイルから rsa.PrivateKey を取得できる",
			buildCfg: func(t *testing.T) *auth.Config {
				t.Helper()
				return &auth.Config{
					Tenancy:     "ocid1.tenancy.oc1..t",
					User:        "ocid1.user.oc1..u",
					Region:      "ap-tokyo-1",
					Fingerprint: "aa:bb:cc:dd:ee",
					KeyFile:     writeTestKeyPEM(t),
				}
			},
		},
		{
			name: "Passphrase ありでも PEM ファイルから rsa.PrivateKey を取得できる",
			buildCfg: func(t *testing.T) *auth.Config {
				t.Helper()
				// 平文 PEM + Passphrase 非 nil。OCI SDK は Passphrase が非 nil でも
				// 平文 PEM なら正しくデコードできる (暗号化ヘッダがあれば適用) ことを利用し、
				// Provider() がシグネチャ変更後も Passphrase を SDK に通すことを確認する。
				return &auth.Config{
					Tenancy:     "ocid1.tenancy.oc1..t",
					User:        "ocid1.user.oc1..u",
					Region:      "ap-tokyo-1",
					Fingerprint: "aa:bb:cc:dd:ee",
					KeyFile:     writeTestKeyPEM(t),
					Passphrase:  ptr("s3cret"),
				}
			},
		},
		{
			name: "KeyFile が存在しない場合は ErrKeyFileRead",
			buildCfg: func(t *testing.T) *auth.Config {
				t.Helper()
				return &auth.Config{
					Tenancy:     "ocid1.tenancy.oc1..t",
					User:        "ocid1.user.oc1..u",
					Region:      "ap-tokyo-1",
					Fingerprint: "aa:bb:cc:dd:ee",
					KeyFile:     filepath.Join(t.TempDir(), "does-not-exist.pem"),
				}
			},
			wantErr:       auth.ErrKeyFileRead,
			wantErrSubstr: "does-not-exist.pem",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := tc.buildCfg(t)
			provider, err := cfg.Provider()

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("errors.Is mismatch: got %v, want sentinel %v", err, tc.wantErr)
				}
				if tc.wantErrSubstr != "" && !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("error message: got %q, want substring %q", err.Error(), tc.wantErrSubstr)
				}
				if provider != nil {
					t.Errorf("expected nil provider on error, got: %v", provider)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if provider == nil {
				t.Fatal("Provider() returned nil ConfigurationProvider")
			}

			// E2E: SDK が PEM をデコードして RSA 秘密鍵を取り出せることを確認する。
			// 以前は KeyFile (パス) を SDK に渡しており PrivateRSAKey() が
			// "PEM data was not found in buffer" で必ず失敗していた (CR-9 の本質)。
			key, err := provider.PrivateRSAKey()
			if err != nil {
				t.Fatalf("PrivateRSAKey() failed: %v", err)
			}
			if key == nil {
				t.Fatal("PrivateRSAKey() returned nil key")
			}
			if err := key.Validate(); err != nil {
				t.Errorf("RSA key is invalid: %v", err)
			}
		})
	}
}
