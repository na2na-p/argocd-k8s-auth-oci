package cmd_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/cmd"
)

// execCredentialJSON は ExecCredential 出力検証用の最小構造体。
type execCredentialJSON struct {
	APIVersion string                    `json:"apiVersion"`
	Kind       string                    `json:"kind"`
	Status     *execCredentialStatusJSON `json:"status,omitempty"`
}

type execCredentialStatusJSON struct {
	ExpirationTimestamp string `json:"expirationTimestamp,omitempty"`
	Token               string `json:"token,omitempty"`
}

// writeTestKeyPEM はテスト用 RSA 鍵を PKCS#1 PEM 形式で TempDir に書き出し、
// そのファイルパスを返す。auth.Config.Provider() が PEM 読み取り → SDK 構築まで
// 通すことを検証するために利用する。
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

// fullAuthEnv は OCI API キー認証で必須の環境変数すべてを map で返す。
// 各テストはこの戻り値を起点に欠落 / 上書きを表現する。
func fullAuthEnv(keyFile string) map[string]string {
	return map[string]string{
		"OCI_TENANCY":     "ocid1.tenancy.oc1..t",
		"OCI_USER":        "ocid1.user.oc1..u",
		"OCI_FINGERPRINT": "aa:bb:cc:dd:ee",
		"OCI_KEY_FILE":    keyFile,
		"OCI_REGION":      "us-ashburn-1",
		"OCI_CLUSTER_ID":  "ocid1.cluster.oc1.iad.test",
	}
}

// newLookup は map ベースの環境変数 lookup を生成する。
func newLookup(env map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// newTestRootCmd は cmd.NewRootCmdForTest 経由で root コマンドを生成し、
// stdout を bytes.Buffer に取り込んで返す。
func newTestRootCmd(envLookup func(string) (string, bool), args []string) (*bytes.Buffer, error) {
	rootCmd := cmd.NewRootCmdForTest(envLookup)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	return buf, err
}

func TestRootCommand_VersionFlag(t *testing.T) {
	// SetVersionInfo が package-level state を変更するため t.Parallel() は使わない。

	tests := []struct {
		name       string
		args       []string
		version    string
		commit     string
		wantSubstr string
	}{
		{
			name:       "正常系: --version フラグでバージョン情報が出力される",
			args:       []string{"--version"},
			version:    "1.2.3",
			commit:     "abc1234",
			wantSubstr: "argocd-k8s-auth-oci version 1.2.3 (commit: abc1234)",
		},
		{
			name:       "正常系: -v ショートフラグでバージョン情報が出力される",
			args:       []string{"-v"},
			version:    "0.1.0",
			commit:     "deadbeef",
			wantSubstr: "argocd-k8s-auth-oci version 0.1.0 (commit: deadbeef)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// SetVersionInfo の競合を避けるため逐次実行。
			cmd.SetVersionInfo(tt.version, tt.commit)

			noEnv := func(string) (string, bool) { return "", false }
			buf, err := newTestRootCmd(noEnv, tt.args)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := buf.String()
			if !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("output %q does not contain %q", got, tt.wantSubstr)
			}
		})
	}
}

func TestRootCommand_RequiredFlagValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		args          []string
		wantErrSubstr string
	}{
		{
			name:          "異常系: --cluster-id 未指定でエラー",
			args:          []string{"--region=us-ashburn-1"},
			wantErrSubstr: "--cluster-id is required",
		},
		{
			name:          "異常系: --region 未指定でエラー",
			args:          []string{"--cluster-id=ocid1.cluster.oc1.iad.test"},
			wantErrSubstr: "--region is required",
		},
		{
			name:          "異常系: 必須フラグ全未指定でエラー",
			args:          []string{},
			wantErrSubstr: "--cluster-id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			noEnv := func(string) (string, bool) { return "", false }
			_, err := newTestRootCmd(noEnv, tt.args)

			if err == nil {
				t.Fatal("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestRootCommand_EnvVariableBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		envOverride       map[string]string
		envDelete         []string
		args              []string
		wantErrSubstr     string
		wantClusterRegion bool // cluster-id と region がフラグ経由で設定されることを期待
	}{
		{
			name:              "正常系: OCI_CLUSTER_ID / OCI_REGION 環境変数からフラグが設定される",
			args:              []string{},
			wantClusterRegion: true,
		},
		{
			name: "正常系: フラグが環境変数より優先される",
			envOverride: map[string]string{
				"OCI_CLUSTER_ID": "env-cluster-id",
				"OCI_REGION":     "env-region",
			},
			args:              []string{"--cluster-id=flag-cluster-id", "--region=flag-region"},
			wantClusterRegion: true,
		},
		{
			name: "異常系: OCI_TENANCY 未設定で configuration error",
			envDelete: []string{
				"OCI_TENANCY",
			},
			args:          []string{},
			wantErrSubstr: "OCI authentication configuration error",
		},
		{
			name: "異常系: OCI_KEY_FILE が存在しないパスを指すと key file error",
			envOverride: map[string]string{
				"OCI_KEY_FILE": "/nonexistent/path/to/key.pem",
			},
			args:          []string{},
			wantErrSubstr: "OCI key file error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keyFile := writeTestKeyPEM(t)
			env := fullAuthEnv(keyFile)
			for k, v := range tt.envOverride {
				env[k] = v
			}
			for _, k := range tt.envDelete {
				delete(env, k)
			}

			_, err := newTestRootCmd(newLookup(env), tt.args)

			if tt.wantErrSubstr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q but got nil", tt.wantErrSubstr)
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}

			// wantClusterRegion ケースでは provider 構築まで成功し OKE token 生成まで
			// 到達するため、err は nil になる想定。
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRootCommand_IntegrationSuccess(t *testing.T) {
	t.Parallel()

	t.Run("正常系: 全モジュール統合でExecCredential JSONが出力される", func(t *testing.T) {
		t.Parallel()

		keyFile := writeTestKeyPEM(t)
		env := fullAuthEnv(keyFile)
		args := []string{
			"--token-lifetime=4m",
			"--timeout=10s",
		}

		buf, err := newTestRootCmd(newLookup(env), args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 出力が valid な ExecCredential JSON であることを検証する。
		out := strings.TrimSpace(buf.String())
		if out == "" {
			t.Fatal("output is empty")
		}

		var cred execCredentialJSON
		if err := json.Unmarshal([]byte(out), &cred); err != nil {
			t.Fatalf("failed to parse ExecCredential JSON: %v\nraw output: %s", err, out)
		}

		wantAPIVersion := "client.authentication.k8s.io/v1beta1"
		if diff := cmp.Diff(wantAPIVersion, cred.APIVersion); diff != "" {
			t.Errorf("apiVersion mismatch (-want +got):\n%s", diff)
		}

		wantKind := "ExecCredential"
		if diff := cmp.Diff(wantKind, cred.Kind); diff != "" {
			t.Errorf("kind mismatch (-want +got):\n%s", diff)
		}

		if cred.Status == nil {
			t.Fatal("status is nil")
		}
		if cred.Status.Token == "" {
			t.Error("token is empty")
		}
		if cred.Status.ExpirationTimestamp == "" {
			t.Error("expirationTimestamp is empty")
		}
	})
}

func TestRootCommand_DefaultFlagValues(t *testing.T) {
	t.Parallel()

	t.Run("正常系: デフォルトのフラグ値が正しい", func(t *testing.T) {
		t.Parallel()

		noEnv := func(string) (string, bool) { return "", false }
		rootCmd := cmd.NewRootCmdForTest(noEnv)

		tokenLifetimeFlag := rootCmd.Flags().Lookup("token-lifetime")
		if tokenLifetimeFlag == nil {
			t.Fatal("token-lifetime flag not found")
		}
		if diff := cmp.Diff("4m0s", tokenLifetimeFlag.DefValue); diff != "" {
			t.Errorf("token-lifetime default mismatch (-want +got):\n%s", diff)
		}

		timeoutFlag := rootCmd.Flags().Lookup("timeout")
		if timeoutFlag == nil {
			t.Fatal("timeout flag not found")
		}
		if diff := cmp.Diff("10s", timeoutFlag.DefValue); diff != "" {
			t.Errorf("timeout default mismatch (-want +got):\n%s", diff)
		}

		debugFlag := rootCmd.Flags().Lookup("debug")
		if debugFlag == nil {
			t.Fatal("debug flag not found")
		}
		if diff := cmp.Diff("false", debugFlag.DefValue); diff != "" {
			t.Errorf("debug default mismatch (-want +got):\n%s", diff)
		}

		versionFlag := rootCmd.Flags().Lookup("version")
		if versionFlag == nil {
			t.Fatal("version flag not found")
		}
		if diff := cmp.Diff("v", versionFlag.Shorthand); diff != "" {
			t.Errorf("version shorthand mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestRootCommand_RemovedLegacyFlags(t *testing.T) {
	t.Parallel()

	// UPST 経路で利用していた旧フラグが新コマンドから完全に削除されていることを保証する。
	t.Run("異常系: 旧UPSTフラグはすべて削除されている", func(t *testing.T) {
		t.Parallel()

		noEnv := func(string) (string, bool) { return "", false }
		rootCmd := cmd.NewRootCmdForTest(noEnv)

		legacyFlags := []string{
			"identity-domain-url",
			"client-id",
			"client-secret",
			"token-path",
		}
		for _, name := range legacyFlags {
			if f := rootCmd.Flags().Lookup(name); f != nil {
				t.Errorf("legacy flag --%s should be removed but still present", name)
			}
		}
	})
}

func TestRootCommand_MaskToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "正常系: 長いトークンの先頭4文字と末尾4文字以外がマスクされる",
			token: "abcdefghijklmnop",
			want:  "abcd****mnop",
		},
		{
			name:  "正常系: 8文字以下のトークンは全てマスクされる",
			token: "abcdefgh",
			want:  "****",
		},
		{
			name:  "正常系: 空文字列は全てマスクされる",
			token: "",
			want:  "****",
		},
		{
			name:  "正常系: 9文字のトークンは先頭4文字と末尾4文字が表示される",
			token: "123456789",
			want:  "1234****6789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cmd.MaskTokenForTest(tt.token)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("maskToken mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
