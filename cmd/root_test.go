package cmd_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/cmd"
)

// execCredentialJSON is a minimal representation used to verify JSON output.
type execCredentialJSON struct {
	APIVersion string                    `json:"apiVersion"`
	Kind       string                    `json:"kind"`
	Status     *execCredentialStatusJSON `json:"status,omitempty"`
}

type execCredentialStatusJSON struct {
	ExpirationTimestamp string `json:"expirationTimestamp,omitempty"`
	Token               string `json:"token,omitempty"`
}

// newTestRootCmd creates a root command for testing via cmd.NewRootCmdForTest.
// It captures stdout into the returned buffer.
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
	// Do not use t.Parallel() because SetVersionInfo modifies package-level state.

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
			// Sequential execution required: SetVersionInfo mutates shared package state.
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

	// Create a temporary token file.
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-sa-token"), 0o600); err != nil {
		t.Fatalf("failed to write token file: %v", err)
	}

	tests := []struct {
		name          string
		args          []string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:          "異常系: --identity-domain-url 未指定でエラー",
			args:          []string{"--client-id=cid", "--cluster-id=clid", "--region=us-ashburn-1", "--token-path=" + tokenFile},
			wantErr:       true,
			wantErrSubstr: "--identity-domain-url is required",
		},
		{
			name:          "異常系: --client-id 未指定でエラー",
			args:          []string{"--identity-domain-url=https://example.com", "--cluster-id=clid", "--region=us-ashburn-1", "--token-path=" + tokenFile},
			wantErr:       true,
			wantErrSubstr: "--client-id is required",
		},
		{
			name:          "異常系: --cluster-id 未指定でエラー",
			args:          []string{"--identity-domain-url=https://example.com", "--client-id=cid", "--region=us-ashburn-1", "--token-path=" + tokenFile},
			wantErr:       true,
			wantErrSubstr: "--cluster-id is required",
		},
		{
			name:          "異常系: --region 未指定でエラー",
			args:          []string{"--identity-domain-url=https://example.com", "--client-id=cid", "--cluster-id=clid", "--token-path=" + tokenFile},
			wantErr:       true,
			wantErrSubstr: "--region is required",
		},
		{
			name:          "異常系: 全必須フラグ未指定でエラー",
			args:          []string{"--token-path=" + tokenFile},
			wantErr:       true,
			wantErrSubstr: "--identity-domain-url is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			noEnv := func(string) (string, bool) { return "", false }
			_, err := newTestRootCmd(noEnv, tt.args)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRootCommand_EnvVariableBinding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		envVars       map[string]string
		args          []string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name: "正常系: 環境変数から全必須フラグが読み取られる（トークン読み取りでエラーになるが環境変数バインドは成功）",
			envVars: map[string]string{
				"OCI_IDENTITY_DOMAIN_URL": "https://identity.example.com",
				"OCI_CLIENT_ID":           "test-client-id",
				"OCI_CLUSTER_ID":          "ocid1.cluster.oc1.iad.test",
				"OCI_REGION":              "us-ashburn-1",
				"OCI_TOKEN_PATH":          "/nonexistent/path",
			},
			args:          []string{},
			wantErr:       true,
			wantErrSubstr: "failed to read SA token", // All required flags set, but token file missing
		},
		{
			name: "正常系: OCI_TOKEN_PATH 環境変数でトークンパスが設定される",
			envVars: map[string]string{
				"OCI_IDENTITY_DOMAIN_URL": "https://identity.example.com",
				"OCI_CLIENT_ID":           "test-client-id",
				"OCI_CLUSTER_ID":          "ocid1.cluster.oc1.iad.test",
				"OCI_REGION":              "us-ashburn-1",
				"OCI_TOKEN_PATH":          "/custom/token/path",
			},
			args:          []string{},
			wantErr:       true,
			wantErrSubstr: "/custom/token/path", // Error should reference the custom path
		},
		{
			name: "正常系: フラグが環境変数より優先される",
			envVars: map[string]string{
				"OCI_IDENTITY_DOMAIN_URL": "https://env-identity.example.com",
				"OCI_CLIENT_ID":           "env-client-id",
				"OCI_CLUSTER_ID":          "env-cluster-id",
				"OCI_REGION":              "env-region",
			},
			args:          []string{"--identity-domain-url=https://flag-identity.example.com", "--client-id=flag-client-id", "--cluster-id=flag-cluster-id", "--region=flag-region", "--token-path=/nonexistent"},
			wantErr:       true,
			wantErrSubstr: "failed to read SA token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			envLookup := func(key string) (string, bool) {
				v, ok := tt.envVars[key]
				return v, ok
			}

			_, err := newTestRootCmd(envLookup, tt.args)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.wantErrSubstr != "" && !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRootCommand_TokenFileReading(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		tokenContent  string
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:          "異常系: トークンファイルが空の場合にエラー",
			tokenContent:  "",
			wantErr:       true,
			wantErrSubstr: "token file is empty",
		},
		{
			name:          "異常系: 存在しないトークンファイルでエラー",
			tokenContent:  "", // Will use a nonexistent path instead.
			wantErr:       true,
			wantErrSubstr: "failed to open token file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var tokenPath string
			if tt.name == "異常系: 存在しないトークンファイルでエラー" {
				tokenPath = "/nonexistent/token/file"
			} else {
				tmpDir := t.TempDir()
				tokenPath = filepath.Join(tmpDir, "token")
				if err := os.WriteFile(tokenPath, []byte(tt.tokenContent), 0o600); err != nil {
					t.Fatalf("failed to write token file: %v", err)
				}
			}

			noEnv := func(string) (string, bool) { return "", false }
			args := []string{
				"--identity-domain-url=https://example.com",
				"--client-id=cid",
				"--cluster-id=clid",
				"--region=us-ashburn-1",
				"--token-path=" + tokenPath,
			}
			_, err := newTestRootCmd(noEnv, args)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
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

		// Set up a mock token exchange server.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request is a POST to /oauth2/v1/token.
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasSuffix(r.URL.Path, "/oauth2/v1/token") {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{"token": "test-upst-token-from-mock-server"}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, "failed to encode response", http.StatusInternalServerError)
			}
		}))
		t.Cleanup(srv.Close)

		// Create a temporary token file.
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "sa-token")
		if err := os.WriteFile(tokenFile, []byte("mock-sa-token-value"), 0o600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		noEnv := func(string) (string, bool) { return "", false }
		args := []string{
			"--identity-domain-url=" + srv.URL,
			"--client-id=test-client-id",
			"--cluster-id=ocid1.cluster.oc1.iad.test",
			"--region=us-ashburn-1",
			"--token-path=" + tokenFile,
			"--token-lifetime=4m",
			"--timeout=10s",
		}

		buf, err := newTestRootCmd(noEnv, args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the output is valid ExecCredential JSON.
		output := strings.TrimSpace(buf.String())
		if output == "" {
			t.Fatal("output is empty")
		}

		var cred execCredentialJSON
		if err := json.Unmarshal([]byte(output), &cred); err != nil {
			t.Fatalf("failed to parse ExecCredential JSON: %v\nraw output: %s", err, output)
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

		// Verify default values for optional flags.
		tokenPathFlag := rootCmd.Flags().Lookup("token-path")
		if tokenPathFlag == nil {
			t.Fatal("token-path flag not found")
		}
		if diff := cmp.Diff("/var/run/secrets/oci-wif/token", tokenPathFlag.DefValue); diff != "" {
			t.Errorf("token-path default mismatch (-want +got):\n%s", diff)
		}

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

func TestRootCommand_TokenExchangeError(t *testing.T) {
	t.Parallel()

	t.Run("異常系: トークン交換が失敗した場合にエラーが返される", func(t *testing.T) {
		t.Parallel()

		// Set up a mock server that always returns 401.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
		}))
		t.Cleanup(srv.Close)

		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "sa-token")
		if err := os.WriteFile(tokenFile, []byte("mock-sa-token"), 0o600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		noEnv := func(string) (string, bool) { return "", false }
		args := []string{
			"--identity-domain-url=" + srv.URL,
			"--client-id=test-client-id",
			"--cluster-id=ocid1.cluster.oc1.iad.test",
			"--region=us-ashburn-1",
			"--token-path=" + tokenFile,
		}
		_, err := newTestRootCmd(noEnv, args)

		if err == nil {
			t.Fatal("expected error but got nil")
		}
		if !strings.Contains(err.Error(), "token exchange failed") {
			t.Errorf("error %q does not contain %q", err.Error(), "token exchange failed")
		}
	})
}
