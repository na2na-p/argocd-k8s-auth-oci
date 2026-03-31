package output_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/output"
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

func TestExecCredentialFormatter_Format(t *testing.T) {
	t.Parallel()

	fixedTime := time.Date(2025, 6, 15, 12, 30, 0, 0, time.UTC)

	tests := []struct {
		name                    string
		token                   string
		expiry                  time.Time
		wantAPIVersion          string
		wantKind                string
		wantToken               string
		wantExpirationTimestamp string
	}{
		{
			name:                    "正常系: 全フィールドが正しい ExecCredential JSON が出力される",
			token:                   "my-bearer-token",
			expiry:                  fixedTime,
			wantAPIVersion:          "client.authentication.k8s.io/v1beta1",
			wantKind:                "ExecCredential",
			wantToken:               "my-bearer-token",
			wantExpirationTimestamp: "2025-06-15T12:30:00Z",
		},
		{
			name:                    "正常系: expirationTimestamp が RFC 3339 形式である",
			token:                   "token-rfc3339",
			expiry:                  time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
			wantAPIVersion:          "client.authentication.k8s.io/v1beta1",
			wantKind:                "ExecCredential",
			wantToken:               "token-rfc3339",
			wantExpirationTimestamp: "2024-01-02T03:04:05Z",
		},
		{
			name:                    "正常系: 空トークンでもエラーにならない",
			token:                   "",
			expiry:                  fixedTime,
			wantAPIVersion:          "client.authentication.k8s.io/v1beta1",
			wantKind:                "ExecCredential",
			wantToken:               "",
			wantExpirationTimestamp: "2025-06-15T12:30:00Z",
		},
		{
			// metav1.Time marshals zero time as an empty string per Kubernetes convention.
			name:                    "正常系: ゼロ時刻でもエラーにならない",
			token:                   "zero-time-token",
			expiry:                  time.Time{},
			wantAPIVersion:          "client.authentication.k8s.io/v1beta1",
			wantKind:                "ExecCredential",
			wantToken:               "zero-time-token",
			wantExpirationTimestamp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			formatter := output.NewCredentialFormatter()

			got, err := formatter.Format(tt.token, tt.expiry)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var parsed execCredentialJSON
			if err := json.Unmarshal(got, &parsed); err != nil {
				t.Fatalf("failed to unmarshal JSON output: %v", err)
			}

			if diff := cmp.Diff(tt.wantAPIVersion, parsed.APIVersion); diff != "" {
				t.Errorf("apiVersion mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantKind, parsed.Kind); diff != "" {
				t.Errorf("kind mismatch (-want +got):\n%s", diff)
			}
			if parsed.Status == nil {
				t.Fatal("status is nil")
			}
			if diff := cmp.Diff(tt.wantToken, parsed.Status.Token); diff != "" {
				t.Errorf("token mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantExpirationTimestamp, parsed.Status.ExpirationTimestamp); diff != "" {
				t.Errorf("expirationTimestamp mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExecCredentialFormatter_Format_ValidJSON(t *testing.T) {
	t.Parallel()

	t.Run("正常系: 出力が有効な JSON である", func(t *testing.T) {
		t.Parallel()

		formatter := output.NewCredentialFormatter()
		got, err := formatter.Format("test-token", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !json.Valid(got) {
			t.Errorf("output is not valid JSON: %s", string(got))
		}
	})
}
