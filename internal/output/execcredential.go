// Package output provides formatters for Kubernetes credential output.
package output

import (
	"encoding/json"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// CredentialFormatter formats a token and expiry into ExecCredential JSON.
type CredentialFormatter interface {
	Format(token string, expiry time.Time) ([]byte, error)
}

// execCredentialFormatter implements CredentialFormatter using the Kubernetes
// client-go ExecCredential type.
type execCredentialFormatter struct{}

// NewCredentialFormatter creates a new CredentialFormatter.
func NewCredentialFormatter() CredentialFormatter {
	return &execCredentialFormatter{}
}

// Format produces a JSON-encoded ExecCredential with the given token and expiry.
func (f *execCredentialFormatter) Format(token string, expiry time.Time) ([]byte, error) {
	t := metav1.NewTime(expiry)
	cred := &clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "client.authentication.k8s.io/v1beta1",
			Kind:       "ExecCredential",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			ExpirationTimestamp: &t,
			Token:               token,
		},
	}

	return json.Marshal(cred)
}
