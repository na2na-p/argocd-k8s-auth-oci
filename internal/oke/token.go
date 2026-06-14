// Package oke は OKE (Oracle Kubernetes Engine) の bearer token を生成する。
package oke

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// TokenGenerator は OCI ConfigurationProvider で cluster_request URL を
// HTTP Signature 署名し、OKE が受理する bearer token を生成する。
type TokenGenerator interface {
	Generate(ctx context.Context, provider common.ConfigurationProvider) (token string, expiry time.Time, err error)
}

// NewTokenGenerator は TokenGenerator を生成する。
// tokenLifetime は ExecCredential の expirationTimestamp に反映される。
func NewTokenGenerator(region string, clusterID string, tokenLifetime time.Duration) TokenGenerator {
	return &ociTokenGenerator{
		region:        region,
		clusterID:     clusterID,
		tokenLifetime: tokenLifetime,
	}
}

type ociTokenGenerator struct {
	region        string
	clusterID     string
	tokenLifetime time.Duration
}

// Generate は OKE cluster_request エンドポイントへの GET を OCI HTTP Signature
// で署名し、署名後 URL (authorization と date を query parameter として持つ) を
// 標準 base64 でエンコードして返す。
func (g *ociTokenGenerator) Generate(ctx context.Context, provider common.ConfigurationProvider) (string, time.Time, error) {
	if provider == nil {
		return "", time.Time{}, fmt.Errorf("provider must not be nil")
	}

	endpoint := fmt.Sprintf("https://containerengine.%s.oraclecloud.com/cluster_request/%s", g.region, g.clusterID)

	// context を request に紐付けて cancel / deadline を伝播させる。
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	// OCI HTTP Signature の仕様上、Date ヘッダを署名前にセットする必要があるため。
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	signer := common.DefaultRequestSigner(provider)
	if err := signer.Sign(req); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign request: %w", err)
	}

	q := req.URL.Query()
	q.Set("authorization", req.Header.Get("Authorization"))
	q.Set("date", req.Header.Get("Date"))
	req.URL.RawQuery = q.Encode()

	token := base64.StdEncoding.EncodeToString([]byte(req.URL.String()))
	expiry := time.Now().UTC().Add(g.tokenLifetime)

	return token, expiry, nil
}
