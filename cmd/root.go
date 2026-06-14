// Package cmd は CLI コマンドを定義する。
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/na2na-p/argocd-k8s-auth-oci/internal/auth"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/oke"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/output"
)

// buildVersion と buildCommit は main.go の SetVersionInfo 経由で設定される。
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

// SetVersionInfo は CLI のバージョン / コミット情報を設定する。
// main.go から ldflags 経由で埋め込まれた値で呼び出される。
func SetVersionInfo(version, commit string) {
	buildVersion = version
	buildCommit = commit
}

// rootOptions は root コマンドのフラグ値を保持する。
// 認証情報 (OCI_TENANCY / OCI_USER / OCI_FINGERPRINT / OCI_KEY_FILE / OCI_PASSPHRASE) は
// auth.ConfigFromEnv が環境変数から直接読み出すため本構造体には含めない。
type rootOptions struct {
	clusterID     string
	region        string
	tokenLifetime time.Duration
	timeout       time.Duration
	debug         bool
	showVersion   bool
}

// newRootCmd は root コマンドを構築する。
// envLookup は環境変数読み出しを抽象化する関数 (本番では os.LookupEnv) で、
// テスト時に環境変数を注入するためのフックとなる。
func newRootCmd(envLookup func(string) (string, bool)) (*cobra.Command, *rootOptions) {
	opts := &rootOptions{}

	cmd := &cobra.Command{
		Use:          "argocd-k8s-auth-oci",
		Short:        "OCI authentication plugin for ArgoCD",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRoot(cmd, opts, envLookup)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.clusterID, "cluster-id", "", "OKE cluster ID (env: OCI_CLUSTER_ID)")
	flags.StringVar(&opts.region, "region", "", "OCI region (env: OCI_REGION)")
	flags.DurationVar(&opts.tokenLifetime, "token-lifetime", 4*time.Minute, "OKE token lifetime")
	flags.DurationVar(&opts.timeout, "timeout", 10*time.Second, "context timeout for OKE token generation")
	flags.BoolVar(&opts.debug, "debug", false, "enable debug output to stderr")
	flags.BoolVarP(&opts.showVersion, "version", "v", false, "show version information and exit")

	bindEnvDefaults(cmd, envLookup)

	return cmd, opts
}

// bindEnvDefaults は cluster-id / region のフラグデフォルトを環境変数から設定する。
// 認証情報の環境変数は auth.ConfigFromEnv が直接読むため本関数では扱わない。
func bindEnvDefaults(cmd *cobra.Command, lookup func(string) (string, bool)) {
	envBindings := []struct {
		envKey   string
		flagName string
	}{
		{"OCI_CLUSTER_ID", "cluster-id"},
		{"OCI_REGION", "region"},
	}

	for _, b := range envBindings {
		if v, ok := lookup(b.envKey); ok {
			if err := cmd.Flags().Set(b.flagName, v); err != nil {
				continue
			}
		}
	}
}

// Execute は root コマンドを実行する。
func Execute() error {
	cmd, _ := newRootCmd(os.LookupEnv)
	return cmd.Execute()
}

// debugLogFunc は debug フラグが有効な場合に stderr へ書き出すロガーを返す。
func debugLogFunc(enabled bool) func(string, ...any) {
	return func(format string, args ...any) {
		if enabled {
			fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
		}
	}
}

// maskToken は debug log 用に機微値の前後 4 文字以外をマスクする。
// API キー認証では fingerprint / user OCID 等を debug log に流す際の安全装置として利用する。
func maskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// runRoot は root コマンドの本処理。
//  1. version 表示
//  2. 必須フラグ検証
//  3. auth.ConfigFromEnv で認証設定を構築
//  4. cfg.Provider() で OCI SDK の ConfigurationProvider を取得
//  5. oke.NewTokenGenerator で OKE token を生成
//  6. output.NewCredentialFormatter で ExecCredential JSON 化して stdout に出力
func runRoot(cmd *cobra.Command, opts *rootOptions, envLookup func(string) (string, bool)) error {
	if opts.showVersion {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "argocd-k8s-auth-oci version %s (commit: %s)\n", buildVersion, buildCommit)
		return err
	}

	// 必須フラグ検証。
	if opts.clusterID == "" {
		return errors.New("--cluster-id is required (or set OCI_CLUSTER_ID)")
	}
	if opts.region == "" {
		return errors.New("--region is required (or set OCI_REGION)")
	}

	logDebug := debugLogFunc(opts.debug)

	// Step 1: 環境変数から OCI API キー認証設定を読み込む。
	logDebug("Loading OCI API key configuration from environment")
	cfg, err := auth.ConfigFromEnv(envLookup)
	if err != nil {
		// 必須環境変数の欠落は configuration error として分類して伝える。
		if errors.Is(err, auth.ErrRequiredEnvMissing) {
			return fmt.Errorf("OCI authentication configuration error: %w", err)
		}
		return fmt.Errorf("failed to load OCI authentication configuration: %w", err)
	}
	logDebug("OCI config loaded: tenancy=%s user=%s region=%s fingerprint=%s",
		maskToken(cfg.Tenancy), maskToken(cfg.User), cfg.Region, maskToken(cfg.Fingerprint))

	// Step 2: PEM ファイルを読み込んで OCI SDK の ConfigurationProvider を構築する。
	logDebug("Building OCI ConfigurationProvider from key file %s", cfg.KeyFile)
	provider, err := cfg.Provider()
	if err != nil {
		// PEM ファイル読み込み失敗は configuration error と区別して伝える。
		if errors.Is(err, auth.ErrKeyFileRead) {
			return fmt.Errorf("OCI key file error: %w", err)
		}
		return fmt.Errorf("failed to build OCI ConfigurationProvider: %w", err)
	}

	// Step 3: タイムアウト付き context で OKE token を生成する。
	parentCtx := cmd.Context()
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, opts.timeout)
	defer cancel()

	logDebug("Generating OKE token: region=%s cluster=%s lifetime=%s", opts.region, opts.clusterID, opts.tokenLifetime)
	okeGen := oke.NewTokenGenerator(opts.region, opts.clusterID, opts.tokenLifetime)
	token, expiry, err := okeGen.Generate(ctx, provider)
	if err != nil {
		return fmt.Errorf("OKE token generation error: %w", err)
	}
	logDebug("OKE token generated, expires at %s", expiry.Format(time.RFC3339))

	// Step 4: ExecCredential JSON に整形して stdout に出力する。
	logDebug("Formatting ExecCredential output")
	formatter := output.NewCredentialFormatter()
	credJSON, err := formatter.Format(token, expiry)
	if err != nil {
		return fmt.Errorf("failed to format ExecCredential: %w", err)
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(credJSON))
	return err
}
