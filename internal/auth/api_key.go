// Package auth は環境変数から OCI API キー認証用の設定を読み込む。
package auth

import (
	"errors"
	"fmt"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// OCI API キー認証で参照する環境変数名。
// mattn/oci-cluster-token との互換性を保つため変数名を踏襲する。
const (
	EnvKeyTenancy     = "OCI_TENANCY"
	EnvKeyUser        = "OCI_USER"
	EnvKeyRegion      = "OCI_REGION"
	EnvKeyFingerprint = "OCI_FINGERPRINT"
	EnvKeyKeyFile     = "OCI_KEY_FILE"
	EnvKeyPassphrase  = "OCI_PASSPHRASE"
)

// ErrRequiredEnvMissing は必須環境変数が未設定または空文字の場合に
// ConfigFromEnv が返すエラーを識別する sentinel。
// 呼び出し側は errors.Is でこの sentinel を判別し、ラップされたメッセージから
// どのキーが欠落しているかを取得する想定。
var ErrRequiredEnvMissing = errors.New("required env missing")

// ErrKeyFileRead は OCI API キー PEM ファイルの読み込み失敗を識別する sentinel。
// Config.Provider が os.ReadFile で wrap して返すので、呼び出し側は errors.Is で
// 「ファイル不存在 / 権限不足など PEM 入手段階の失敗」を区別できる。
var ErrKeyFileRead = errors.New("OCI API key file read failed")

// Config は OCI API キー認証に必要なパラメータを保持する。
type Config struct {
	Tenancy     string
	User        string
	Region      string
	Fingerprint string
	KeyFile     string
	// Passphrase はキー暗号化時のみ非 nil。未設定 / 空文字は absent 扱いとし
	// nil のままで OCI SDK 側にそのまま渡せるよう pointer 型にしている。
	Passphrase *string
}

// ConfigFromEnv は環境変数 lookup 関数経由で OCI API キー設定を読み出す。
// 必須: OCI_TENANCY, OCI_USER, OCI_REGION, OCI_FINGERPRINT, OCI_KEY_FILE。
// 任意: OCI_PASSPHRASE。
func ConfigFromEnv(lookup func(string) (string, bool)) (*Config, error) {
	cfg := &Config{}
	// 必須キーは内部ループでまとめて検証する。外部公開しないことで
	// env キーの追加・順序変更を package 内に閉じ込める。
	requiredEnvKeys := []struct {
		key  string
		dest *string
	}{
		{EnvKeyTenancy, &cfg.Tenancy},
		{EnvKeyUser, &cfg.User},
		{EnvKeyRegion, &cfg.Region},
		{EnvKeyFingerprint, &cfg.Fingerprint},
		{EnvKeyKeyFile, &cfg.KeyFile},
	}
	for _, b := range requiredEnvKeys {
		v, ok := lookup(b.key)
		if !ok || v == "" {
			return nil, fmt.Errorf("%s: %w", b.key, ErrRequiredEnvMissing)
		}
		*b.dest = v
	}
	if v, ok := lookup(EnvKeyPassphrase); ok && v != "" {
		cfg.Passphrase = &v
	}
	return cfg, nil
}

// Provider は OCI Go SDK の HTTP 署名で使う ConfigurationProvider を返す。
// OCI SDK の NewRawConfigurationProvider は第 5 引数に PEM "内容" 文字列を要求し、
// 内部で pem.Decode([]byte(privateKey)) を呼ぶため、ファイルパス文字列をそのまま渡すと
// "PEM data was not found in buffer" で失敗する。
// したがって本メソッドで KeyFile を読み込んで PEM 内容を SDK に渡す。
func (c *Config) Provider() (common.ConfigurationProvider, error) {
	pemBytes, err := os.ReadFile(c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrKeyFileRead, c.KeyFile, err)
	}
	return common.NewRawConfigurationProvider(
		c.Tenancy,
		c.User,
		c.Region,
		c.Fingerprint,
		string(pemBytes),
		c.Passphrase,
	), nil
}
