// Package cmd provides CLI command definitions.
package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/na2na-p/argocd-k8s-auth-oci/internal/auth"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/oke"
	"github.com/na2na-p/argocd-k8s-auth-oci/internal/output"
)

// buildVersion and buildCommit are set via SetVersionInfo from main.go.
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

// SetVersionInfo sets the version and commit information for the CLI.
// This is called from main.go with values populated via ldflags.
func SetVersionInfo(version, commit string) {
	buildVersion = version
	buildCommit = commit
}

// rootOptions holds the parsed flag values for the root command.
type rootOptions struct {
	identityDomainURL string
	clientID          string
	clusterID         string
	region            string
	tokenPath         string
	tokenLifetime     time.Duration
	timeout           time.Duration
	debug             bool
	showVersion       bool
}

// newRootCmd creates a new root command with all flags configured.
// The envLookup function is used to read environment variables (os.LookupEnv in production).
func newRootCmd(envLookup func(string) (string, bool)) (*cobra.Command, *rootOptions) {
	opts := &rootOptions{}

	cmd := &cobra.Command{
		Use:          "argocd-k8s-auth-oci",
		Short:        "OCI authentication plugin for ArgoCD",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRoot(cmd, opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.identityDomainURL, "identity-domain-url", "", "OCI Identity Domain URL (env: OCI_IDENTITY_DOMAIN_URL)")
	flags.StringVar(&opts.clientID, "client-id", "", "OCI client ID (env: OCI_CLIENT_ID)")
	flags.StringVar(&opts.clusterID, "cluster-id", "", "OKE cluster ID (env: OCI_CLUSTER_ID)")
	flags.StringVar(&opts.region, "region", "", "OCI region (env: OCI_REGION)")
	flags.StringVar(&opts.tokenPath, "token-path", "/var/run/secrets/oci-wif/token", "path to SA token file, use - for stdin (env: OCI_TOKEN_PATH)")
	flags.DurationVar(&opts.tokenLifetime, "token-lifetime", 4*time.Minute, "OKE token lifetime")
	flags.DurationVar(&opts.timeout, "timeout", 10*time.Second, "HTTP client timeout")
	flags.BoolVar(&opts.debug, "debug", false, "enable debug output to stderr")
	flags.BoolVarP(&opts.showVersion, "version", "v", false, "show version information and exit")

	bindEnvDefaults(cmd, envLookup)

	return cmd, opts
}

// bindEnvDefaults reads environment variables and sets flag defaults.
func bindEnvDefaults(cmd *cobra.Command, lookup func(string) (string, bool)) {
	envBindings := []struct {
		envKey   string
		flagName string
	}{
		{"OCI_IDENTITY_DOMAIN_URL", "identity-domain-url"},
		{"OCI_CLIENT_ID", "client-id"},
		{"OCI_CLUSTER_ID", "cluster-id"},
		{"OCI_REGION", "region"},
		{"OCI_TOKEN_PATH", "token-path"},
	}

	for _, b := range envBindings {
		if v, ok := lookup(b.envKey); ok {
			if err := cmd.Flags().Set(b.flagName, v); err != nil {
				continue
			}
		}
	}
}

// Execute runs the root command.
func Execute() error {
	cmd, _ := newRootCmd(os.LookupEnv)
	return cmd.Execute()
}

// debugLogFunc returns a logging function that writes to stderr when debug is enabled.
func debugLogFunc(enabled bool) func(string, ...any) {
	return func(format string, args ...any) {
		if enabled {
			fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
		}
	}
}

// maskToken returns a masked version of a token for debug logging.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// runRoot is the main execution function for the root command.
func runRoot(cmd *cobra.Command, opts *rootOptions) error {
	if opts.showVersion {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "argocd-k8s-auth-oci version %s (commit: %s)\n", buildVersion, buildCommit)
		return err
	}

	// Validate required flags.
	if opts.identityDomainURL == "" {
		return fmt.Errorf("--identity-domain-url is required (or set OCI_IDENTITY_DOMAIN_URL)")
	}
	if opts.clientID == "" {
		return fmt.Errorf("--client-id is required (or set OCI_CLIENT_ID)")
	}
	if opts.clusterID == "" {
		return fmt.Errorf("--cluster-id is required (or set OCI_CLUSTER_ID)")
	}
	if opts.region == "" {
		return fmt.Errorf("--region is required (or set OCI_REGION)")
	}

	logDebug := debugLogFunc(opts.debug)

	// Step 1: Read SA token.
	logDebug("Reading SA token from %s", opts.tokenPath)
	saToken, err := readToken(opts.tokenPath)
	if err != nil {
		return fmt.Errorf("failed to read SA token: %w", err)
	}
	logDebug("SA token read successfully (%s)", maskToken(saToken))

	// Step 2: Create key generator.
	logDebug("Creating ephemeral key generator")
	keyGen := auth.NewKeyGenerator(nil)

	// Step 3: Create token exchanger with timeout-configured HTTP client.
	logDebug("Creating token exchanger for %s", opts.identityDomainURL)
	httpClient := &http.Client{Timeout: opts.timeout}
	exchanger := auth.NewTokenExchanger(opts.identityDomainURL, opts.clientID, keyGen, httpClient)

	// Step 4: Exchange SA token for UPST.
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	logDebug("Exchanging SA token for UPST")
	result, err := exchanger.Exchange(ctx, saToken)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}
	logDebug("UPST token obtained (%s)", maskToken(result.UPSTToken))

	// Step 5: Create OKE token generator.
	logDebug("Creating OKE token generator for region=%s cluster=%s lifetime=%s", opts.region, opts.clusterID, opts.tokenLifetime)
	okeGen := oke.NewTokenGenerator(opts.region, opts.clusterID, opts.tokenLifetime)

	// Step 6: Generate OKE token.
	logDebug("Generating OKE token")
	token, expiry, err := okeGen.Generate(ctx, result.UPSTToken, result.PrivateKey)
	if err != nil {
		return fmt.Errorf("OKE token generation failed: %w", err)
	}
	logDebug("OKE token generated, expires at %s", expiry.Format(time.RFC3339))

	// Step 7: Format as ExecCredential JSON.
	logDebug("Formatting ExecCredential output")
	formatter := output.NewCredentialFormatter()
	credJSON, err := formatter.Format(token, expiry)
	if err != nil {
		return fmt.Errorf("failed to format ExecCredential: %w", err)
	}

	// Step 8: Write to stdout.
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(credJSON))
	return err
}

// readToken reads the SA token from the specified path.
// If path is "-", it reads from stdin.
func readToken(path string) (string, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("failed to open token file %s: %w", path, err)
		}
		defer func() { _ = f.Close() }()
		reader = f
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}

	token := string(data)
	if token == "" {
		return "", fmt.Errorf("token file is empty")
	}

	return token, nil
}
