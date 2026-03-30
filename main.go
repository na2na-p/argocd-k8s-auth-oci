// argocd-k8s-auth-oci is an OCI (Oracle Cloud Infrastructure) authentication plugin for ArgoCD.
package main

import (
	"os"

	"github.com/na2na-p/argocd-k8s-auth-oci/cmd"
)

// version and commit are set via ldflags at build time.
//
//nolint:unused // These variables are populated via -ldflags at build time and will be used once the version command is implemented.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
