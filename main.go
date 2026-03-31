// argocd-k8s-auth-oci is an OCI (Oracle Cloud Infrastructure) authentication plugin for ArgoCD.
package main

import (
	"os"

	"github.com/na2na-p/argocd-k8s-auth-oci/cmd"
)

// version and commit are set via ldflags at build time.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
