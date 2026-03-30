// Package cmd provides CLI command definitions.
package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd is the root command definition.
var rootCmd = &cobra.Command{
	Use:   "argocd-k8s-auth-oci",
	Short: "OCI authentication plugin for ArgoCD",
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
