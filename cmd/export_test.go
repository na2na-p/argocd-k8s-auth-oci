package cmd

import "github.com/spf13/cobra"

// NewRootCmdForTest creates a new root command for testing.
// It exposes newRootCmd with the given environment lookup function.
func NewRootCmdForTest(envLookup func(string) (string, bool)) *cobra.Command {
	cmd, _ := newRootCmd(envLookup)
	return cmd
}

// MaskTokenForTest exposes maskToken for testing.
func MaskTokenForTest(token string) string {
	return maskToken(token)
}
