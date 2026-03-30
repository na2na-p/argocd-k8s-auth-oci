//go:build tools

// Package tools holds dependency imports to keep them in go.mod.
// These packages will be used in subsequent tasks (005-010).
package tools

import (
	_ "github.com/oracle/oci-go-sdk/v65/common"
	_ "k8s.io/client-go/kubernetes"
)
