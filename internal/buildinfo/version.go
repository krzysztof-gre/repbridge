// Package buildinfo identifies the application release, independent of dependencies.
package buildinfo

// Version is injected from the release tag by GoReleaser; source builds use dev.
var Version = "dev"
