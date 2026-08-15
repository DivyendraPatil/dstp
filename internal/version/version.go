// Package version holds build-time identity injected via -ldflags.
package version

// These are set by goreleaser / make via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return "dstp " + Version + " (commit " + Commit + ", built " + Date + ")"
}
