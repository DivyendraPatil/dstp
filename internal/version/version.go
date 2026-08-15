// Package version holds build-time identity.
package version

import (
	"runtime/debug"
	"strings"
)

// These can be set by goreleaser / make via -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	v, c, d := Version, Commit, Date
	if v == "dev" || v == "" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
		}
	}
	if c == "none" || c == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					c = s.Value
					if len(c) > 7 {
						c = c[:7]
					}
				}
				if s.Key == "vcs.time" && s.Value != "" {
					d = s.Value
				}
			}
		}
	}
	v = strings.TrimSpace(v)
	return "dstp " + v + " (commit " + c + ", built " + d + ")"
}
