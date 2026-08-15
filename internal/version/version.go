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
	v, c, d := resolve()
	return "dstp " + v + " (commit " + c + ", built " + d + ")"
}

func resolve() (v, c, d string) {
	v, c, d = Version, Commit, Date
	needModule := v == "dev" || v == ""
	needVCS := c == "none" || c == "" || d == "unknown" || d == ""
	if !needModule && !needVCS {
		return strings.TrimSpace(v), c, d
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return strings.TrimSpace(v), c, d
	}
	if needModule && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		v = bi.Main.Version
	}
	if needVCS {
		dirty := false
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if (c == "none" || c == "") && s.Value != "" {
					c = s.Value
					if len(c) > 7 {
						c = c[:7]
					}
				}
			case "vcs.time":
				if (d == "unknown" || d == "") && s.Value != "" {
					d = s.Value
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = true
				}
			}
		}
		if dirty && c != "" && c != "none" && !strings.HasSuffix(c, "-dirty") {
			c += "-dirty"
		}
	}
	return strings.TrimSpace(v), c, d
}
