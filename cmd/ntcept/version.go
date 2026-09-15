package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is stamped into release builds with the linker:
//
//	go build -ldflags "-X main.Version=v0.1.0" ./cmd/ntcept
//
// Left empty — as a plain `go build` leaves it — ntcept reports the commit the binary was built
// from, which the Go toolchain embeds automatically. So there is no version number to keep in
// sync in source: an untagged build identifies itself by its SHA.
var Version = ""

// versionString is the human-readable build identity: an explicit release version if one was
// stamped in, otherwise "<short-sha>[-dirty] (goX.Y)".
func versionString() string {
	if Version != "" {
		return Version
	}
	rev, dirty := "unknown", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return fmt.Sprintf("%s%s (%s)", rev, dirty, runtime.Version())
}

func versionCmd(args []string) int {
	fmt.Println("ntcept " + versionString())
	return 0
}
