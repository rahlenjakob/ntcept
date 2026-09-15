package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/pftun"
)

// cleanupCmd undoes anything a crashed run could have left behind. Normal exits already do this.
func cleanupCmd(args []string) int {
	for _, s := range attach.StopStale() {
		fmt.Printf("stopped session %s, still running as pid %d\n", s.Name, s.PID)
	}
	if runtime.GOOS == "darwin" {
		// Flushing a pf anchor needs root. Run as a normal user, the pfctl calls fail quietly
		// and nothing is actually removed, so say so rather than report a hollow success.
		if os.Geteuid() != 0 {
			fmt.Println("note: flushing leftover pf rules needs root — run `sudo ntcept cleanup`")
		}
		n, err := pftun.Cleanup()
		if err != nil {
			return die("%v", err)
		}
		fmt.Printf("pf anchor %s flushed (%d rule(s) removed)\n", pftun.Anchor, n)
		fmt.Println("utun devices are owned by the process and disappear with it")
	}
	fmt.Println("session state cleared")
	return 0
}
