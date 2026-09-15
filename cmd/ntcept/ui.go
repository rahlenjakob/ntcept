package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"

	"github.com/rahlenjakob/ntcept/internal/attach"
)

// uiCmd opens the inspector, which is served by the running session's control plane.
func uiCmd(args []string) int {
	s, err := attach.ResolveSession(sessionName)
	if err != nil {
		return die("%v", err)
	}
	url := "http://127.0.0.1:" + strconv.Itoa(s.ControlPort)
	fmt.Println(url)
	opener := "xdg-open"
	if runtime.GOOS == "darwin" {
		opener = "open"
	}
	if path, err := exec.LookPath(opener); err == nil {
		_ = exec.Command(path, url).Start()
	}
	return 0
}
