package main

import (
	"flag"
	"fmt"
	"runtime"

	"github.com/rahlenjakob/ntcept/internal/pftun"
)

// installCmd performs the one privileged step macOS needs, once per machine.
func installCmd(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	noSudoers := fs.Bool("no-sudoers", false,
		"skip the passwordless grant; sudo ntcept run will prompt each time")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if runtime.GOOS != "darwin" {
		fmt.Println("Nothing to install. On Linux the tunnel attach needs no setup: it uses a")
		fmt.Println("network namespace, which an unprivileged process can create for itself.")
		return 0
	}
	fmt.Print("ntcept install — one-time macOS setup\n\n")
	if err := pftun.Install(!*noSudoers); err != nil {
		return die("%v", err)
	}
	return 0
}

func uninstallCmd(args []string) int {
	if runtime.GOOS != "darwin" {
		fmt.Println("nothing was installed")
		return 0
	}
	if err := pftun.Uninstall(); err != nil {
		return die("%v", err)
	}
	return 0
}
