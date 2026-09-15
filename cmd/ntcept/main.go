// ntcept intercepts, inspects and manages the network traffic of an application, without
// changing the application or the machine it runs on.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/netns"
	"github.com/rahlenjakob/ntcept/internal/pftun"
)

type command struct {
	name    string
	usage   string
	summary string
	run     func(args []string) int
}

var commands []command

func main() {
	// Privileged re-entry points. Neither is ever invoked by a user.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case netns.HelperArg:
			os.Exit(netns.RunHelper(os.Args[2:]))
		case pftun.HelperArg:
			os.Exit(pftun.RunHelper(os.Args[2:]))
		}
	}
	register()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		usage()
		return
	}
	for _, c := range commands {
		if c.name == name {
			os.Exit(c.run(os.Args[2:]))
		}
	}
	fmt.Fprintf(os.Stderr, "ntcept: unknown command %q\n\n", name)
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintln(os.Stderr, "ntcept — intercept, inspect and manage an application's network traffic")
	fmt.Fprintln(os.Stderr, "\nUsage:\n  ntcept <command> [flags]")
	fmt.Fprintln(os.Stderr, "\nCommands:")
	sorted := append([]command(nil), commands...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })
	for _, c := range sorted {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(os.Stderr, "\nStart here:\n  ntcept run -- npm run dev")
	fmt.Fprintln(os.Stderr, "  ntcept ls")
	fmt.Fprintln(os.Stderr, "\nEvery command takes --json.")
}

func die(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "ntcept: "+strings.TrimSuffix(format, "\n")+"\n", a...)
	return 1
}

// takePositionals pulls up to n leading non-flag arguments out before flag parsing.
//
// Go's flag package stops at the first positional, so `ntcept show 12 --full` would otherwise
// treat --full as another positional and reject the command. Both orders work this way.
func takePositionals(args []string, n int) (found []string, rest []string) {
	rest = args
	for len(found) < n && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		found = append(found, rest[0])
		rest = rest[1:]
	}
	return found, rest
}
