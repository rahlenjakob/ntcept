package main

import "github.com/rahlenjakob/ntcept/internal/capture"

func register() {
	commands = []command{
		{"run", "ntcept run [flags] -- <command>", "launch a command with its traffic intercepted", runCmd},
		{"ls", "ntcept ls [filters]", "list captured flows", lsCmd},
		{"show", "ntcept show <id>", "show one flow in full", showCmd},
		{"follow", "ntcept follow [filters]", "tail flows as they complete", followCmd},
		{"wait", "ntcept wait [filters]", "block until a matching flow completes", waitCmd},
		{"diff", "ntcept diff <a> <b>", "compare two flows", diffCmd},
		{"repeat", "ntcept repeat <id>", "re-send a captured request through the proxy", repeatCmd},
		{"curl", "ntcept curl <id>", "print an equivalent curl command", curlCmd},
		{"intercept", "ntcept intercept on|off", "hold traffic for a verdict before it is sent", interceptCmd},
		{"queue", "ntcept queue", "what is currently held, waiting on you", queueCmd},
		{"forward", "ntcept forward <held-id>", "send a held exchange on unchanged", verdictCmd(capture.ActionForward)},
		{"drop", "ntcept drop <held-id>", "kill a held exchange, as the network would", verdictCmd(capture.ActionDrop)},
		{"edit", "ntcept edit <held-id>", "modify a held exchange, then send it on", verdictCmd(capture.ActionEdit)},
		{"respond", "ntcept respond <held-id>", "answer a held request locally, never sending it", verdictCmd(capture.ActionRespond)},
		{"ui", "ntcept ui", "open the inspector in a browser", uiCmd},
		{"status", "ntcept status", "what the running session is doing", statusCmd},
		{"sessions", "ntcept sessions", "list the ntcept sessions running now", sessionsCmd},
		{"clear", "ntcept clear", "discard the capture buffer", clearCmd},
		{"ca", "ntcept ca", "print the CA path and how to trust it", caCmd},
		{"cleanup", "ntcept cleanup", "undo anything a crashed run left behind", cleanupCmd},
		{"doctor", "ntcept doctor", "check what this machine can actually intercept", doctorCmd},
		{"version", "ntcept version", "print the build version (commit sha)", versionCmd},
		{"install", "sudo ntcept install", "one-time macOS setup, so `run` never needs a password", installCmd},
		{"uninstall", "sudo ntcept uninstall", "reverse the one-time setup", uninstallCmd},
	}
}
