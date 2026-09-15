//go:build darwin

package pftun

import (
	"strings"
	"testing"
)

// F1: the lock path must not follow $TMPDIR. launchd sets $TMPDIR per-user and sudo does not
// preserve it, so if the path tracked $TMPDIR the root helper and the user's ntcept would look in
// different directories and never see each other's locks — which is exactly the bug that let a
// crashed session's pf anchor leak. This pins the fix: the path is derived from the user's home,
// looked up by uid, and is stable whatever $TMPDIR says.
func TestLockPathIgnoresTMPDIR(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp/bogus-audit-tmpdir/")
	p := namedLockPath("loopback")
	if strings.Contains(p, "bogus-audit-tmpdir") {
		t.Fatalf("lock path follows $TMPDIR (%s); helper and user would diverge under sudo", p)
	}
}

// S1: an intake file without a token is from a session before tokens existed. A handoff cannot be
// authenticated without one, so such a file must be refused rather than treated as authorising an
// unauthenticated handoff.
func TestParseIntakeRequiresAToken(t *testing.T) {
	if _, _, _, ok := parseIntake([]byte("4242 55000\n")); ok {
		t.Fatal("a two-field intake file (no token) must be rejected")
	}
	pid, port, token, ok := parseIntake([]byte("4242 55000 9187364523\n"))
	if !ok || pid != 4242 || port != 55000 || token != 9187364523 {
		t.Fatalf("well-formed intake did not round-trip: %d %d %d %v", pid, port, token, ok)
	}
}

func TestParseIntakeRejectsJunk(t *testing.T) {
	for _, in := range []string{"", "notanumber x y", "4242 0 5", "4242 99999 5", "4242 55000 notoken"} {
		if _, _, _, ok := parseIntake([]byte(in)); ok {
			t.Errorf("parseIntake(%q) should have been rejected", in)
		}
	}
}

// S1: the handoff target may only be loopback. The intake is reachable by any local process, and
// the host field is attacker-influenced, so refusing anything but loopback stops the intake being
// turned into a dialer for arbitrary hosts.
func TestOnlyLoopbackHandoffTargets(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
		if !isLoopbackHost(h) {
			t.Errorf("%s is loopback and should be accepted", h)
		}
	}
	for _, h := range []string{"10.0.0.1", "192.168.1.5", "example.com", "0.0.0.0", ""} {
		if isLoopbackHost(h) {
			t.Errorf("%s is not loopback and must be refused", h)
		}
	}
}

// A token is meant to be unguessable; two sessions must not draw the same one.
func TestHandoffTokensDiffer(t *testing.T) {
	a, b := handoffToken(), handoffToken()
	if a == b || a == 0 || b == 0 {
		t.Fatalf("tokens should be distinct and non-zero: %d %d", a, b)
	}
	if a < 0 || b < 0 {
		t.Fatalf("tokens must be non-negative to render cleanly: %d %d", a, b)
	}
}
