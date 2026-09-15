package main

import (
	"runtime"
	"strings"
	"testing"
)

func TestMechanismNamesSomethingConcrete(t *testing.T) {
	if m := Mechanism(); m == "" || !strings.Contains(m, "scoped to") {
		t.Fatalf("the mechanism line should say what is intercepted and how far it reaches: %q", m)
	}
}

// Publishing is the last behavioural difference between the platforms, so which one needs it is
// worth stating once and testing, rather than being implied by a build tag.
func TestNeedsPublishing(t *testing.T) {
	got := needsPublishing()
	want := runtime.GOOS == "linux"
	if got != want {
		t.Errorf("needsPublishing() on %s = %v, want %v — only the Linux namespace hides "+
			"the command's listening sockets", runtime.GOOS, got, want)
	}
}

// Loopback capture is the other one-sided difference: only macOS has to redirect it, because
// there the command shares the machine's network.
func TestNeedsLocalCapture(t *testing.T) {
	got := needsLocalCapture()
	want := runtime.GOOS == "darwin"
	if got != want {
		t.Errorf("needsLocalCapture() on %s = %v, want %v", runtime.GOOS, got, want)
	}
}

func TestPortListCollectsRepeatedFlags(t *testing.T) {
	var p portList
	for _, spec := range []string{"3000", "8080:3000"} {
		if err := p.Set(spec); err != nil {
			t.Fatal(err)
		}
	}
	maps, err := p.maps()
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) != 2 {
		t.Fatalf("expected two mappings, got %d", len(maps))
	}
	if maps[0].HostAddr != "127.0.0.1:3000" || maps[0].ChildPort != 3000 {
		t.Errorf("unexpected first mapping %+v", maps[0])
	}
	if maps[1].HostAddr != "127.0.0.1:8080" || maps[1].ChildPort != 3000 {
		t.Errorf("unexpected second mapping %+v", maps[1])
	}
}

func TestPortListRejectsNonsenseWithTheOffendingValue(t *testing.T) {
	var p portList
	_ = p.Set("3000")
	_ = p.Set("not-a-port")
	_, err := p.maps()
	if err == nil {
		t.Fatal("a bad --publish must be an error, not a silently skipped port")
	}
	if !strings.Contains(err.Error(), "not-a-port") {
		t.Fatalf("the error should name the value the user typed: %q", err)
	}
}
