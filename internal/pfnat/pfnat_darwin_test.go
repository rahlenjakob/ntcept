//go:build darwin

package pfnat

import (
	"net"
	"testing"
)

// The struct layout is reconstructed from a kernel-private header, so a wrong offset returns a
// plausible-but-wrong answer rather than an error. Plausible is the guard that rejects answers
// that cannot be right; if it ever loosens, a bad layout would be trusted in silence.
func TestPlausibleRejectsWhatCannotBeRight(t *testing.T) {
	good := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5432}
	if err := Plausible(good, 40000); err != nil {
		t.Fatalf("a loopback address on a real port should pass: %v", err)
	}
	for _, tc := range []struct {
		name     string
		got      *net.TCPAddr
		listener int
	}{
		{"nil", nil, 40000},
		{"not loopback", &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5432}, 40000},
		{"port zero", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, 40000},
		{"equals listener", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}, 40000},
	} {
		if err := Plausible(tc.got, tc.listener); err == nil {
			t.Errorf("%s: expected rejection, got none", tc.name)
		}
	}
}
