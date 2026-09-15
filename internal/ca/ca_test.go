package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTheCAIsCreatedOnceAndReused(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Minting a new root on every run would invalidate whatever the user already trusts, and
	// break every certificate already issued to a long-lived process.
	if !first.Cert.Equal(second.Cert) {
		t.Fatal("the CA was regenerated rather than loaded")
	}
	if first.Cert.Subject.CommonName != CommonName {
		t.Fatalf("unexpected subject %q", first.Cert.Subject.CommonName)
	}
	if !first.Cert.IsCA || !first.Cert.BasicConstraintsValid {
		t.Fatal("the root must be a usable CA")
	}
}

// The private key can mint a certificate for any name on the internet. It must not be readable
// by anyone else on the machine.
func TestThePrivateKeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("ca.key is mode %o; anyone on this machine could mint certificates", perm)
	}
	// The certificate is public by design — runtimes have to be able to read it.
	certInfo, err := os.Stat(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if certInfo.Mode().Perm()&0o004 == 0 {
		t.Fatal("ca.pem must be readable, or a child process cannot trust it")
	}
}

func TestHomeHonoursNTCEPTHOME(t *testing.T) {
	t.Setenv("NTCEPT_HOME", "/tmp/ntcept-test-home")
	if got := Home(); got != "/tmp/ntcept-test-home" {
		t.Fatalf("Home() = %q", got)
	}
}

// A leaf ntcept mints has to verify against ntcept's own root, or every intercepted connection
// fails closed and the app sees an error it would never have seen in production.
func TestMintedLeavesChainToTheRoot(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(a.PEM) {
		t.Fatal("could not load the generated root")
	}

	for _, host := range []string{"api.stripe.com", "127.0.0.1", "::1"} {
		leaf, err := a.LeafFor(host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if leaf.Leaf == nil {
			t.Fatalf("%s: the parsed leaf should be attached for the handshake path", host)
		}
		opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if _, err := leaf.Leaf.Verify(opts); err != nil {
			t.Fatalf("%s: a minted leaf does not chain to ntcept's own root: %v", host, err)
		}
		if err := leaf.Leaf.VerifyHostname(host); err != nil {
			t.Fatalf("%s: the leaf does not cover the name it was minted for: %v", host, err)
		}
		if leaf.Leaf.NotAfter.Before(time.Now()) {
			t.Fatalf("%s: the leaf is already expired", host)
		}
	}
}

// An IP literal has to land in the IP SANs rather than the DNS names, which is the difference
// between an intercepted direct-to-address connection working and failing.
func TestAnAddressGoesInTheIPSANs(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("expected one IP SAN, got ips=%v dns=%v", leaf.Leaf.IPAddresses, leaf.Leaf.DNSNames)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Fatalf("an address is not a DNS name: %v", leaf.Leaf.DNSNames)
	}
}

func TestLeafForSANsCoversNameAndAddressTogether(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafForSANs([]string{"probe.ntcept.invalid"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.Leaf.VerifyHostname("probe.ntcept.invalid"); err != nil {
		t.Fatalf("the hostname is not covered: %v", err)
	}
	if err := leaf.Leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("the address is not covered: %v", err)
	}
}

// Leaves are minted on every handshake, so the cache is on the hot path. Concurrent handshakes
// to the same host must not race, and must not mint two different certificates.
func TestLeafCacheIsSharedAndSafeUnderConcurrency(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const n = 32
	out := make([]*tls.Certificate, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			leaf, err := a.LeafFor("api.example.com")
			if err != nil {
				t.Error(err)
				return
			}
			out[i] = leaf
		}(i)
	}
	wg.Wait()
	for i, leaf := range out {
		if leaf == nil {
			t.Fatalf("goroutine %d got no certificate", i)
		}
		if leaf != out[0] {
			t.Fatal("the same host minted more than one certificate; the cache is not shared")
		}
	}
}

// SNI is how ntcept knows which certificate to present. A client dialling an address sends none,
// and the fallback is what keeps that working.
func TestServerConfigUsesSNIThenFallback(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.ServerConfig("203.0.113.9", []string{"h2", "http/1.1"})
	if strings.Join(cfg.NextProtos, ",") != "h2,http/1.1" {
		t.Fatalf("ALPN was not offered: %v", cfg.NextProtos)
	}

	withSNI, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.stripe.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := withSNI.Leaf.VerifyHostname("api.stripe.com"); err != nil {
		t.Fatalf("SNI was ignored: %v", err)
	}

	noSNI, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if err := noSNI.Leaf.VerifyHostname("203.0.113.9"); err != nil {
		t.Fatalf("the fallback was not used for a client that sent no SNI: %v", err)
	}
}

func TestCorruptedCAFilesAreReportedClearly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreate(dir)
	if err == nil {
		t.Fatal("a corrupted CA should be an error, not a silent regeneration")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Fatalf("the error should name the directory to fix, got %q", err)
	}
}
