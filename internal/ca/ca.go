// Package ca manages the local certificate authority ntcept uses to terminate TLS.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const CommonName = "ntcept local CA"

// Home is where the CA, rules and any recorded fixtures live.
func Home() string {
	if v := os.Getenv("NTCEPT_HOME"); v != "" {
		return v
	}
	h, err := os.UserHomeDir()
	if err != nil {
		h = "."
	}
	return filepath.Join(h, ".ntcept")
}

type Authority struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	PEM     []byte
	CertDir string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func LoadOrCreate(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")

	certPEM, errC := os.ReadFile(certPath)
	keyPEM, errK := os.ReadFile(keyPath)
	if errC != nil || errK != nil {
		var err error
		if certPEM, keyPEM, err = generateCA(); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
	}

	cert, key, err := parsePair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading CA from %s: %w", dir, err)
	}
	return &Authority{Cert: cert, Key: key, PEM: certPEM, CertDir: dir, cache: map[string]*tls.Certificate{}}, nil
}

// CertPath is the file a runtime's trust store should be pointed at.
func (a *Authority) CertPath() string { return filepath.Join(a.CertDir, "ca.pem") }

func generateCA() (certPEM, keyPEM []byte, err error) {
	// RSA for the root: Java keystores and a few older stacks are still happier with it, and it
	// is minted exactly once per machine. Leaves below are ECDSA, which is what gets minted often.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: CommonName, Organization: []string{"ntcept"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(3, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}

func parsePair(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, fmt.Errorf("malformed PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("CA key is not a signer")
	}
	return cert, signer, nil
}

func serial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, limit)
	return n
}

// LeafForSANs mints a certificate covering several names and addresses at once. Used where one
// server has to be reachable both by hostname and by literal IP.
func (a *Authority) LeafForSANs(names []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cn := "ntcept"
	if len(names) > 0 {
		cn = names[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"ntcept"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.Key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, a.Cert.Raw}, PrivateKey: key}
	if parsed, err := x509.ParseCertificate(der); err == nil {
		leaf.Leaf = parsed
	}
	return leaf, nil
}

// LeafFor mints (and memoises) a certificate for one SNI name or literal IP.
//
// The lock is held across generation rather than only around the map. A browser opening a page
// makes six connections to the same host at once, and releasing the lock to generate would have
// all six miss, mint their own certificate and overwrite each other — the cache would do nothing
// precisely when it is needed. Minting a P-256 leaf takes tens of microseconds, and only on the
// first connection to a host, so serialising it costs less than the duplicated work did.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if hit, ok := a.cache[host]; ok {
		return hit, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host, Organization: []string{"ntcept"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.Key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, a.Cert.Raw}, PrivateKey: key}
	if parsed, err := x509.ParseCertificate(der); err == nil {
		leaf.Leaf = parsed
	}

	a.cache[host] = leaf
	return leaf, nil
}

// ServerConfig returns a TLS config that mints certificates on demand from SNI.
// fallback covers clients that connect without SNI (direct-to-IP).
func (a *Authority) ServerConfig(fallback string, nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: nextProtos,
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hi.ServerName
			if name == "" {
				name = fallback
			}
			if name == "" {
				name = "localhost"
			}
			return a.LeafFor(name)
		},
	}
}
