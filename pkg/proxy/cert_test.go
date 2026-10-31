package proxy

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCertAuthorityGenerationAndMinting(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lminspect-ca-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	certPath := filepath.Join(tempDir, "ca.crt")
	keyPath := filepath.Join(tempDir, "ca.key")

	ca, err := NewCertAuthority(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Fatal("CA files were not written to disk")
	}

	// Test reload
	ca2, err := NewCertAuthority(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to reload CA: %v", err)
	}
	if ca2.caCert.Subject.CommonName != ca.caCert.Subject.CommonName {
		t.Fatal("reloaded CA subject mismatch")
	}

	// Mint certificate for domain
	tlsCert, err := ca.GetCertificate("example.com")
	if err != nil {
		t.Fatalf("failed to mint domain certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("leaf CN mismatch: %s", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("leaf SAN DNS mismatch: %v", leaf.DNSNames)
	}

	// Verify certificate is signed by CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "example.com",
	})
	if err != nil {
		t.Fatalf("leaf certificate verification failed: %v", err)
	}

	// Mint certificate for IP literal
	ipCert, err := ca.GetCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("failed to mint IP certificate: %v", err)
	}
	ipLeaf, err := x509.ParseCertificate(ipCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(ipLeaf.IPAddresses) != 1 || ipLeaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("leaf IP SAN mismatch: %v", ipLeaf.IPAddresses)
	}
}
