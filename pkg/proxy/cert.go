package proxy

import (
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
	"strings"
	"sync"
	"time"
)

// CertAuthority manages the proxy's Root CA and dynamically generates leaf certificates.
type CertAuthority struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	cache  map[string]*tls.Certificate
	mu     sync.RWMutex
}

// NewCertAuthority initializes or loads a CA from the provided paths.
// If certPath or keyPath do not exist or are empty, a new 2048-bit RSA CA is generated.
func NewCertAuthority(certPath, keyPath string) (*CertAuthority, error) {
	ca := &CertAuthority{
		cache: make(map[string]*tls.Certificate),
	}

	if certPath != "" && keyPath != "" && fileExists(certPath) && fileExists(keyPath) {
		if err := ca.loadCA(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to load CA: %w", err)
		}
		return ca, nil
	}

	if err := ca.generateCA(); err != nil {
		return nil, fmt.Errorf("failed to generate CA: %w", err)
	}

	if certPath != "" && keyPath != "" {
		_ = ca.Save(certPath, keyPath)
	}

	return ca, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (ca *CertAuthority) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("no PEM block in cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("no PEM block in key file")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return fmt.Errorf("failed to parse private key: %v / %v", err, err2)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("private key is not RSA")
		}
	}

	ca.caCert = cert
	ca.caKey = key
	return nil
}

func (ca *CertAuthority) generateCA() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"lminspect Proxy"},
			CommonName:    "lminspect Root CA",
			Country:       []string{"US"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	ca.caCert = cert
	ca.caKey = priv
	return nil
}

// Save writes the CA certificate and private key to disk.
func (ca *CertAuthority) Save(certPath, keyPath string) error {
	_ = os.MkdirAll(filepath.Dir(certPath), 0755)
	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.caKey)})
}

// CACertPEM returns the PEM encoded bytes of the Root CA certificate.
func (ca *CertAuthority) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
}

// GetCertificate returns a cached or dynamically generated TLS certificate for host.
func (ca *CertAuthority) GetCertificate(host string) (*tls.Certificate, error) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	ca.mu.RLock()
	if cert, ok := ca.cache[host]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Double check after lock
	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	cert, err := ca.mintCertificate(host)
	if err != nil {
		return nil, err
	}
	ca.cache[host] = cert
	return cert, nil
}

func (ca *CertAuthority) mintCertificate(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"lminspect"},
			CommonName:   host,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.caCert, &priv.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.caCert.Raw},
		PrivateKey:  priv,
	}

	return tlsCert, nil
}

// TLSConfig returns a tls.Config configured for dynamic on-the-fly certificate generation.
func (ca *CertAuthority) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := info.ServerName
			if serverName == "" {
				serverName = "localhost"
			}
			return ca.GetCertificate(serverName)
		},
		NextProtos: []string{"http/1.1"},
	}
}
