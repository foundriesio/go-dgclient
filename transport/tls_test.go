package transport

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/foundriesio/go-dgclient/v1/sotatoml"
	"github.com/stretchr/testify/require"
)

type FactoryPki struct {
	CA         crypto.Signer
	CAPubPem   []byte
	TlsConfig  *tls.Config
	ClientPub  []byte
	ClientPriv []byte
}

func GeneratePki(factoryName string) (*FactoryPki, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create a CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{factoryName},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Minute), // 1 minute
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// Self-sign the CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	caCertPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, err
	}

	// Set up server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{factoryName},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotAfter:    time.Now().Add(time.Minute),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	certPrivKeyPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	}

	serverCert, err := tls.X509KeyPair(pem.EncodeToMemory(certPEM), pem.EncodeToMemory(certPrivKeyPem))
	if err != nil {
		return nil, err
	}

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// Set up client certificate
	cliCert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: "client",
		},
		NotAfter:    time.Now().Add(time.Minute),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}

	cliCertPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	cliCertBytes, err := x509.CreateCertificate(rand.Reader, cliCert, caCert, &cliCertPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	cliCertPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cliCertBytes,
	}

	cliCertPrivKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cliCertPrivKey),
	}

	pki := FactoryPki{
		CA:         caPrivKey,
		CAPubPem:   pem.EncodeToMemory(caCertPEM),
		TlsConfig:  serverTLSConf,
		ClientPub:  pem.EncodeToMemory(cliCertPEM),
		ClientPriv: pem.EncodeToMemory(cliCertPrivKeyPEM),
	}
	return &pki, nil
}

func TestGetTlsConfig(t *testing.T) {
	pki, err := GeneratePki("test")
	require.Nil(t, err)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "root.crt")
	clientPath := filepath.Join(tmpDir, "client.pem")
	keyPath := filepath.Join(tmpDir, "priv.key")
	require.Nil(t, os.WriteFile(caPath, pki.CAPubPem, 0o777))
	require.Nil(t, os.WriteFile(clientPath, pki.ClientPub, 0o777))
	require.Nil(t, os.WriteFile(keyPath, pki.ClientPriv, 0o777))

	sota := `
[tls]
ca_source = "file"
pkey_source = "file"
cert_source = "file"

[import]
tls_cacert_path = "%s"
tls_pkey_path = "%s"
tls_clientcert_path = "%s"
`
	sota = fmt.Sprintf(sota, caPath, keyPath, clientPath)
	require.Nil(t, os.WriteFile(filepath.Join(tmpDir, "sota.toml"), []byte(sota), 0o777))

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte("OK"))
		require.Nil(t, err)
	}))
	defer ts.Close()
	ts.TLS = pki.TlsConfig
	ts.StartTLS()

	toml, err := sotatoml.NewAppConfig([]string{tmpDir})
	require.Nil(t, err)

	cfg, _, err := GetTlsConfig(toml)
	require.Nil(t, err)

	transport := &http.Transport{TLSClientConfig: cfg}
	client := &http.Client{Timeout: time.Second * 30, Transport: transport}

	res, err := client.Get(ts.URL)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.Nil(t, err)
	require.Equal(t, "OK", string(body))
}
