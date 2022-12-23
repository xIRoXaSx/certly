package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	r "github.com/stretchr/testify/require"
)

func defaultOpts() Options {
	var ts = time.UnixMilli(1670181939000).UTC()
	return Options{
		CommonName:         "test-CN",
		Organization:       "Test-Orga",
		OrganizationalUnit: "Test-OU",
		Country:            "DE",
		State:              "Test-State",
		Locality:           "Test-Locality",
		DNSNames:           []string{"test.example.com"},
		IsCA:               false,
		NotBefore:          ts,
		NotAfter:           ts.Add(24 * 365 * time.Hour),
	}
}

func TestCertificate(t *testing.T) {
	t.Parallel()

	var renewed = time.UnixMilli(1670281939000).UTC()
	opts := defaultOpts()
	newRsaCert := func() (c *Certificate) {
		c, err := New(&opts)
		r.NoError(t, err)
		r.NoError(t, c.CreateRsaPrivateKey(RSA4096))
		return
	}

	c := newRsaCert()
	r.NoError(t, c.SignSelf())
	r.True(t, c.isSigned)
	r.Error(t, c.SignSelf())

	// Test x509 fields.
	xCert, err := x509.ParseCertificate([]byte(c.Der))
	r.NoError(t, err)
	parsedOpts, err := ParseCertificateOptions(xCert)
	r.NoError(t, err)
	r.Exactly(t, opts, *parsedOpts)

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
	tooShortPass := "too_short"
	pk := c.rsa
	pkPem := c.EncryptedPrivateKey
	r.Error(t, c.EncryptPrivateKey(tooShortPass))
	r.NoError(t, c.EncryptPrivateKey(testPass))
	r.NoError(t, c.LoadPrivateKey())
	c.rsa = nil
	c.EncryptedPrivateKey = ""
	r.NoError(t, c.DecryptPrivateKey(testPass, Rsa))
	r.Error(t, c.DecryptPrivateKey(tooShortPass, Rsa))
	r.Exactly(t, pk, c.rsa)
	r.Exactly(t, c.rsa, c.Rsa())
	r.Exactly(t, pkPem, c.EncryptedPrivateKey)

	// Test to sign with CA.
	// Create CA.
	caOpts := opts
	caOpts.CommonName = "test-CA"
	caOpts.IsCA = true
	ca, err := New(&caOpts)
	r.NoError(t, err)
	ca.ID = 1
	r.Error(t, ca.SignSelf())
	r.NoError(t, ca.CreateRsaPrivateKey(RSA4096))
	r.NoError(t, ca.SignSelf())

	// Certificate is already signed by itself, create a new one.
	c = newRsaCert()
	r.NoError(t, c.SignWith(ca))
	r.True(t, c.isSigned)
	xCert, err = x509.ParseCertificate([]byte(c.Der))
	r.NoError(t, err)
	r.NotNil(t, xCert)
	r.Exactly(t, xCert.Issuer.CommonName, caOpts.CommonName)

	// Test to convert to Pem.
	var buf bytes.Buffer
	r.NoError(t, pem.Encode(&buf, &pem.Block{
		Type:  CertificateKey,
		Bytes: xCert.Raw,
	}))
	r.NotEmpty(t, buf.Bytes())

	// Test to renew certificates.
	nbf := opts.NotBefore
	naf := opts.NotAfter
	id := c.ID
	sn := xCert.SerialNumber
	opts.NotBefore = renewed
	opts.NotAfter = renewed.Add(24 * 365 * time.Hour)
	rn, err := c.Renew(&opts, ca)
	r.NoError(t, err)
	xCert, err = x509.ParseCertificate([]byte(rn.Der))
	r.NoError(t, err)
	r.Exactly(t, xCert.Issuer.CommonName, caOpts.CommonName)
	r.Greater(t, xCert.NotBefore, nbf)
	r.Greater(t, xCert.NotAfter, naf)
	r.Exactly(t, rn.ID, id)
	r.Exactly(t, rn.SignerID, ca.ID)
	r.NotEqual(t, xCert.SerialNumber, sn)
}

func TestCertificate_Rsa(t *testing.T) {
	t.Parallel()

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
	opts := defaultOpts()
	var c *Certificate
	sizes := []RsaSize{RSA1024, RSA2048, RSA4096}
	for _, size := range sizes {
		var err error
		c, err = New(&opts)
		r.NoError(t, err)
		r.NoError(t, c.CreateRsaPrivateKey(size))
		r.NoError(t, c.SignSelf())
		r.True(t, c.isSigned)
		r.Error(t, c.SignSelf())

		r.NotNil(t, c.Rsa())
		r.NotNil(t, c.rsa)
		r.Exactly(t, c.rsa, c.Rsa())
		p, err := c.RsaToPem()
		r.NoError(t, err)
		r.NotNil(t, p)
		pub, ok := c.Rsa().Public().(interface{})
		r.True(t, ok)
		pubKey, err := ParsePublicRsa(pub)
		r.NoError(t, err)
		r.NotNil(t, pubKey)

		r.Nil(t, c.ecdsa)
		r.Nil(t, c.Ecdsa())
		diffKey, err := c.EcdsaToPem()
		r.Error(t, err)
		r.Nil(t, diffKey)
		r.NoError(t, c.SetUnsafePrivateKey())
		r.NoError(t, c.LoadUnsafePrivateKey())
		r.Exactly(t, AlgorithmToString(c.Algorithm), "RSA")
	}

	// Test private key encryption.
	r.Error(t, c.EncryptPrivateKey(testPass[:len(testPass)-1]))
	r.NoError(t, c.EncryptPrivateKey(testPass))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetEncryptedPrivateKey(), c.privateKeyBlock)

	// Test private key decryption.
	r.Error(t, c.DecryptPrivateKey(testPass[:len(testPass)-1], Rsa))
	r.Error(t, c.DecryptPrivateKey(testPass[:len(testPass)-1]+"!", Rsa))
	r.NoError(t, c.DecryptPrivateKey(testPass, Rsa))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotNil(t, blk)
}

func TestCertificate_Ecdsa(t *testing.T) {
	t.Parallel()

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
	tooShortPass := "too_short"
	opts := defaultOpts()
	curves := []Curve{P224, P256, P384, P521}
	var c *Certificate
	for _, curve := range curves {
		var err error
		c, err = New(&opts)
		r.NoError(t, err)
		r.NoError(t, c.CreateEcdsaPrivateKey(curve))
		r.NoError(t, c.SignSelf())
		r.True(t, c.isSigned)

		r.NotNil(t, c.Ecdsa())
		r.NotNil(t, c.ecdsa)
		r.Exactly(t, c.ecdsa, c.Ecdsa())
		p, err := c.EcdsaToPem()
		r.NoError(t, err)
		r.NotNil(t, p)
		pub, ok := c.Ecdsa().Public().(interface{})
		r.True(t, ok)
		pubKey, err := ParsePublicEcdsa(pub)
		r.NoError(t, err)
		r.NotNil(t, pubKey)

		r.Nil(t, c.rsa)
		r.Nil(t, c.Rsa())
		diffKey, err := c.RsaToPem()
		r.Error(t, err)
		r.Nil(t, diffKey)
		r.NoError(t, c.SetUnsafePrivateKey())
		r.NoError(t, c.LoadUnsafePrivateKey())
		r.Exactly(t, AlgorithmToString(c.Algorithm), "ECDSA")
	}

	r.NoError(t, c.EncryptPrivateKey(testPass))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetEncryptedPrivateKey(), c.privateKeyBlock)
	r.NoError(t, c.DecryptPrivateKey(testPass, Ecdsa))
	r.Error(t, c.DecryptPrivateKey(tooShortPass, Ecdsa))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotNil(t, blk)
}

func TestCertificate_Ed25519(t *testing.T) {
	t.Parallel()

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
	tooShortPass := "too_short"
	opts := defaultOpts()
	var c *Certificate
	var err error
	c, err = New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.CreateEd25519PrivateKey())
	r.NoError(t, c.SignSelf())
	r.True(t, c.isSigned)

	r.NotNil(t, c.Ed25519())
	r.NotNil(t, c.ed25519)
	r.Exactly(t, c.ed25519, c.Ed25519())
	p, err := c.Ed25519ToPem()
	r.NoError(t, err)
	r.NotNil(t, p)
	pub := c.Ed25519PublicCryptoKey()
	r.NotNil(t, pub)
	pubKey, err := c.Ed25519PublicKey()
	r.NoError(t, err)
	r.NotNil(t, pubKey)

	r.Nil(t, c.rsa)
	r.Nil(t, c.Rsa())
	diffKey, err := c.RsaToPem()
	r.Error(t, err)
	r.Nil(t, diffKey)
	r.NoError(t, c.SetUnsafePrivateKey())
	r.NoError(t, c.LoadUnsafePrivateKey())
	r.Exactly(t, AlgorithmToString(c.Algorithm), "ED25591")

	r.NoError(t, c.EncryptPrivateKey(testPass))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetEncryptedPrivateKey(), c.privateKeyBlock)
	r.NoError(t, c.DecryptPrivateKey(testPass, Ed25591))
	r.Error(t, c.DecryptPrivateKey(tooShortPass, Ed25591))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotNil(t, blk)
}

func TestCertificate_ParseX509(t *testing.T) {
	t.Parallel()

	opts := defaultOpts()
	c, err := New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.CreateRsaPrivateKey(RSA1024))
	r.NoError(t, c.SignSelf())
	r.True(t, c.isSigned)
	xCert, err := c.ParseX509()
	r.NoError(t, err)
	xCert2, err := x509.ParseCertificate([]byte(c.Der))
	r.NoError(t, err)
	r.Exactly(t, xCert, xCert2)
}

func TestCertificate_NilCerts(t *testing.T) {
	var (
		crt  *Certificate
		opts = defaultOpts()
	)
	c, err := New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.CreateRsaPrivateKey(RSA1024))
	r.Error(t, c.sign(nil))
	r.False(t, c.isSigned)
	r.Error(t, crt.sign(nil))
}
