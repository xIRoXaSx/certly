package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math"
	"reflect"
	"strings"
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
		Expiration: Expiration{
			NotBefore: ts,
			NotAfter:  ts.Add(24 * 365 * time.Hour),
		},
	}
}

func TestCertificate(t *testing.T) {
	t.Parallel()

	// Test nil opts cert.
	c, err := New(nil)
	r.Error(t, err)
	r.Nil(t, c)

	var renewed = time.UnixMilli(1670281939000).UTC()
	opts := defaultOpts()
	newRsaCert := func() (c *Certificate) {
		c, err := New(&opts)
		r.NoError(t, err)
		r.NoError(t, c.CreateRsaPrivateKey(RSA4096))
		return
	}

	// Test x509 field validation.
	c = newRsaCert()
	o := defaultOpts()
	v := reflect.Indirect(reflect.ValueOf(&o))
	fieldNum := v.NumField()
	for i := 0; i < fieldNum; i++ {
		f := v.Field(i)
		fType := f.Type()
		fTypeName := f.Type().String()

		if fTypeName == "bool" {
			continue
		}

		fVal := f.Interface()
		if fTypeName == "[]string" {
			f.Set(reflect.Indirect(reflect.ValueOf([]string{
				"", "", "", "", "", "", "", "", "", "",
				"", "", "", "", "", "", "", "", "", "", "",
			})))
		} else {
			f.Set(reflect.Zero(fType))
		}

		_, err := New(&o)
		r.Error(t, err, v.Type().Field(i).Name)
		f.Set(reflect.ValueOf(fVal))
	}

	c = newRsaCert()
	r.NoError(t, c.SignSelf())
	r.True(t, c.isSigned)
	r.Error(t, c.SignSelf())

	// Test x509 fields.
	xCert, err := x509.ParseCertificate(c.PublicKey)
	r.NoError(t, err)
	parsedOpts, err := ParseCertificateOptions(xCert)
	r.NoError(t, err)
	r.Exactly(t, opts, *parsedOpts)

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
	pk := c.rsa
	pkPem := c.PrivateKey
	r.True(t, c.IsUnsafe())
	r.NoError(t, c.EncryptPrivateKey([]byte(testPass)))
	r.False(t, c.IsUnsafe())
	r.NoError(t, c.LoadPrivateKey())
	c.rsa = nil
	c.PrivateKey = nil
	r.NoError(t, c.DecryptPrivateKey([]byte(testPass)))
	r.False(t, c.IsUnsafe())
	r.Exactly(t, pk, c.rsa)
	r.Exactly(t, c.rsa, c.Rsa())
	r.Exactly(t, pkPem, c.PrivateKey)

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
	r.True(t, ca.IsUnsafe())

	// Certificate is already signed by itself, create a new one.
	c = newRsaCert()
	r.NoError(t, c.SignWith(ca))
	r.True(t, c.isSigned)
	xCert, err = x509.ParseCertificate(c.PublicKey)
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
	xCert, err = x509.ParseCertificate(rn.PublicKey)
	r.NoError(t, err)
	r.Exactly(t, xCert.Issuer.CommonName, caOpts.CommonName)
	r.Greater(t, xCert.NotBefore, nbf)
	r.Greater(t, xCert.NotAfter, naf)
	r.Exactly(t, rn.ID, id)
	r.Exactly(t, rn.SignerID, ca.ID)
	r.NotEqual(t, xCert.SerialNumber, sn)

	// Test invalid algorithms.
	c, err = New(&opts)
	r.NoError(t, err)
	r.Error(t, c.CreateEcdsaPrivateKey(Curve(math.MaxUint)))

	c, err = New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.CreateEcdsaPrivateKey(P256))
	r.NoError(t, c.SignSelf())
	c.Algorithm = math.MaxUint

	// Test with IP addresses.
	opts = defaultOpts()
	opts.IPAddresses = []string{"10.10.10.10"}
	c, err = New(&opts)
	r.NoError(t, err)

	opts.IPAddresses = []string{""}
	c, err = New(&opts)
	r.Error(t, err)

	opts.IPAddresses = []string{"10.10.10"}
	c, err = New(&opts)
	r.Error(t, err)
}

func TestNewWithIdentifier(t *testing.T) {
	t.Parallel()

	opts := defaultOpts()
	id := uint64(100)
	name := "NewCertificate"
	c, err := NewWithIdentifier(id, name, &opts)
	r.NoError(t, err)
	r.Exactly(t, c.ID, id)
	r.Exactly(t, c.Name, name)

	c, err = NewWithIdentifier(id, "", &opts)
	r.Error(t, err)
	opts.CommonName = ""
	c, err = NewWithIdentifier(id, name, &opts)
	r.Error(t, err)
	r.NoError(t, c.CreateEd25519PrivateKey())
	r.NoError(t, c.SetUnsafePrivateKey())
	r.NoError(t, c.SignWith(c))
}

func TestCertificate_Release(t *testing.T) {
	t.Parallel()

	newTestCert := func(keyType string, signSelf bool) *Certificate {
		opts := defaultOpts()
		c, err := New(&opts)
		r.NoError(t, err)
		r.NoError(t, c.CreatePrivateKey(keyType))
		if signSelf {
			r.NoError(t, c.SignSelf())
		}
		return c
	}

	// All fields should be empty.
	checkAllEmpty := func(t *testing.T, c *Certificate) {
		r.Nil(t, c.rsa)
		r.Nil(t, c.ecdsa)
		r.Nil(t, c.ed25519)
		r.Empty(t, c.privateKeyBlock.Data)
	}

	// Dedicated field should be filled.
	checkFilled := func(t *testing.T, algo string, c *Certificate) {
		switch algo {
		case AlgorithmToString(Rsa):
			r.NotNil(t, c.rsa)
			r.Nil(t, c.ecdsa)
			r.Nil(t, c.ed25519)
		case AlgorithmToString(Ecdsa):
			r.Nil(t, c.rsa)
			r.NotNil(t, c.ecdsa)
			r.Nil(t, c.ed25519)
		default:
			r.Nil(t, c.rsa)
			r.Nil(t, c.ecdsa)
			r.NotNil(t, c.ed25519)
		}
	}

	caOpts := defaultOpts()
	caOpts.IsCA = true
	caPass := "SomeTestPassphrase"
	keyType := "RSA.1024"
	algo := strings.Split(keyType, ".")[0]
	ca, err := New(&caOpts)
	r.NoError(t, err)
	r.NoError(t, ca.EnableAutoRelease().CreatePrivateKey(keyType))
	r.NoError(t, ca.SignSelf())
	r.Empty(t, ca.PrivateKey)
	caPriv := ca.privateKeyBlock.Data
	r.NoError(t, ca.EncryptPrivateKey([]byte(caPass)))
	encCaPriv := ca.PrivateKey
	r.NotEmpty(t, encCaPriv)
	checkAllEmpty(t, ca)
	r.NotEqualValues(t, caPriv, encCaPriv)
	xCA, err := ca.ParseX509()
	r.NoError(t, err)

	// Check if certs cannot be signed with current CA state.
	c := newTestCert(keyType, true).EnableAutoRelease()
	r.Error(t, c.SignWith(ca))
	pass := []byte(caPass)
	salt := make([]byte, len(ca.Salt))
	nonce := make([]byte, len(ca.Nonce))
	copy(salt, ca.Salt)
	copy(nonce, ca.Nonce)
	r.Error(t, ca.DecryptPrivateKey(pass[:len(pass)-1]))

	copy(ca.Salt, salt)
	copy(ca.Nonce, nonce)
	r.NoError(t, ca.DecryptPrivateKey([]byte(caPass)))
	c = newTestCert(keyType, true)
	r.Error(t, c.SignWith(ca))
	pemBlk, err := c.getPrivateKeyPem()
	r.NoError(t, err)
	priv := pemBlk.Bytes
	checkFilled(t, algo, c)
	r.NoError(t, c.EncryptPrivateKey(append([]byte(caPass), '!')))
	checkFilled(t, algo, c)
	c.Release()
	checkAllEmpty(t, c)

	// Check if field can be loaded again.
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.PrivateKey, c.privateKeyBlock.Data)
	r.NoError(t, c.DecryptPrivateKey(append([]byte(caPass), '!')))
	pemBlk, err = c.getPrivateKeyPem()
	r.NoError(t, err)
	r.Exactly(t, pemBlk.Bytes, priv)
	defer func() {
		ca.Release()
		checkAllEmpty(t, ca)
	}()

	// Check if passed slice is zero-ed.
	pass = []byte("SomePass")
	expectedPass := make([]byte, len(pass))
	for i := 0; i < len(pass); i++ {
		expectedPass[i] = 0
	}
	c = newTestCert(keyType, true)
	r.NoError(t, c.EncryptPrivateKey(pass))
	r.Exactly(t, expectedPass, pass)

	pass = []byte("SomePass")
	r.NoError(t, c.DecryptPrivateKey(pass))
	r.Exactly(t, expectedPass, pass)

	rsaKey := AlgorithmToString(Rsa)
	ecdsaKey := AlgorithmToString(Ecdsa)
	edKey := AlgorithmToString(Ed25591)
	cases := []string{
		rsaKey + ".1024",
		rsaKey + ".2048",
		rsaKey + ".4096",
		ecdsaKey + ".P224",
		ecdsaKey + ".P256",
		ecdsaKey + ".P384",
		ecdsaKey + ".P521",
		edKey,
	}
	for _, tc := range cases {
		algo = strings.Split(tc, ".")[0]

		// Fields should be empty after releasing.
		c = newTestCert(tc, true)
		checkFilled(t, algo, c)
		r.Nil(t, c.privateKeyBlock.Data)
		c.Release()
		checkAllEmpty(t, c)

		// Check if SignWith fails after releasing.
		c = newTestCert(tc, false).EnableAutoRelease()
		checkFilled(t, algo, c)
		r.NoError(t, c.SetUnsafePrivateKey())
		checkAllEmpty(t, c)
		r.Error(t, c.SignWith(c))
		r.NoError(t, c.LoadPrivateKey())
		checkFilled(t, algo, c)
		r.NoError(t, c.SignWith(c))
		r.NoError(t, c.SetUnsafePrivateKey())
		checkAllEmpty(t, c)

		// Check if SignSelf fails after releasing.
		c = newTestCert(tc, false).EnableAutoRelease()
		r.NoError(t, c.SetUnsafePrivateKey())
		checkAllEmpty(t, c)
		r.Error(t, c.SignSelf())
		r.NoError(t, c.LoadPrivateKey())
		checkFilled(t, algo, c)
		r.NoError(t, c.SignSelf())
		r.NoError(t, c.SetUnsafePrivateKey())
		checkAllEmpty(t, c)

		// New certs without EnableAutoRelease should keep private key values.
		// Using SignWith.
		c = newTestCert(tc, false)
		checkFilled(t, algo, c)
		r.NoError(t, c.SignWith(ca))
		r.NoError(t, c.SetUnsafePrivateKey())
		checkFilled(t, algo, c)

		// Check if field can be loaded anyway.
		r.NoError(t, c.LoadPrivateKey())
		checkFilled(t, algo, c)
		r.Exactly(t, c.privateKeyBlock.Data, c.PrivateKey)
		c.Release()
		checkAllEmpty(t, c)

		// Using SignSelf.
		c = newTestCert(tc, false)
		checkFilled(t, algo, c)
		r.NoError(t, c.SignSelf())
		r.NoError(t, c.SetUnsafePrivateKey())
		checkFilled(t, algo, c)

		// Check if field can be loaded again.
		r.NoError(t, c.LoadPrivateKey())
		checkFilled(t, algo, c)
		r.Exactly(t, c.privateKeyBlock.Data, c.PrivateKey)
		c.Release()
		checkAllEmpty(t, c)

		var xC *x509.Certificate
		c = newTestCert(tc, false)
		r.NoError(t, c.SignWith(ca))
		c.EnableAutoRelease()
		xC, err = c.ParseX509()
		r.NoError(t, err)
		r.Exactly(t, xCA.Issuer.SerialNumber, xC.Issuer.SerialNumber)
		r.Exactly(t, xCA.Issuer.CommonName, xC.Issuer.CommonName)
	}
}

func TestMapToCertError(t *testing.T) {
	err := mapToCertError(errors.New("cipher: message authentication failed"))
	r.ErrorIs(t, err, ErrCipherMsgAuthFailed)

	err = mapToCertError(ErrCipherMsgAuthFailed)
	r.ErrorIs(t, err, ErrCipherMsgAuthFailed)

	tErr := errors.New("test")
	err = mapToCertError(tErr)
	r.ErrorIs(t, err, tErr)

	err = mapToCertError(nil)
	r.NoError(t, err)
}

func TestCertificate_CreatePrivateKey(t *testing.T) {
	t.Parallel()

	// Test algo to string.
	r.Exactly(t, "None", AlgorithmToString(Algorithm(0)))
	r.Exactly(t, "RSA", AlgorithmToString(Algorithm(1)))
	r.Exactly(t, "ECDSA", AlgorithmToString(Algorithm(2)))
	r.Exactly(t, "ED25591", AlgorithmToString(Algorithm(3)))
	r.Exactly(t, "None", AlgorithmToString(Algorithm(0)))

	// Test private key creation from string.
	opts := defaultOpts()
	rsaKey := AlgorithmToString(Rsa)
	ecdsaKey := AlgorithmToString(Ecdsa)
	edKey := AlgorithmToString(Ed25591)
	cases := []string{
		rsaKey + ".1024",
		rsaKey + ".2048",
		rsaKey + ".4096",
		ecdsaKey + ".P224",
		ecdsaKey + ".P256",
		ecdsaKey + ".P384",
		ecdsaKey + ".P521",
		edKey,
	}

	for _, c := range cases {
		// Test upper case.
		crt, err := New(&opts)
		r.NoError(t, err)
		r.NoError(t, crt.CreatePrivateKey(c))

		// Test lower case.
		crt, err = New(&opts)
		r.NoError(t, err)
		r.NoError(t, crt.CreatePrivateKey(strings.ToLower(c)))

		// Test invalid, no and wrong delimiter.
		if c != edKey {
			crt, err = New(&opts)
			r.NoError(t, err)
			r.Error(t, crt.CreatePrivateKey(strings.ReplaceAll(c, ".", "")))

			crt, err = New(&opts)
			r.NoError(t, err)
			r.Error(t, crt.CreatePrivateKey(strings.ReplaceAll(c, ".", ",")))
		}
	}

	// Test too many args.
	crt, err := New(&opts)
	r.NoError(t, err)
	r.Error(t, crt.CreatePrivateKey(cases[0]+".1"))
	r.Error(t, crt.CreatePrivateKey(cases[3]+".1"))

	// Test unavailable sizes.
	crt, err = New(&opts)
	r.NoError(t, err)
	r.Error(t, crt.CreatePrivateKey(cases[0]+"1"))
	r.Error(t, crt.CreatePrivateKey(cases[3]+"1"))
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
		r.Exactly(t, AlgorithmToString(c.Algorithm), "RSA")
	}

	// Test private key encryption.
	r.NoError(t, c.EncryptPrivateKey([]byte(testPass)))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetPrivateKey(), c.privateKeyBlock)
	r.Exactly(t, c.GetPrivateKey().Data, c.PrivateKey)

	// Test private key decryption.
	pass := []byte(testPass)
	salt := make([]byte, len(c.Salt))
	nonce := make([]byte, len(c.Nonce))
	copy(salt, c.Salt)
	copy(nonce, c.Nonce)
	r.Error(t, c.DecryptPrivateKey(pass[:len(pass)-1]))

	copy(c.Salt, salt)
	copy(c.Nonce, nonce)
	r.NoError(t, c.DecryptPrivateKey([]byte(testPass)))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotEmpty(t, blk.Bytes)

	c, err = New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.EnableAutoRelease().CreateRsaPrivateKey(RSA1024))
	r.Exactly(t, c.rsa, c.Rsa())
	p := c.Rsa()
	r.NotEqual(t, rsa.PrivateKey{}, *p)
	r.NotNil(t, p)
	r.NoError(t, c.SetUnsafePrivateKey())
	r.Nil(t, c.Rsa())
	r.Exactly(t, rsa.PrivateKey{}, *p)
	pm, err := c.RsaToPem()
	r.Error(t, err)
	r.Nil(t, pm)
}

func TestCertificate_Ecdsa(t *testing.T) {
	t.Parallel()

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
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
		r.Exactly(t, AlgorithmToString(c.Algorithm), "ECDSA")
	}

	r.NoError(t, c.EncryptPrivateKey([]byte(testPass)))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetPrivateKey(), c.privateKeyBlock)
	r.NoError(t, c.DecryptPrivateKey([]byte(testPass)))
	pass := []byte(testPass)
	r.Error(t, c.DecryptPrivateKey(pass[:len(pass)-1]))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotEmpty(t, blk.Bytes)

	c, err = New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.EnableAutoRelease().CreateEcdsaPrivateKey(P521))
	r.Exactly(t, c.ecdsa, c.Ecdsa())
	p := c.Ecdsa()
	r.NotEqual(t, ecdsa.PrivateKey{}, *p)
	r.NotNil(t, p)
	r.NoError(t, c.SetUnsafePrivateKey())
	r.Nil(t, c.Ecdsa())
	r.Exactly(t, ecdsa.PrivateKey{}, *p)
	pm, err := c.EcdsaToPem()
	r.Error(t, err)
	r.Nil(t, pm)
}

func TestCertificate_Ed25519(t *testing.T) {
	t.Parallel()

	// Test encryption and decryption.
	testPass := "This_Is_Just_A_Simple_Test_Value"
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
	pm, err := c.Ed25519ToPem()
	r.NoError(t, err)
	r.NotNil(t, pm)
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
	r.Exactly(t, AlgorithmToString(c.Algorithm), "ED25591")

	r.NoError(t, c.EncryptPrivateKey([]byte(testPass)))
	r.NoError(t, c.LoadPrivateKey())
	r.Exactly(t, c.GetPrivateKey(), c.privateKeyBlock)
	r.NoError(t, c.DecryptPrivateKey([]byte(testPass)))
	pass := []byte(testPass)
	r.Error(t, c.DecryptPrivateKey(pass[:len(pass)-1]))
	blk, err := c.PrivateKeyBlock()
	r.NoError(t, err)
	r.NotEmpty(t, blk.Bytes)

	c, err = New(&opts)
	r.NoError(t, err)
	r.NoError(t, c.EnableAutoRelease().CreateEd25519PrivateKey())
	r.Exactly(t, c.ed25519, c.Ed25519())
	p := c.Ed25519()
	r.NotEqual(t, ed25519.PrivateKey{}, *p)
	r.NotNil(t, p)
	r.NoError(t, c.SetUnsafePrivateKey())
	r.Nil(t, c.Ed25519())
	r.Exactly(t, ed25519.PrivateKey{}, *p)
	pm, err = c.Ed25519ToPem()
	r.Error(t, err)
	r.Nil(t, pm)
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
	xCert2, err := x509.ParseCertificate(c.PublicKey)
	r.NoError(t, err)
	r.Exactly(t, xCert, xCert2)
	xCert3, err := ParseX509(c.PublicKey)
	r.NoError(t, err)
	r.Exactly(t, xCert, xCert3)
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
