package pgp

import (
	"testing"

	r "github.com/stretchr/testify/require"
	"github.com/xiroxasx/certly/cert"
	"golang.org/x/crypto/openpgp/packet"
)

func defaultOpts() Options {
	return Options{
		Size:    cert.RSA2048,
		Name:    "test",
		Comment: "A test comment",
		Email:   "test@local.com",
	}
}

func TestCertificate_CreatePgpPrivateKey(t *testing.T) {
	t.Parallel()

	var (
		p        *Pgp
		err      error
		testPass = "This_Is_Just_A_Simple_Test_Value"
	)
	newTestPgp := func() (p *Pgp) {
		opts := defaultOpts()
		p, err := New(opts)
		r.NoError(t, err)
		p.EnableAutoRelease()
		r.Nil(t, p.Pgp())
		r.NoError(t, p.CreatePgpPrivateKey(cert.RSA2048))
		r.NotNil(t, p.Pgp())
		return p
	}

	// Test auto-release after setting unsafe private key.
	p = newTestPgp()
	r.NotNil(t, p.Pgp())
	r.NoError(t, p.SetUnsafePrivateKey())
	r.Nil(t, p.Pgp())

	// Test auto-release after encrypting the private key.
	p = newTestPgp()
	r.NotNil(t, p.Pgp())
	r.NoError(t, p.EncryptPrivateKey([]byte(testPass)))
	r.Nil(t, p.Pgp())

	p = newTestPgp()
	r.NotNil(t, p.Pgp())
	r.Exactly(t, p.pgp, p.Pgp())
	pm, err := p.PrivateKeyToPem()
	r.NoError(t, err)
	r.NotNil(t, pm)
	r.NoError(t, p.EncryptPrivateKey([]byte(testPass)))
	r.NoError(t, p.LoadPrivateKey())
	r.Exactly(t, p.GetPrivateKey(), p.privateKeyBlock)
	r.NoError(t, p.DecryptPrivateKey([]byte(testPass)))
	tPass := []byte(testPass)
	expectedPass := make([]byte, len(tPass))
	for i := 0; i < len(tPass); i++ {
		expectedPass[i] = 0
	}
	r.NoError(t, p.EncryptPrivateKey(tPass))
	r.Exactly(t, expectedPass, tPass)
	pass := []byte(testPass)
	r.Error(t, p.DecryptPrivateKey(pass[:len(pass)-1]))

	p = newTestPgp()
	pgp := p.Pgp()
	r.NotEqual(t, packet.PrivateKey{}, *pgp)
	r.NotNil(t, pgp)
	r.NoError(t, p.SetUnsafePrivateKey())
	r.Nil(t, p.Pgp())
	r.Exactly(t, packet.PrivateKey{}, *pgp)

	opts := defaultOpts()
	p, err = New(opts)
	r.NoError(t, err)
	r.Nil(t, p.Pgp())
	r.Error(t, p.CreatePrivateKey("RSA..1024"))
	r.Error(t, p.CreatePrivateKey("RSA..024"))
	r.Error(t, p.CreatePrivateKey("RSA.1023"))
	r.NoError(t, p.CreatePrivateKey("RSA.1024"))
	r.NotNil(t, p.Pgp())
	r.Nil(t, p.PrivateKey)
	r.NoError(t, p.SetUnsafePrivateKey())
	r.NotNil(t, p.PrivateKey)
	r.NoError(t, p.LoadPrivateKey())

	opts = defaultOpts()
	p, err = New(opts)
	r.NoError(t, err)
	r.Nil(t, p.Pgp())
	r.NoError(t, p.CreatePgpPrivateKey(cert.RSA2048))
	r.NotNil(t, p.Pgp())
	p.Release()
	r.Nil(t, p.Pgp())
	r.Nil(t, p.privateKeyBlock.Data)
}
