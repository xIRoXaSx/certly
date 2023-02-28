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

	// Test encryption and decryption.
	testPass := []byte("This_Is_Just_A_Simple_Test_Value")
	opts := defaultOpts()
	var (
		p   *Pgp
		err error
	)
	p, err = New(opts)
	r.NoError(t, err)
	r.NoError(t, p.CreatePgpPrivateKey(cert.RSA2048))

	r.NotNil(t, p.Pgp())
	r.NotNil(t, p.pgp)
	r.Exactly(t, p.pgp, p.Pgp())
	pm, err := p.PrivateKeyToPem()
	r.NoError(t, err)
	r.NotNil(t, pm)
	r.NoError(t, p.SetUnsafePrivateKey())

	r.NoError(t, p.EncryptPrivateKey(testPass))
	r.NoError(t, p.LoadPrivateKey())
	r.Exactly(t, p.GetPrivateKey(), p.privateKeyBlock)
	r.NoError(t, p.DecryptPrivateKey(testPass))
	r.Error(t, p.DecryptPrivateKey(testPass[:len(testPass)-1]))

	p, err = New(opts)
	r.NoError(t, err)
	r.NoError(t, p.EnableAutoRelease().CreatePgpPrivateKey(cert.RSA4096))
	r.Exactly(t, p.pgp, p.Pgp())
	pgp := p.Pgp()
	r.NotEqual(t, packet.PrivateKey{}, *pgp)
	r.NotNil(t, pgp)
	r.NoError(t, p.SetUnsafePrivateKey())
	r.Nil(t, p.Pgp())
	r.Exactly(t, packet.PrivateKey{}, *pgp)
}
