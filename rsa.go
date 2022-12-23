package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RsaSize int

const (
	RSA1024 RsaSize = 1024
	RSA2048 RsaSize = 2048
	RSA4096 RsaSize = 4096
)

// CreateRsaPrivateKey creates an RSA private key.
func (c *Certificate) CreateRsaPrivateKey(size RsaSize) (err error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	c.rsa, err = rsa.GenerateKey(rand.Reader, int(size))
	if err != nil {
		return
	}
	c.Algorithm = Rsa
	return
}

// RsaPublicKey returns the rsa.PublicKey of the Certificate.
func (c *Certificate) RsaPublicKey() (key *rsa.PublicKey) {
	return &c.rsa.PublicKey
}

func (c *Certificate) RsaToPem() (p *pem.Block, err error) {
	if c.rsa == nil {
		return nil, errPrivateKeyCannotBeNil
	}

	der, err := x509.MarshalPKCS8PrivateKey(c.rsa)
	if err != nil {
		return
	}
	return &pem.Block{
		Type:  RsaPrivateKeyKey,
		Bytes: der,
	}, nil
}

func (c *Certificate) Rsa() *rsa.PrivateKey {
	return c.rsa
}

func ParsePublicRsa(c interface{}) (p *rsa.PublicKey, err error) {
	pubKey, ok := c.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to parse to rsa public key")
	}
	return pubKey, nil
}
