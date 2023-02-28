package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
)

type RsaSize int

const (
	RSA1024 RsaSize = 1024
	RSA2048 RsaSize = 2048
	RSA4096 RsaSize = 4096
)

func ParseRsaSize(size string) (s RsaSize, err error) {
	i, err := strconv.ParseInt(size, 10, 32)
	if err != nil {
		return
	}

	switch i {
	case int64(RSA1024):
		s = RSA1024

	case int64(RSA2048):
		s = RSA2048

	case int64(RSA4096):
		s = RSA4096

	default:
		err = errors.New("no such size")
	}
	return
}

// CreateRsaPrivateKey creates an RSA private key.
func (c *Certificate) CreateRsaPrivateKey(size RsaSize) (err error) {
	if size != RSA1024 && size != RSA2048 && size != RSA4096 {
		return errors.New("no such rsa size implemented")
	}

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
		return nil, ErrPrivateKeyCannotBeNil
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
