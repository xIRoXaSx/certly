package cert

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// CreateEd25519PrivateKey creates an ED25519 private key.
func (c *Certificate) CreateEd25519PrivateKey() (err error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	cb := make([]byte, ed25519.SeedSize)
	read, err := rand.Reader.Read(cb)
	if err != nil {
		return
	}
	if read != ed25519.SeedSize {
		return errors.New("did not receive expected size of ed25591 random")
	}
	key := ed25519.NewKeyFromSeed(cb)
	c.ed25519 = &key
	c.Algorithm = Ed25591
	return
}

// Ed25519PublicKey returns the ed25519.PublicKey of the Certificate.
func (c *Certificate) Ed25519PublicKey() (key *ed25519.PublicKey, err error) {
	k, ok := c.ed25519.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("unable to cast to ed25519 public key")
	}
	return &k, nil
}

// Ed25519PublicCryptoKey returns the uncasted crypto.PublicKey of the Certificate.
func (c *Certificate) Ed25519PublicCryptoKey() (key crypto.PublicKey) {
	return c.ed25519.Public()
}

func (c *Certificate) Ed25519ToPem() (p *pem.Block, err error) {
	if c.ed25519 == nil {
		return nil, errPrivateKeyCannotBeNil
	}

	der, err := x509.MarshalPKCS8PrivateKey(*c.ed25519)
	if err != nil {
		return
	}
	return &pem.Block{
		Type:  PrivateKeyKey,
		Bytes: der,
	}, nil
}

func (c *Certificate) Ed25519() *ed25519.PrivateKey {
	return c.ed25519
}
