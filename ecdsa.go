package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// CreateEcdsaPrivateKey creates an ECDSA private key.
func (c *Certificate) CreateEcdsaPrivateKey(curve Curve) (err error) {
	var cv elliptic.Curve
	switch curve {
	case P224:
		cv = elliptic.P224()
	case P256:
		cv = elliptic.P256()
	case P384:
		cv = elliptic.P384()
	case P521:
		cv = elliptic.P521()
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	c.ecdsa, err = ecdsa.GenerateKey(cv, rand.Reader)
	if err != nil {
		return
	}
	c.Algorithm = Ecdsa
	return
}

// EcdsaPublicKey returns the ecdsa.PublicKey of the Certificate.
func (c *Certificate) EcdsaPublicKey() (key *ecdsa.PublicKey) {
	return &c.ecdsa.PublicKey
}

func (c *Certificate) EcdsaToPem() (p *pem.Block, err error) {
	if c.ecdsa == nil {
		return nil, errPrivateKeyCannotBeNil
	}

	der, err := x509.MarshalECPrivateKey(c.ecdsa)
	if err != nil {
		return
	}
	return &pem.Block{
		Type:  EcPrivateKeyKey,
		Bytes: der,
	}, nil
}

func (c *Certificate) Ecdsa() *ecdsa.PrivateKey {
	return c.ecdsa
}

func ParsePublicEcdsa(c interface{}) (p *ecdsa.PublicKey, err error) {
	pubKey, ok := c.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("unable to parse to ecdsa public key")
	}
	return pubKey, nil
}
