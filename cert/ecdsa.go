package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
)

type Curve uint

const (
	P224 Curve = iota
	P256
	P384
	P521
)

func parseEcdsaSize(curve string) (c Curve, err error) {
	// Replaces the "P" prefix if provided.
	size := strings.Replace(strings.ToUpper(curve), "P", "", 1)
	i, err := strconv.ParseInt(size, 10, 16)
	if err != nil {
		return
	}

	switch i {
	case 224:
		c = P224

	case 256:
		c = P256

	case 384:
		c = P384

	case 521:
		c = P521

	default:
		err = errors.New("no such curve")
	}
	return
}

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
	default:
		return errors.New("no such curve implemented")
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
