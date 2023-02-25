package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// CreatePgpPrivateKey creates a PGP private key.
func (c *Certificate) CreatePgpPrivateKey(size RsaSize) (err error) {
	key, err := rsa.GenerateKey(rand.Reader, int(size))
	if err != nil {
		return
	}

	buf := bytes.Buffer{}
	privW, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return
	}
	privKey := packet.NewRSAPrivateKey(time.Now(), key)
	err = privKey.Serialize(privW)
	if err != nil {
		return
	}
	err = privW.Close()
	if err != nil {
		return
	}

	pubBuf := bytes.Buffer{}
	pubW, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}
	pubKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	err = pubKey.Serialize(pubW)
	if err != nil {
		return
	}
	err = pubW.Close()
	if err != nil {
		return
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	c.PublicKey = pubBuf.Bytes()
	c.pgp = privKey
	c.Algorithm = Pgp
	return
}

func (c *Certificate) Pgp() *packet.PrivateKey {
	return c.pgp
}

func (c *Certificate) PgpToPem() (p *pem.Block, err error) {
	if c.pgp == nil {
		return nil, errPrivateKeyCannotBeNil
	}

	buf := &bytes.Buffer{}
	privW, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return
	}
	err = c.pgp.Serialize(privW)
	if err != nil {
		return
	}
	err = privW.Close()
	if err != nil {
		return
	}

	body, err := io.ReadAll(buf)
	if err != nil {
		return
	}

	return &pem.Block{
		Type:  PgpPrivateKeyKey,
		Bytes: body,
	}, nil
}

func (c *Certificate) parsePgpPrivateKey(key []byte) (k *packet.PrivateKey, err error) {
	blk, err := armor.Decode(bytes.NewReader(key))
	if err != nil {
		return
	}
	if blk.Type != openpgp.PrivateKeyType {
		err = errors.New("invalid pgp private key")
		return
	}

	reader := packet.NewReader(blk.Body)
	pack, err := reader.Next()
	if err != nil {
		return
	}
	k, ok := pack.(*packet.PrivateKey)
	if !ok {
		err = errors.New("unable to parse to pgp private key")
	}
	return
}
