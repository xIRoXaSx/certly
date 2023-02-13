package cert

import (
	"bytes"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// CreatePgpPrivateKey creates a PGP private key.
func (c *Certificate) CreatePgpPrivateKey(name, comment, email string) (err error) {
	var e *openpgp.Entity
	e, err = openpgp.NewEntity(name, comment, email, nil)
	if err != nil {
		return
	}

	for _, id := range e.Identities {
		err = id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return
		}
	}

	buf := &bytes.Buffer{}
	pubW, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}
	defer func() {
		cErr := pubW.Close()
		if err == nil {
			err = cErr
		}
	}()

	err = e.Serialize(pubW)
	if err != nil {
		return
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	c.PublicKey = buf.Bytes()
	c.pgp = e.PrivateKey
	c.Algorithm = Pgp
	return
}

type gpgReader struct {
}
