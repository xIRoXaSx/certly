package crypt

import (
	"testing"

	r "github.com/stretchr/testify/require"
)

func TestCrypt(t *testing.T) {
	data := "Some test data"
	pass := "SomePass"
	c := New([]byte(data), nil, nil)
	defer func() {
		c.Release()
		r.Nil(t, c.data)
		r.Nil(t, c.decrypted)
		r.Nil(t, c.encrypted)
		r.Nil(t, c.salt)
		r.Nil(t, c.nonce)
	}()

	r.NoError(t, c.Encrypt([]byte(pass)))
	r.NotNil(t, c.encrypted)
	r.NotNil(t, c.salt)
	r.NotNil(t, c.nonce)
	r.Nil(t, c.decrypted)
	r.Nil(t, c.data)
	r.Equal(t, c.salt, c.Salt())
	r.Equal(t, c.nonce, c.Nonce())
	r.Equal(t, c.encrypted, c.Encrypted())

	c = New(c.Encrypted(), c.Salt(), c.Nonce())
	r.NoError(t, c.Decrypt([]byte(pass)))
	r.Exactly(t, []byte(data), c.decrypted)
	r.Exactly(t, c.decrypted, c.Decrypted())
	r.Nil(t, c.encrypted)
	r.NotNil(t, c.salt)
	r.NotNil(t, c.nonce)
	r.NotNil(t, c.decrypted)
	r.Nil(t, c.data)
	r.Equal(t, c.salt, c.Salt())
	r.Equal(t, c.nonce, c.Nonce())
	r.Equal(t, c.decrypted, c.Decrypted())
}
