package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"

	"github.com/xiroxasx/certly"
	"golang.org/x/crypto/pbkdf2"
)

type Crypt struct {
	data      []byte
	decrypted []byte
	encrypted []byte
	salt      []byte
	nonce     []byte
	mx        *sync.Mutex
}

func New(data, salt, nonce []byte) *Crypt {
	return &Crypt{
		data:  data,
		salt:  salt,
		nonce: nonce,
		mx:    &sync.Mutex{},
	}
}

func (c *Crypt) Encrypt(pass []byte) (err error) {
	var (
		key  []byte
		salt []byte
		blk  cipher.Block
	)
	defer func() {
		// Zero values.
		b := [][]byte{pass, c.data, key}
		for i := range b {
			for j := range b[i] {
				b[i][j] = 0
			}
			b[i] = nil
		}
		blk = nil
		c.data = nil
		pass = nil
	}()

	c.mx.Lock()
	defer c.mx.Unlock()

	key, salt = deriveKey(pass, nil)
	blk, err = aes.NewCipher(key)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)

	if err != nil {
		return
	}
	c.encrypted = gcm.Seal(nonce, nonce, c.data, nil)
	c.salt = salt
	c.nonce = nonce
	return
}

func (c *Crypt) Decrypt(pass []byte) (err error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	var (
		enc   []byte
		salt  []byte
		nonce []byte

		derivedKey []byte
		raw        []byte
		gcm        cipher.AEAD
		blk        cipher.Block
	)
	defer func() {
		// Zero values.
		b := [][]byte{derivedKey, raw, pass, enc, salt, nonce}
		for i := range b {
			for j := range b[i] {
				b[i][j] = 0
			}
			b[i] = nil
		}
		gcm = nil
		blk = nil
	}()

	enc = make([]byte, len(c.data))
	salt = make([]byte, len(c.salt))
	nonce = make([]byte, len(c.nonce))
	copy(enc, c.data)
	copy(salt, c.salt)
	copy(nonce, c.nonce)
	derivedKey, _ = certly.DeriveKey(pass, salt)
	blk, err = aes.NewCipher(derivedKey)
	if err != nil {
		return
	}
	gcm, err = cipher.NewGCM(blk)
	if err != nil {
		return
	}

	raw, err = gcm.Open(nil, nonce, enc[gcm.NonceSize():], nil)
	if err != nil {
		return
	}
	c.decrypted = make([]byte, len(raw))
	copy(c.decrypted, raw)
	return
}

func (c *Crypt) Encrypted() []byte {
	return c.encrypted
}

func (c *Crypt) Decrypted() []byte {
	return c.decrypted
}

func (c *Crypt) Salt() []byte {
	return c.salt
}

func (c *Crypt) Nonce() []byte {
	return c.nonce
}

func (c *Crypt) Release() {
	fields := [][]byte{c.data, c.decrypted, c.encrypted, c.salt, c.nonce}
	for i := range fields {
		for j := range fields[i] {
			fields[i][j] = 0
		}
		fields[i] = nil
	}
}

func deriveKey(phrase []byte, salt []byte) (key, s []byte) {
	if len(salt) == 0 {
		salt = make([]byte, 8)
		_, err := rand.Read(salt)
		if err != nil {
			return
		}
	}
	return pbkdf2.Key(phrase, salt, 4096, 32, sha256.New), salt
}
