package certly

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

func DeriveKey(phrase []byte, salt []byte) (key, s []byte) {
	if len(salt) == 0 {
		salt = make([]byte, 8)
		_, err := rand.Read(salt)
		if err != nil {
			return
		}
	}
	return pbkdf2.Key(phrase, salt, 4096, 32, sha256.New), salt
}
