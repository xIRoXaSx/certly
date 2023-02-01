package cert

import "errors"

var (
	ErrNoSuchAlgorithm       = errors.New("no such algorithm implemented")
	ErrNotOfAesLength        = errors.New("passphrase is not of required length")
	errCertCannotBeNil       = errors.New("certificate to sign cannot be nil")
	errSignerCannotBeNil     = errors.New("signer cannot be nil")
	errPrivateKeyCannotBeNil = errors.New("private key cannot be nil")
)
