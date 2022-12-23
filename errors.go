package cert

import "errors"

var (
	ErrNoSuchAlgorithm       = errors.New("no such algorithm implemented")
	errNotOfAesLength        = errors.New("passphrase must be one of the following lengths: 16, 24, 32")
	errCertCannotBeNil       = errors.New("certificate to sign cannot be nil")
	errSignerCannotBeNil     = errors.New("signer cannot be nil")
	errPrivateKeyCannotBeNil = errors.New("private key cannot be nil")
)
