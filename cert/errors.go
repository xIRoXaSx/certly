package cert

import (
	"errors"
)

var (
	ErrNoSuchAlgorithm       = errors.New("no such algorithm implemented")
	ErrCipherMsgAuthFailed   = errors.New("message authentication failed")
	errCertToSignCannotBeNil = errors.New("certificate to sign cannot be nil")
	errSignerCannotBeNil     = errors.New("signer cannot be nil")
	errPrivateKeyCannotBeNil = errors.New("private key cannot be nil")
)

func mapToCertError(err error) error {
	if err == nil {
		return nil
	}

	if err.Error() == "cipher: message authentication failed" {
		return ErrCipherMsgAuthFailed
	}
	return err
}
