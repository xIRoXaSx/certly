package cert

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	CertificateKey   = "CERTIFICATE"
	PrivateKeyKey    = "PRIVATE KEY"
	EcPrivateKeyKey  = "EC PRIVATE KEY"
	RsaPrivateKeyKey = "RSA PRIVATE KEY"
)

type Certificate struct {
	gorm.Model
	// Name is the user specified name for this certificate.
	Name string
	// Der is the public certificate in DER format.
	Der string
	// EncryptedPrivateKey is the raw encrypted private key.
	EncryptedPrivateKey string
	// Algorithm is the used private key algorithm.
	Algorithm Algorithm
	// SignerID is the ID of the signing Certificate.
	SignerID uint
	// IsUnsafe is weather the certificate's private key is encrypted or not.
	IsUnsafe        bool
	isSigned        bool
	privateKeyBlock Block
	ecdsa           *ecdsa.PrivateKey
	rsa             *rsa.PrivateKey
	ed25519         *ed25519.PrivateKey
	privateKey      *crypto.PrivateKey
	template        *x509.Certificate
	mx              *sync.Mutex
}

type Options struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	DNSNames           []string
	IsCA               bool
	NotBefore          time.Time
	NotAfter           time.Time
}

type Curve uint

const (
	P224 Curve = iota
	P256
	P384
	P521
)

type Algorithm uint

const (
	None Algorithm = iota
	Rsa
	Ecdsa
	Ed25591
)

func AlgorithmToString(a Algorithm) string {
	switch a {
	case Rsa:
		return "RSA"

	case Ecdsa:
		return "ECDSA"

	case Ed25591:
		return "ED25591"

	default:
		return "None"
	}
}

type Block struct {
	Algorithm Algorithm
	Data      string
}

// New creates a new Certificate type.
func New(opts *Options) (crt *Certificate, err error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}

	var (
		usage    = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	)
	if !opts.IsCA {
		usage = x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment
	} else {
		extUsage = append(extUsage, x509.ExtKeyUsageClientAuth)
	}
	crt = &Certificate{
		mx: &sync.Mutex{},
		template: &x509.Certificate{
			SerialNumber:          big.NewInt(int64(uuid.New().ID())),
			DNSNames:              opts.DNSNames,
			KeyUsage:              usage,
			ExtKeyUsage:           extUsage,
			BasicConstraintsValid: true,
			NotBefore:             opts.NotBefore,
			NotAfter:              opts.NotAfter,
			IsCA:                  opts.IsCA,
			Subject: pkix.Name{
				Country:            []string{opts.Country},
				Organization:       []string{opts.Organization},
				OrganizationalUnit: []string{opts.OrganizationalUnit},
				Locality:           []string{opts.Locality},
				Province:           []string{opts.State},
				CommonName:         opts.CommonName,
			},
		},
	}
	return
}

// SignSelf signs the certificate itself.
func (c *Certificate) SignSelf() (err error) {
	return c.sign(c)
}

// SignWith signs the certificate with the given *Certificate.
func (c *Certificate) SignWith(sc *Certificate) (err error) {
	return c.sign(sc)
}

func (c *Certificate) sign(sc *Certificate) (err error) {
	if c == nil {
		return errCertCannotBeNil
	}
	if sc == nil {
		return errSignerCannotBeNil
	}
	if c.isSigned {
		return errors.New("certificate is already signed")
	}
	if sc.ecdsa == nil && sc.rsa == nil && sc.ed25519 == nil {
		return errors.New("private key must not be nil")
	}

	certs := []*Certificate{c, sc}
	for _, cert := range certs {
		if cert.template == nil {
			cert.template, err = x509.ParseCertificate([]byte(cert.Der))
			if err != nil {
				return err
			}
		}
	}

	var (
		pub  crypto.PublicKey
		priv crypto.PrivateKey
	)
	if sc.rsa != nil {
		pub = sc.RsaPublicKey()
		priv = sc.rsa
	} else if sc.ecdsa != nil {
		pub = sc.EcdsaPublicKey()
		priv = sc.ecdsa
	} else {
		pub = sc.Ed25519PublicCryptoKey()
		priv = sc.ed25519
	}

	der, err := x509.CreateCertificate(rand.Reader, c.template, sc.template, pub, priv)
	if err != nil {
		return
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	c.isSigned = true
	c.Der = string(der)
	c.SignerID = sc.ID
	return
}

// GetEncryptedPrivateKey gets the encrypted private key.
func (c *Certificate) GetEncryptedPrivateKey() Block {
	return c.privateKeyBlock
}

func (c *Certificate) SetUnsafePrivateKey() (err error) {
	c.mx.Lock()
	defer c.mx.Unlock()

	var pemBlk *pem.Block
	if c.rsa != nil {
		pemBlk, err = c.RsaToPem()
	} else if c.ecdsa != nil {
		pemBlk, err = c.EcdsaToPem()
	} else {
		pemBlk, err = c.Ed25519ToPem()
	}
	if err != nil {
		return
	}
	c.EncryptedPrivateKey = string(pemBlk.Bytes)
	c.IsUnsafe = true
	return
}

// EncryptPrivateKey encrypts the private key.
// Needs either a 16, 24 or 32 byte long passphrase.
func (c *Certificate) EncryptPrivateKey(pass string) (err error) {
	if !IsOfAesLength(len(pass)) {
		return errNotOfAesLength
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	blk, err := aes.NewCipher([]byte(pass))
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

	var pemBlk *pem.Block
	if c.rsa != nil {
		pemBlk, err = c.RsaToPem()
	} else if c.ecdsa != nil {
		pemBlk, err = c.EcdsaToPem()
	} else {
		pemBlk, err = c.Ed25519ToPem()
	}
	if err != nil {
		return
	}
	enc := gcm.Seal(nonce, nonce, pemBlk.Bytes, nil)
	c.EncryptedPrivateKey = string(enc)
	return
}

// DecryptPrivateKey decrypts the private key.
func (c *Certificate) DecryptPrivateKey(pass string, algo Algorithm) (err error) {
	if !IsOfAesLength(len(pass)) {
		return errNotOfAesLength
	}

	if len(c.privateKeyBlock.Data) == 0 {
		if c.IsUnsafe {
			err = c.LoadUnsafePrivateKey()
		} else {
			err = c.LoadPrivateKey()
		}
		if err != nil {
			return
		}
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	blk, err := aes.NewCipher([]byte(pass))
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return
	}

	enc := c.privateKeyBlock.Data
	nonce := enc[:gcm.NonceSize()]
	enc = enc[gcm.NonceSize():]
	raw, err := gcm.Open(nil, []byte(nonce), []byte(enc), nil)
	if err != nil {
		return
	}

	var (
		key interface{}
		ok  bool
	)
	switch algo {
	case Rsa:
		key, err = x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return
		}
		c.rsa, ok = key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast rsa private key")
		}

	case Ecdsa:
		key, err = x509.ParseECPrivateKey(raw)
		if err != nil {
			return
		}
		c.ecdsa, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast ecdsa private key")
		}

	case Ed25591:
		key, err = x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return
		}
		var k ed25519.PrivateKey
		k, ok = key.(ed25519.PrivateKey)
		if !ok {
			return errors.New("unable to cast ed25519 private key")
		}
		c.ed25519 = &k

	default:
		return ErrNoSuchAlgorithm
	}

	return
}

// LoadPrivateKey loads the encrypted private key's Block type.
// Get the encrypted key via *Certificate.GetEncryptedPrivateKey.
func (c *Certificate) LoadPrivateKey() (err error) {
	if c.mx == nil {
		c.mx = &sync.Mutex{}
	}
	c.mx.Lock()
	defer c.mx.Unlock()

	c.privateKeyBlock = Block{
		Algorithm: c.Algorithm,
		Data:      c.EncryptedPrivateKey,
	}
	return
}

// LoadUnsafePrivateKey loads the unsafe private key.
func (c *Certificate) LoadUnsafePrivateKey() (err error) {
	if c.mx == nil {
		c.mx = &sync.Mutex{}
	}
	c.mx.Lock()
	defer c.mx.Unlock()

	var (
		key interface{}
		ok  bool
	)
	switch c.Algorithm {
	case Rsa:
		key, err = x509.ParsePKCS8PrivateKey([]byte(c.EncryptedPrivateKey))
		if err != nil {
			return
		}
		c.rsa, ok = key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast rsa private key")
		}

	case Ecdsa:
		key, err = x509.ParseECPrivateKey([]byte(c.EncryptedPrivateKey))
		if err != nil {
			return
		}
		c.ecdsa, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast ecdsa private key")
		}

	case Ed25591:
		key, err = x509.ParsePKCS8PrivateKey([]byte(c.EncryptedPrivateKey))
		if err != nil {
			return
		}
		var k ed25519.PrivateKey
		k, ok = key.(ed25519.PrivateKey)
		if !ok {
			return errors.New("unable to cast rsa private key")
		}
		c.ed25519 = &k

	default:
		return ErrNoSuchAlgorithm
	}
	return
}

// PrivateKeyBlock converts the private key into a *pem.Block.
func (c *Certificate) PrivateKeyBlock() (blk *pem.Block, err error) {
	var (
		keyType string
		b       []byte
	)
	switch c.Algorithm {
	case Rsa:
		keyType = RsaPrivateKeyKey
		b, err = x509.MarshalPKCS8PrivateKey(c.Rsa())

	case Ecdsa:
		keyType = EcPrivateKeyKey
		b, err = x509.MarshalECPrivateKey(c.Ecdsa())

	case Ed25591:
		keyType = PrivateKeyKey
		b, err = x509.MarshalPKCS8PrivateKey(*c.Ed25519())

	default:
		return nil, ErrNoSuchAlgorithm
	}
	if err != nil {
		return
	}
	return &pem.Block{
		Type:  keyType,
		Bytes: b,
	}, nil
}

// Renew renews the Certificate with the provided options.
// The caller must ensure, that the private key of sc is decrypted.
func (c *Certificate) Renew(opts *Options, sc *Certificate) (renewed *Certificate, err error) {
	renewed, err = New(opts)
	if err != nil {
		return
	}
	c.CopyPropertiesTo(renewed, true)
	err = renewed.SignWith(sc)
	return
}

func (c *Certificate) CopyPropertiesTo(dst *Certificate, copyUnexported bool) {
	dst.ID = c.ID
	dst.Name = c.Name
	dst.Algorithm = c.Algorithm
	dst.SignerID = c.SignerID
	dst.EncryptedPrivateKey = c.EncryptedPrivateKey
	if copyUnexported {
		dst.rsa = c.rsa
		dst.ecdsa = c.ecdsa
		dst.ed25519 = c.ed25519
	}
	return
}

func (c *Certificate) ParseX509() (crt *x509.Certificate, err error) {
	return x509.ParseCertificate([]byte(c.Der))
}

func ParseCertificateOptions(crt *x509.Certificate) (opts *Options, err error) {
	firstOrEmpty := func(opt []string) string {
		if len(opt) == 0 {
			return ""
		}
		return opt[0]
	}
	return &Options{
		CommonName:         crt.Subject.CommonName,
		Organization:       firstOrEmpty(crt.Subject.Organization),
		OrganizationalUnit: firstOrEmpty(crt.Subject.OrganizationalUnit),
		Country:            firstOrEmpty(crt.Subject.Country),
		State:              firstOrEmpty(crt.Subject.Province),
		Locality:           firstOrEmpty(crt.Subject.Locality),
		DNSNames:           crt.DNSNames,
		IsCA:               crt.IsCA,
		NotBefore:          crt.NotBefore,
		NotAfter:           crt.NotAfter,
	}, nil
}

// IsOfAesLength returns true if len is 16, 24 or 32.
func IsOfAesLength(len int) bool {
	return len == 16 || len == 24 || len == 32
}
