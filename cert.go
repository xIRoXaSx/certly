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
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"

	"cert2go/pkg/assertion"

	"gorm.io/gorm"
)

const (
	CertificateKey   = "CERTIFICATE"
	PrivateKeyKey    = "PRIVATE KEY"
	EcPrivateKeyKey  = "EC PRIVATE KEY"
	RsaPrivateKeyKey = "RSA PRIVATE KEY"
	DerKey           = "DER"
	PemKey           = "PEM"

	// MaxSANLen is not an actual RFC5280 constraint, 4096 should suffice.
	MaxSANLen                    = 4096
	MaxDomainSliceLen            = 20
	RFC5280SerialNumberLen       = 64
	RFC5280CommonNameLen         = 64
	RFC5280CountryLen            = 2
	RFC5280OrganizationLen       = 64
	RFC5280OrganizationalUnitLen = 64
	RFC5280StateLen              = 128
	RFC5280LocalityLen           = 128
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
	IsUnsafe bool
	// IsCA indicates whether the certificate is a certificate authority or not.
	IsCA            bool
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
	CommonName         string   `json:"CommonName"`
	Organization       string   `json:"Organization"`
	OrganizationalUnit string   `json:"OrganizationalUnit"`
	Country            string   `json:"Country"`
	State              string   `json:"State"`
	Locality           string   `json:"Locality"`
	DNSNames           []string `json:"DNSNames"`
	IsCA               bool     `json:"IsCA"`
	Expiration
}

type Expiration struct {
	NotBefore time.Time `json:"NotBefore"`
	NotAfter  time.Time `json:"NotAfter"`
}

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

// CreatePrivateKey generates a private key for the certificate from keyType.
// The keyType is built via the syntax {{Algorithm}}.{{Option}}.
// The option can be omitted if the type does not have any option.
// Examples: RSA.4096, ECDSA.P521, ED25519.
func (c *Certificate) CreatePrivateKey(keyType string) (err error) {
	// Algorithm and option may only take up to 10 bytes.
	err = assertion.AssertWithinRange(len(keyType), 7, 10)
	if err != nil {
		return errors.New("no such algorithm")
	}

	opts := strings.Split(keyType, ".")
	switch strings.ToUpper(opts[0]) {
	case AlgorithmToString(Rsa):
		err = assertion.AssertExactly(len(opts), 2)
		if err != nil {
			return fmt.Errorf("%v: unable to retrieve algorithm size", err)
		}
		var size RsaSize
		size, err = parseRsaSize(opts[1])
		if err != nil {
			return err
		}
		err = c.CreateRsaPrivateKey(size)

	case AlgorithmToString(Ecdsa):
		err = assertion.AssertExactly(len(opts), 2)
		if err != nil {
			return fmt.Errorf("%v: unable to retrieve algorithm size", err)
		}
		var size Curve
		size, err = parseEcdsaSize(opts[1])
		if err != nil {
			return err
		}
		err = c.CreateEcdsaPrivateKey(size)

	case AlgorithmToString(Ed25591):
		err = c.CreateEd25519PrivateKey()

	default:
		return errors.New("no such algorithm")
	}
	return
}

// New creates a new Certificate type.
// The returned crt is validated via Certificate.ValidateTemplate.
func New(opts *Options) (crt *Certificate, err error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}

	var (
		usage    = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
		extUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	)
	if !opts.IsCA {
		usage = x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment
	} else {
		extUsage = append(extUsage, x509.ExtKeyUsageClientAuth)
	}
	limit := new(big.Int).Lsh(big.NewInt(1), RFC5280SerialNumberLen)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return
	}
	crt = &Certificate{
		IsCA: opts.IsCA,
		mx:   &sync.Mutex{},
		template: &x509.Certificate{
			SerialNumber:          serial,
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
	err = crt.ValidateTemplate()
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
		return ErrNotOfAesLength
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
		return ErrNotOfAesLength
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
	err = renewed.ValidateTemplate()
	if err != nil {
		return
	}
	if c == sc {
		err = renewed.SignSelf()
	} else {
		err = renewed.SignWith(sc)
	}
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

func ParseX509(b []byte) (crt *x509.Certificate, err error) {
	return x509.ParseCertificate(b)
}

// ValidateTemplate validates the certificate's template via RFC5280.
// Source: https://www.ietf.org/rfc/rfc5280.txt.
func (c *Certificate) ValidateTemplate() (err error) {
	// Time validation.
	err = ValidateTime(c.template.NotBefore)
	if err != nil {
		return fmt.Errorf("%v: %s", err, "not before")
	}
	err = ValidateTime(c.template.NotAfter)
	if err != nil {
		return fmt.Errorf("%v: %s", err, "not after")
	}

	// General and Subject Alternative Name validation.
	err = ValidateSerialNumber(c.template.SerialNumber)
	if err != nil {
		return fmt.Errorf("%v: %s", err, "serial number")
	}
	err = ValidateSubjectAltName(c.template.DNSNames)
	if err != nil {
		return fmt.Errorf("%v: %s", err, "subject alternative name slice size")
	}

	// Subject validation.
	err = ValidateCommonName(c.template.Subject.CommonName)
	if err != nil {
		return fmt.Errorf("%v: %s", err, "common name length")
	}
	err = ValidateOrganization(c.template.Subject.Organization[0])
	if err != nil {
		return fmt.Errorf("%v: %s", err, "organization name length")
	}
	err = ValidateOrganizationalUnit(c.template.Subject.OrganizationalUnit[0])
	if err != nil {
		return fmt.Errorf("%v: %s", err, "organizational unit name length")
	}
	err = ValidateCountry(c.template.Subject.Country[0])
	if err != nil {
		return fmt.Errorf("%v: %s", err, "country name length")
	}
	err = ValidateState(c.template.Subject.Province[0])
	if err != nil {
		return fmt.Errorf("%v: %s", err, "state name length")
	}
	err = ValidateLocality(c.template.Subject.Locality[0])
	if err != nil {
		return fmt.Errorf("%v: %s", err, "locality name length")
	}
	return
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
		Expiration:         Expiration{NotBefore: crt.NotBefore, NotAfter: crt.NotAfter},
	}, nil
}

// IsOfAesLength returns true if len is 16, 24 or 32.
func IsOfAesLength(len int) bool {
	return len == 16 || len == 24 || len == 32
}
