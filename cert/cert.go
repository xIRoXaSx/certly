package cert

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

	"github.com/xiroxasx/certly/cert/assertion"
	"golang.org/x/crypto/pbkdf2"
)

const (
	CertificateKey   = "CERTIFICATE"
	PrivateKeyKey    = "PRIVATE KEY"
	EcPrivateKeyKey  = "EC PRIVATE KEY"
	RsaPrivateKeyKey = "RSA PRIVATE KEY"

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
	ID uint64
	// Name is the user specified name for this certificate.
	Name string
	// PublicKey is the public certificate in DER format.
	PublicKey []byte
	// PrivateKey is the private key of this Certificate and may be encrypted.
	PrivateKey []byte
	// Algorithm is the used private key algorithm.
	Algorithm Algorithm
	// SignerID is the ID of the signing Certificate.
	SignerID uint64
	// IsCA indicates whether the certificate is a certificate authority or not.
	IsCA            bool
	Iterations      uint
	Nonce           []byte
	Salt            []byte
	releasable      bool
	isSigned        bool
	privateKeyBlock Block
	ecdsa           *ecdsa.PrivateKey
	rsa             *rsa.PrivateKey
	ed25519         *ed25519.PrivateKey
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
	Data      []byte
}

// New creates a new RFC5280 compliant Certificate.
// The returned c is validated via Certificate.ValidateTemplate.
func New(opts *Options) (c *Certificate, err error) {
	return newCert(opts)
}

// NewWithIdentifier is like New but assigns the given name and id as well.
// The returned c is validated via Certificate.ValidateTemplate.
func NewWithIdentifier(id uint64, name string, opts *Options) (c *Certificate, err error) {
	c, err = newCert(opts)
	if err != nil {
		return
	}
	err = ValidateCommonName(name)
	if err != nil {
		return
	}
	c.ID = id
	c.Name = name
	return
}

func newCert(opts *Options) (c *Certificate, err error) {
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
	cn := opts.CommonName
	c = &Certificate{
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
				CommonName:         cn,
			},
		},
	}
	err = c.ValidateTemplate()
	if err != nil {
		return
	}
	c.Name = cn
	return
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

	var (
		pub  crypto.PublicKey
		priv crypto.PrivateKey
	)
	defer func() {
		pub = nil
		priv = nil
	}()

	sc.mx.Lock()
	defer sc.mx.Unlock()

	if sc != c {
		c.mx.Lock()
		defer c.mx.Unlock()
	}

	certs := []*Certificate{c, sc}
	for _, cert := range certs {
		if cert.template == nil {
			cert.template, err = x509.ParseCertificate(cert.PublicKey)
			if err != nil {
				return err
			}
		}
	}

	if sc.rsa == nil && sc.ecdsa == nil && sc.ed25519 == nil {
		err = sc.loadRawPrivateKey(sc.PrivateKey)
		if err != nil {
			return
		}
	}

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

	c.isSigned = true
	c.PublicKey = der
	c.SignerID = sc.ID
	return
}

// GetPrivateKey gets the private key.
// The returned Block contains any of the available private key forms (rsa, ...).
// Note that the private key might be encrypted.
func (c *Certificate) GetPrivateKey() Block {
	return c.privateKeyBlock
}

// SetUnsafePrivateKey sets the private key without encrypting it.
func (c *Certificate) SetUnsafePrivateKey() (err error) {
	var pb pem.Block
	c.mx.Lock()
	defer func() {
		c.mx.Unlock()
		pb = pem.Block{}
		c.autoRelease()
	}()

	pb, err = c.getPrivateKeyPem()
	if err != nil {
		return
	}
	c.PrivateKey = pb.Bytes
	return
}

// EncryptPrivateKey encrypts the private key with the given pass.
func (c *Certificate) EncryptPrivateKey(pass []byte) (err error) {
	var (
		key  []byte
		salt []byte
		enc  []byte
		blk  cipher.Block
		pb   pem.Block
	)
	defer func() {
		// Zero values.
		b := [][]byte{key, salt, enc}
		for i := range b {
			for j := range b[i] {
				b[i][j] = 0
			}
			b[i] = nil
		}
		blk = nil
		pb = pem.Block{}
	}()

	c.mx.Lock()
	defer func() {
		c.mx.Unlock()
		c.autoRelease()
	}()

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

	pb, err = c.getPrivateKeyPem()
	if err != nil {
		return
	}
	enc = gcm.Seal(nonce, nonce, pb.Bytes, nil)

	c.Salt = make([]byte, len(salt))
	c.Nonce = make([]byte, len(nonce))
	c.PrivateKey = make([]byte, len(enc))
	copy(c.Salt, salt)
	copy(c.Nonce, nonce)
	copy(c.PrivateKey, enc)
	return
}

func (c *Certificate) getPrivateKeyPem() (pb pem.Block, err error) {
	var pemBlk *pem.Block
	if c.rsa != nil {
		pemBlk, err = c.RsaToPem()
	} else if c.ecdsa != nil {
		pemBlk, err = c.EcdsaToPem()
	} else {
		pemBlk, err = c.Ed25519ToPem()
	}
	pb = *pemBlk
	return
}

// LoadPrivateKey loads the private key.
// Note that the private key might be encrypted.
// Get the key via *Certificate.GetPrivateKey or *Certificate.PrivateKey.
func (c *Certificate) LoadPrivateKey() (err error) {
	if c.mx == nil {
		c.mx = &sync.Mutex{}
	}
	c.mx.Lock()
	defer c.mx.Unlock()

	c.privateKeyBlock = Block{
		Algorithm: c.Algorithm,
		Data:      c.PrivateKey,
	}
	if c.IsUnsafe() {
		// Private key does not need to be decrypted, load corresponding field directly.
		err = c.loadRawPrivateKey(c.PrivateKey)
	}
	return
}

// DecryptPrivateKey decrypts the private key.
func (c *Certificate) DecryptPrivateKey(pass []byte) (err error) {
	defer func() {
		err = mapToCertError(err)
	}()

	if len(c.privateKeyBlock.Data) == 0 {
		// Ensure that the private key is loaded.
		err = c.LoadPrivateKey()
		if err != nil {
			return
		}
	}

	c.mx.Lock()
	defer c.mx.Unlock()

	var (
		derivedKey []byte
		raw        []byte
		gcm        cipher.AEAD
		blk        cipher.Block
	)
	defer func() {
		// Zero values.
		b := [][]byte{derivedKey, raw}
		for i := range b {
			for j := range b[i] {
				b[i][j] = 0
			}
			b[i] = nil
		}
		gcm = nil
		blk = nil
	}()

	enc := c.privateKeyBlock.Data
	salt := c.Salt
	nonce := c.Nonce
	derivedKey, _ = deriveKey(pass, salt)
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
	err = c.loadRawPrivateKey(raw)
	return
}

// loadRawPrivateKey loads the corresponding private key field.
// The caller must ensure to lock Certificate.mx.
func (c *Certificate) loadRawPrivateKey(raw []byte) (err error) {
	var key interface{}

	// Work with a copy of the raw key.
	rawKey := make([]byte, len(raw))
	_ = copy(rawKey, raw)
	defer func() {
		// Zero values.
		for i := range rawKey {
			rawKey[i] = 0
		}
		rawKey = nil
		key = nil
	}()

	var ok bool
	switch c.Algorithm {
	case Rsa:
		key, err = x509.ParsePKCS8PrivateKey(rawKey)
		if err != nil {
			return
		}
		c.rsa, ok = key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast rsa private key")
		}

	case Ecdsa:
		key, err = x509.ParseECPrivateKey(rawKey)
		if err != nil {
			return
		}
		c.ecdsa, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("unable to cast ecdsa private key")
		}

	case Ed25591:
		key, err = x509.ParsePKCS8PrivateKey(rawKey)
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

// PrivateKeyBlock returns the private key as a pem.Block.
func (c *Certificate) PrivateKeyBlock() (blk pem.Block, err error) {
	var keyType string

	switch c.Algorithm {
	case Rsa:
		keyType = RsaPrivateKeyKey
		blk.Bytes, err = x509.MarshalPKCS8PrivateKey(c.Rsa())

	case Ecdsa:
		keyType = EcPrivateKeyKey
		blk.Bytes, err = x509.MarshalECPrivateKey(c.Ecdsa())

	case Ed25591:
		keyType = PrivateKeyKey
		blk.Bytes, err = x509.MarshalPKCS8PrivateKey(*c.Ed25519())

	default:
		err = ErrNoSuchAlgorithm
		return
	}
	if err != nil {
		return
	}
	blk.Type = keyType
	return
}

// Release releases private key data.
// After calling, the private key needs to be loaded / decrypted again.
func (c *Certificate) Release() {
	c.release()
}

// EnableAutoRelease raises Certificate.Release automatically after
// calling Certificate.EncryptPrivateKey or Certificate.SetUnsafePrivateKey.
func (c *Certificate) EnableAutoRelease() *Certificate {
	c.releasable = true
	return c
}

func (c *Certificate) autoRelease() {
	if c.releasable {
		c.release()
	}
}

// release releases data stored inside the unexported private key fields.
func (c *Certificate) release() {
	c.mx.Lock()
	defer c.mx.Unlock()

	if c.rsa != nil {
		*c.rsa = rsa.PrivateKey{}
		c.rsa = nil
	}
	if c.ecdsa != nil {
		*c.ecdsa = ecdsa.PrivateKey{}
		c.ecdsa = nil
	}
	if c.ed25519 != nil {
		*c.ed25519 = ed25519.PrivateKey{}
		c.ed25519 = nil
	}
	for i := range c.privateKeyBlock.Data {
		c.privateKeyBlock.Data[i] = 0
	}
	c.privateKeyBlock.Data = nil
}

func (c *Certificate) IsUnsafe() bool {
	return len(c.Salt) == 0 && len(c.Nonce) == 0
}

// Renew renews the Certificate with the provided options.
// The caller must ensure, that the private key of sc is decrypted.
func (c *Certificate) Renew(opts *Options, sc *Certificate) (renewed *Certificate, err error) {
	renewed, err = New(opts)
	if err != nil {
		return
	}
	defer func() {
		if err == nil {
			renewed.Iterations++
		}
	}()

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
	dst.PrivateKey = c.PrivateKey
	dst.Iterations = c.Iterations
	if copyUnexported {
		dst.rsa = c.rsa
		dst.ecdsa = c.ecdsa
		dst.ed25519 = c.ed25519
	}
	return
}

func (c *Certificate) ParseX509() (crt *x509.Certificate, err error) {
	return x509.ParseCertificate(c.PublicKey)
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

func ParseX509(b []byte) (crt *x509.Certificate, err error) {
	return x509.ParseCertificate(b)
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
