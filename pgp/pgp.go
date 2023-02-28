package pgp

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/xiroxasx/certly/cert"
	"github.com/xiroxasx/certly/cert/assertion"
	"github.com/xiroxasx/certly/crypt"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	privateKeyKey = "PGP PRIVATE KEY BLOCK"
)

type Pgp struct {
	ID uint64
	// Name is the user specified name.
	Name string
	// PublicKey is the public key.
	PublicKey []byte
	// PrivateKey is the private key and may be encrypted.
	PrivateKey      []byte
	Nonce           []byte
	Salt            []byte
	opts            Options
	releasable      bool
	isSigned        bool
	privateKeyBlock cert.Block
	pgp             *packet.PrivateKey
	mx              *sync.Mutex
}

type Options struct {
	Size    cert.RsaSize
	Name    string
	Comment string
	Email   string
}

// New creates a new PGP pair.
func New(opts Options) (p *Pgp, err error) {
	return newPgp(opts)
}

func newPgp(opts Options) (p *Pgp, err error) {
	p = &Pgp{mx: &sync.Mutex{}}
	if err != nil {
		return
	}
	err = cert.ValidateCommonName(opts.Name)
	if err != nil {
		return
	}
	p.Name = opts.Name
	p.opts = opts
	return
}

// CreatePrivateKey generates a private key from keyType.
// The keyType is built via the syntax {{Algorithm}}.{{Option}}.
// Examples: RSA.4096, RSA.2048, RSA.1024.
func (p *Pgp) CreatePrivateKey(keyType string) (err error) {
	// Algorithm and option may only take up to 10 bytes.
	err = assertion.AssertWithinRange(len(keyType), 7, 10)
	if err != nil {
		return errors.New("no such algorithm")
	}

	opts := strings.Split(keyType, ".")
	err = assertion.AssertExactly(len(opts), 2)
	if err != nil {
		err = fmt.Errorf("%v: unable to retrieve algorithm size", err)
		return
	}
	size, err := cert.ParseRsaSize(opts[1])
	if err != nil {
		return
	}
	return p.CreatePgpPrivateKey(size)
}

// CreatePgpPrivateKey creates a PGP private key.
func (p *Pgp) CreatePgpPrivateKey(size cert.RsaSize) (err error) {
	e, err := openpgp.NewEntity(p.opts.Name, p.opts.Comment, p.opts.Email, &packet.Config{
		Rand:    rand.Reader,
		RSABits: int(size),
	})
	if err != nil {
		return
	}

	for _, id := range e.Identities {
		err = id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return
		}
	}
	//key, err := rsa.GenerateKey(rand.Reader, int(size))
	//if err != nil {
	//	return
	//}

	buf := bytes.Buffer{}
	privW, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return
	}
	//privKey := packet.NewRSAPrivateKey(time.Now(), key)
	//err = e.PrivateKey.Serialize(privW)
	err = e.SerializePrivate(privW, nil)
	if err != nil {
		return
	}
	err = privW.Close()
	if err != nil {
		return
	}

	pubBuf := bytes.Buffer{}
	pubW, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}
	//pubKey := packet.NewRSAPublicKey(time.Now(), &key.PublicKey)
	//err = e.PrimaryKey.Serialize(pubW)
	err = e.Serialize(pubW)
	if err != nil {
		return
	}
	err = pubW.Close()
	if err != nil {
		return
	}

	p.mx.Lock()
	defer p.mx.Unlock()

	p.PublicKey = pubBuf.Bytes()
	p.pgp = e.PrivateKey
	return
}

func (p *Pgp) Pgp() *packet.PrivateKey {
	return p.pgp
}

func (p *Pgp) PrivateKeyToPem() (blk *pem.Block, err error) {
	if p.pgp == nil {
		return nil, cert.ErrPrivateKeyCannotBeNil
	}

	buf := &bytes.Buffer{}
	privW, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return
	}
	err = p.pgp.Serialize(privW)
	if err != nil {
		return
	}
	err = privW.Close()
	if err != nil {
		return
	}

	body, err := io.ReadAll(buf)
	if err != nil {
		return
	}

	return &pem.Block{
		Type:  privateKeyKey,
		Bytes: body,
	}, nil
}

func (p *Pgp) PrivateKeyBlock() (blk pem.Block, err error) {
	pemBlk, err := p.PrivateKeyToPem()
	if err != nil {
		return
	}

	blk.Bytes = pemBlk.Bytes
	blk.Type = pemBlk.Type
	return
}

// LoadPrivateKey loads the private key.
// Note that the private key might be encrypted.
// Get the key via *Certificate.GetPrivateKey or *Certificate.PrivateKey.
func (p *Pgp) LoadPrivateKey() (err error) {
	p.ensureMxInit()
	p.mx.Lock()
	defer p.mx.Unlock()

	p.privateKeyBlock = cert.Block{
		Algorithm: cert.Pgp,
		Data:      p.PrivateKey,
	}
	if p.IsUnsafe() {
		// Private key does not need to be decrypted, load corresponding field directly.
		// Work with a copy of the raw key.
		rawKey := make([]byte, len(p.PrivateKey))
		_ = copy(rawKey, p.PrivateKey)
		defer func() {
			// Zero values.
			for i := range rawKey {
				rawKey[i] = 0
			}
			rawKey = nil
		}()

		p.pgp, err = p.parsePgpPrivateKey(rawKey)
	}
	return
}

func (p *Pgp) IsUnsafe() bool {
	return len(p.Salt) == 0 && len(p.Nonce) == 0
}

func (p *Pgp) parsePgpPrivateKey(key []byte) (k *packet.PrivateKey, err error) {
	blk, err := armor.Decode(bytes.NewReader(key))
	if err != nil {
		return
	}
	if blk.Type != openpgp.PrivateKeyType {
		err = errors.New("invalid pgp private key")
		return
	}

	reader := packet.NewReader(blk.Body)
	pack, err := reader.Next()
	if err != nil {
		return
	}
	k, ok := pack.(*packet.PrivateKey)
	if !ok {
		err = errors.New("unable to parse to pgp private key")
	}
	return
}

func (p *Pgp) SetUnsafePrivateKey() (err error) {
	var pb pem.Block
	p.mx.Lock()
	defer func() {
		p.mx.Unlock()
		pb = pem.Block{}
		p.autoRelease()
	}()

	pb, err = p.getPrivateKeyPem()
	if err != nil {
		return
	}
	p.PrivateKey = pb.Bytes
	return
}

func (p *Pgp) GetPrivateKey() cert.Block {
	return p.privateKeyBlock
}

func (p *Pgp) getPrivateKeyPem() (pb pem.Block, err error) {
	var pemBlk *pem.Block
	if p.pgp != nil {
		pemBlk, err = p.PrivateKeyToPem()
	} else {
		err = errors.New("no data found")
	}
	if err != nil {
		return
	}
	pb = *pemBlk
	return
}

// EncryptPrivateKey encrypts the private key with the given pass.
func (p *Pgp) EncryptPrivateKey(pass []byte) (err error) {
	blk, err := p.getPrivateKeyPem()
	if err != nil {
		return
	}

	c := crypt.New(blk.Bytes, nil, nil)
	err = c.Encrypt(pass)
	if err != nil {
		return
	}

	enc := c.Encrypted()
	p.Salt = make([]byte, len(c.Salt()))
	p.Nonce = make([]byte, len(c.Nonce()))
	p.PrivateKey = make([]byte, len(enc))
	copy(p.Salt, c.Salt())
	copy(p.Nonce, c.Nonce())
	copy(p.PrivateKey, enc)

	//var (
	//	key  []byte
	//	salt []byte
	//	enc  []byte
	//	cBlk cipher.Block
	//	pb   pem.Block
	//)
	//defer func() {
	//	// Zero values.
	//	b := [][]byte{key, salt, enc}
	//	for i := range b {
	//		for j := range b[i] {
	//			b[i][j] = 0
	//		}
	//		b[i] = nil
	//	}
	//	cBlk = nil
	//	pb = pem.Block{}
	//}()
	//
	//p.ensureMxInit()
	//p.mx.Lock()
	//defer func() {
	//	p.mx.Unlock()
	//	p.autoRelease()
	//}()
	//
	//key, salt = certly.DeriveKey(pass, nil)
	//cBlk, err = aes.NewCipher(key)
	//if err != nil {
	//	return
	//}
	//gcm, err := cipher.NewGCM(cBlk)
	//if err != nil {
	//	return
	//}
	//nonce := make([]byte, gcm.NonceSize())
	//_, err = io.ReadFull(rand.Reader, nonce)
	//if err != nil {
	//	return
	//}
	//
	//pb, err = p.getPrivateKeyPem()
	//if err != nil {
	//	return
	//}
	//enc = gcm.Seal(nonce, nonce, pb.Bytes, nil)
	//
	//p.Salt = make([]byte, len(salt))
	//p.Nonce = make([]byte, len(nonce))
	//p.PrivateKey = make([]byte, len(enc))
	//copy(p.Salt, salt)
	//copy(p.Nonce, nonce)
	//copy(p.PrivateKey, enc)
	return
}

// DecryptPrivateKey decrypts the private key.
func (p *Pgp) DecryptPrivateKey(pass []byte) (err error) {
	if len(p.privateKeyBlock.Data) == 0 {
		// Ensure that the private key is loaded.
		err = p.LoadPrivateKey()
		if err != nil {
			return
		}
	}

	p.mx.Lock()
	defer p.mx.Unlock()

	var (
		derivedKey []byte
		raw        []byte
	)
	defer func() {
		// Zero values.
		b := [][]byte{derivedKey, raw, pass}
		for i := range b {
			for j := range b[i] {
				b[i][j] = 0
			}
			b[i] = nil
		}
	}()

	c := crypt.New(p.privateKeyBlock.Data, p.Salt, p.Nonce)
	err = c.Decrypt(pass)
	if err != nil {
		return
	}

	p.pgp, err = p.parsePgpPrivateKey(raw)
	if err != nil {
		return
	}
	return
}

// EnableAutoRelease raises Certificate.Release automatically after
// calling Certificate.EncryptPrivateKey or Certificate.SetUnsafePrivateKey.
func (p *Pgp) EnableAutoRelease() *Pgp {
	p.ensureMxInit()
	p.mx.Lock()
	defer p.mx.Unlock()

	p.releasable = true
	return p
}

func (p *Pgp) ensureMxInit() *Pgp {
	if p.mx == nil {
		p.mx = &sync.Mutex{}
	}
	return p
}

// Release releases private key data.
// After calling, the private key needs to be loaded / decrypted again.
func (p *Pgp) Release() {
	p.release()
}

// release releases data stored inside the unexported private key fields.
func (p *Pgp) release() {
	p.mx.Lock()
	defer p.mx.Unlock()

	if p.pgp != nil {
		*p.pgp = packet.PrivateKey{}
		p.pgp = nil
	}
	for i := range p.privateKeyBlock.Data {
		p.privateKeyBlock.Data[i] = 0
	}
	p.privateKeyBlock.Data = nil
}

func (p *Pgp) autoRelease() {
	if p.releasable {
		p.release()
	}
}
