# certly
## Description
Aiming to simplify the creation and singing process, certly is a RFC5280 focused go library for generating 
x509 certificates which currently supports **RSA**, **ECDSA** and **ED25519** keys.  

## Installation
Use `go get -u github.com/xiroxasx/certly` to get started.  

## Usage
### Creating certificates
```go
package main

import (
	"time"

	"github.com/xiroxasx/certly/cert"
)

func main() {
    // Create certificates with corresponding options.
    now := time.Now()
    c, err := cert.New(&cert.Options{
        CommonName:         "My-CN",
        Organization:       "My-Orga",
        OrganizationalUnit: "My-OU",
        Country:            "DE",
        State:              "My-State",
        Locality:           "My-Locality",
        DNSNames:           []string{"test.example.com"},
        IsCA:               false,
        Expiration: cert.Expiration{
            NotBefore: now,
            NotAfter:  now.Add(24 * 365 * time.Hour),
        },
    })
    if err != nil {
        // Error handling.
    }
    
    // Unset unexported fields after encrypting / setting the private key.
    c.EnableAutoRelease()
    
    // Create a new RSA private key.
    err = c.CreateRsaPrivateKey(cert.RSA2048)
    if err != nil {
        // Error handling.
    }
    
    // Self-sign the new certificate.
    err = c.SignSelf()
    if err != nil {
        // Error handling.
    }
    
    // Encrypt the private key before storing it in c.PrivateKey.
    // If not desired, use c.SetUnsafePrivateKey() instead.
    err = c.EncryptPrivateKey([]byte("MySuperSecretPassphrase!"))
    if err != nil {
        // Error handling.
    }
    
    // Since c.EnableAutoRelease() and c.EncryptPrivateKey() is executed,
    // The private key is now only available as encrypted []byte (c.PrivateKey).
}
```

### Signing certificates with CA
```go
package main

import (
	"time"
	
	"github.com/xiroxasx/certly/cert"
)

func main() {	
	// Create certificates with corresponding options.
	now := time.Now()
	ca, err := cert.New(&cert.Options{
		CommonName:         "My-CA",
		Organization:       "My-Orga",
		OrganizationalUnit: "My-OU",
		Country:            "DE",
		State:              "My-State",
		Locality:           "My-Locality",
		DNSNames:           []string{"ca.example.com"},
		IsCA:               true,
		Expiration: cert.Expiration{
			NotBefore: now,
			NotAfter:  now.Add(24 * 365 * time.Hour),
		},
	})
	if err != nil {
		// Error handling.
	}

	// Unset unexported fields after encrypting / setting the private key.
	ca.EnableAutoRelease()

	// Create a new RSA private key.
	err = ca.CreateRsaPrivateKey(cert.RSA4096)
	if err != nil {
		// Error handling.
	}

	// Self-sign the new certificate.
	err = ca.SignSelf()
	if err != nil {
		// Error handling.
	}
	
	// Create a new certificate like above.
	c, err := cert.New(&cert.Options{
		// ...
		IsCA: false,
		// ...
    })
	if err != nil {
		// Error handling.
	}

	// Unset unexported fields after encrypting / setting the private key.
	c.EnableAutoRelease()

	// Create a new RSA private key.
	err = c.CreateRsaPrivateKey(cert.RSA2048)
	if err != nil {
		// Error handling.
	}
	
	// Sign certificate with CA.
	err = c.SignWith(ca)
	if err != nil {
		// Error handling.
	}

	// Encrypt the private keys before storing it in ca.PrivateKey.
	// If not desired, use ca.SetUnsafePrivateKey() instead.
	err = ca.EncryptPrivateKey([]byte("MySuperSecretPassphrase!"))
	if err != nil {
		// Error handling.
	}
	err = c.EncryptPrivateKey([]byte("MySuperSecretPassphrase2!"))
	if err != nil {
		// Error handling.
	}
	// Since ca.EnableAutoRelease(), c.EnableAutoRelease(), ca.EncryptPrivateKey(),and c.EncryptPrivateKey() are executed,
	// the private keys is now only available as encrypted []byte (ca.PrivateKey / c.PrivateKey).
}
```

### Creating different keys
```go
package main

import (	
	"github.com/xiroxasx/certly/cert"
)

func main() {
	// Create certificates with corresponding options.
	c, err := cert.New(&cert.Options{
		CommonName: "My-CN",
		// ...
	})
	if err != nil {
		// Error handling.
	}

	// Unset unexported fields after encrypting / setting the private key.
	c.EnableAutoRelease()
	
	// Create RSA key with 4096 bits.
	c.CreateRsaPrivateKey(cert.RSA4096)
	
	// Create ECDSA key with P521 curve.
	c.CreateEcdsaPrivateKey(cert.P521)

	// Create ED25519 key.
	c.CreateEd25519PrivateKey()

	// Create RSA key with 4096 bits from string.
	c.CreatePrivateKey("RSA.4096")
	
	// Create ECDSA key with P521 curve from string.
	c.CreatePrivateKey("ECDSA.P521")

	// Create ED25519 key from string.
	c.CreatePrivateKey("ED25519")
}
```