package cryptos

import "github.com/cloudflare/circl/kem"

type KeyHolder interface {
	Keys() (publicKey kem.PublicKey, privateKey kem.PrivateKey, err error)
}

type EphemeralKeyHolder struct{}

var _ KeyHolder = (*EphemeralKeyHolder)(nil)

func (e *EphemeralKeyHolder) Keys() (publicKey kem.PublicKey, privateKey kem.PrivateKey, err error) {
	return GenerateKeyPair()
}

type ClientKeyHolder struct {
	publicKey  kem.PublicKey
	privateKey kem.PrivateKey
}

var _ KeyHolder = (*ClientKeyHolder)(nil)

func (c *ClientKeyHolder) Keys() (publicKey kem.PublicKey, privateKey kem.PrivateKey, err error) {
	return c.publicKey, c.privateKey, nil
}

func NewClientKeyHolder(publicKey kem.PublicKey, privateKey kem.PrivateKey) *ClientKeyHolder {
	return &ClientKeyHolder{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}
