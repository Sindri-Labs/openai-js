package cryptos

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

var (
	kemID  = hpke.KEM_X25519_HKDF_SHA256
	kdfID  = hpke.KDF_HKDF_SHA256
	aeadID = hpke.AEAD_ChaCha20Poly1305
)

// GenerateKeyPair generates a new HPKE keypair
func GenerateKeyPair() (public kem.PublicKey, private kem.PrivateKey, err error) {
	scheme := kemID.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate HPKE keypair: %w", err)
	}
	return publicKey, privateKey, nil
}

// GenerateKeyPairBytes generates a new HPKE keypair and returns the raw byte representations
func GenerateKeyPairBytes() (public []byte, private []byte, err error) {
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	privateKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return publicKeyBytes, privateKeyBytes, nil
}

// GenerateKeyPairPEM generates a new HPKE keypair and returns PEM-encoded representations
func GenerateKeyPairPEM() (public []byte, private []byte, err error) {
	publicKeyBytes, privateKeyBytes, err := GenerateKeyPairBytes()
	if err != nil {
		return nil, nil, err
	}

	// Encode as PEM
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "HPKE PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "HPKE PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return publicKeyPEM, privateKeyPEM, nil
}

// PublicKeyFromBytes returns a HPKE public key from its raw byte representation
func PublicKeyFromBytes(publicKeyBytes []byte) (kem.PublicKey, error) {
	scheme := kemID.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HPKE public key: %w", err)
	}
	return publicKey, nil
}

// PublicKeyFromPEMBytes decodes a PEM-encoded HPKE public key.
func PublicKeyFromPEMBytes(pemBytes []byte) (kem.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return PublicKeyFromBytes(block.Bytes)
}

func PublicKeyFromHexString(hexString string) (kem.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return PublicKeyFromBytes(publicKeyBytes)
}

// PrivateKeyFromBytes returns a HPKE private key from its raw byte representation
func PrivateKeyFromBytes(privateKeyBytes []byte) (kem.PrivateKey, error) {
	scheme := kemID.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HPKE private key: %w", err)
	}
	return privateKey, nil
}

// PrivateKeyFromPEMBytes decodes a PEM-encoded HPKE private key.
func PrivateKeyFromPEMBytes(pemBytes []byte) (kem.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return PrivateKeyFromBytes(block.Bytes)
}

func HexStringFromPublicKey(publicKey kem.PublicKey) (string, error) {
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	return hex.EncodeToString(publicKeyBytes), nil
}

type EncryptionKeys struct {
	ServerPublicKey  kem.PublicKey
	ClientPublicKey  kem.PublicKey
	ClientPrivateKey kem.PrivateKey
}

type EncryptionBundle struct {
	EncapsulatedKey []byte
	CipherText      []byte
}

// Encrypt encrypts clear text using HPKE with the provided options.
func Encrypt(plainText []byte, keys *EncryptionKeys) (*EncryptionBundle, error) {
	// info := []byte(opts.ServerInfo)
	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	sender, err := suite.NewSender(keys.ServerPublicKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE sender: %w", err)
	}

	encapsulatedKey, sealer, err := sender.SetupAuth(rand.Reader, keys.ClientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup HPKE sender auth: %w", err)
	}

	cipherText, err := sealer.Seal(plainText, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to seal clear text: %w", err)
	}

	bundle := &EncryptionBundle{
		EncapsulatedKey: encapsulatedKey,
		CipherText:      cipherText,
	}

	return bundle, nil
}

// Decrypt decrypts the encrypted bundle using the provided private key.
func Decrypt(bundle *EncryptionBundle, keys *EncryptionKeys) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("encryption bundle cannot be nil")
	}

	suite := hpke.NewSuite(kemID, kdfID, aeadID)
	clientReceiver, err := suite.NewReceiver(keys.ClientPrivateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE receiver: %w", err)
	}

	clientOpener, err := clientReceiver.SetupAuth(bundle.EncapsulatedKey, keys.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to setup HPKE receiver auth: %w", err)
	}
	return clientOpener.Open(bundle.CipherText, nil)
}
