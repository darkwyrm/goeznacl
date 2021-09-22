package goeznacl

import (
	"crypto/rand"
	"errors"

	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
)

// SymmetricKey defines a symmetric encryption key
type SymmetricKey struct {
	Hash CryptoString
	Key  CryptoString
}

// NewSymmetricKey creates a new NewSymmetricKey object from a CryptoString of the key
func NewSymmetricKey(keyString CryptoString) *SymmetricKey {
	var newkey SymmetricKey

	// All parameter validation is handled in Set
	if newkey.Set(keyString) != nil {
		return nil
	}

	return &newkey
}

// NewSymmetricKey creates a new NewSymmetricKey object from a CryptoString of the key
func GenerateSymmetricKey() *SymmetricKey {
	var newkey SymmetricKey

	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	var keyString CryptoString
	keyString.Prefix = "XSALSA20"
	keyString.Data = b85.Encode(keyBytes)

	// All parameter validation is handled in Set
	if newkey.Set(keyString) != nil {
		return nil
	}

	return &newkey
}

// GetEncryptionType returns the algorithm used by the key
func (key SymmetricKey) GetEncryptionType() string {
	return key.Key.Prefix
}

// GetType returns the type of key -- asymmetric or symmetric
func (key SymmetricKey) GetType() string {
	return "symmetric"
}

// Set assigns a pair of CryptoString values to the SymmetricKey
func (key *SymmetricKey) Set(keyString CryptoString) error {

	if keyString.Prefix != "XSALSA20" {
		return errors.New("unsupported encryption algorithm")
	}
	key.Key = keyString
	sum := blake2b.Sum256([]byte(keyString.AsString()))
	key.Hash.SetFromBytes("BLAKE2B-256", sum[:])

	return nil
}

// Encrypt encrypts byte slice using the internal key. It returns the resulting encrypted
// data as a Base85-encoded string that amounts to a CryptoString without the prefix.
func (key SymmetricKey) Encrypt(data []byte) (string, error) {
	if data == nil {
		return "", nil
	}

	keyDecoded := key.Key.RawData()
	if keyDecoded == nil {
		return "", errors.New("decoding error in symmetric key")
	}

	var nonce [24]byte
	rand.Read(nonce[:])

	var keyAdapter [32]byte
	copy(keyAdapter[:], keyDecoded)

	var out = make([]byte, 24)
	copy(out, nonce[:])
	out = secretbox.Seal(out, data, &nonce, &keyAdapter)

	return b85.Encode(out), nil
}

// Decrypt decrypts a string of encrypted data which is Base85 encoded using the internal key.
func (key SymmetricKey) Decrypt(data string) ([]byte, error) {
	if data == "" {
		return nil, nil
	}

	keyDecoded := key.Key.RawData()
	if keyDecoded == nil {
		return nil, errors.New("decoding error in symmetric key")
	}

	var keyAdapter [32]byte
	copy(keyAdapter[:], keyDecoded)

	decodedData, err := b85.Decode(data)
	if err != nil {
		return nil, errors.New("decoding error in data")
	}

	var nonce [24]byte
	copy(nonce[:], decodedData)

	decryptedData, ok := secretbox.Open(nil, decodedData[24:], &nonce, &keyAdapter)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return decryptedData, nil
}
