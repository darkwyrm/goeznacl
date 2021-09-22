package goeznacl

import (
	"crypto/rand"
	"errors"

	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

// This module creates some classes which make working with NaCl in Go much less difficult.
// Currently the only supported algorithm is Curve25519 / ED25519 for encryption and signing and
// XSalsa20 for symmetric encryption. 256-bit BLAKE2 hashes are generated for key identification
// because it offers better performance over SHA2 without hardware acceleration.

var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")
var ErrDecryptionFailure = errors.New("decryption failure")
var ErrVerificationFailure = errors.New("verification failure")

type EncryptorKey interface {
	Encrypt(data []byte) (string, error)
}

type DecryptorKey interface {
	Decrypt(data string) ([]byte, error)
}

// CryptoKey is a baseline interface to the different kinds of keys defined in this module
type CryptoKey interface {
	GetEncryptionType() string
	GetType() string
}

// EncryptionPair defines an asymmetric encryption EncryptionPair
type EncryptionPair struct {
	PublicHash  CryptoString
	PrivateHash CryptoString
	PublicKey   CryptoString
	PrivateKey  CryptoString
}

// NewEncryptionPair creates a new EncryptionPair object from two CryptoString objects
func NewEncryptionPair(pubkey CryptoString, privkey CryptoString) *EncryptionPair {
	var newpair EncryptionPair

	// All parameter validation is handled in Set
	if newpair.Set(pubkey, privkey) != nil {
		return nil
	}

	return &newpair
}

// GetEncryptionType returns the algorithm used by the key
func (kpair EncryptionPair) GetEncryptionType() string {
	return kpair.PublicKey.Prefix
}

// GetType returns the type of key -- asymmetric or symmetric
func (kpair EncryptionPair) GetType() string {
	return "asymmetric"
}

// Set assigns a pair of CryptoString values to the EncryptionPair
func (kpair *EncryptionPair) Set(pubkey CryptoString,
	privkey CryptoString) error {

	if pubkey.Prefix != "CURVE25519" || privkey.Prefix != "CURVE25519" {
		return ErrUnsupportedAlgorithm
	}
	kpair.PublicKey = pubkey
	kpair.PrivateKey = privkey

	sum := blake2b.Sum256([]byte(pubkey.AsString()))
	kpair.PublicHash.SetFromBytes("BLAKE2B-256", sum[:])
	sum = blake2b.Sum256([]byte(privkey.AsString()))
	kpair.PrivateHash.SetFromBytes("BLAKE2B-256", sum[:])

	return nil
}

// Generate initializes the object to a new key pair
func (kpair EncryptionPair) Generate() error {
	pubkey, privkey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	return kpair.Set(NewCSFromBytes("CURVE25519", pubkey[:]),
		NewCSFromBytes("CURVE25519", privkey[:]))
}

// Encrypt encrypts byte slice using the internal public key. It returns the resulting encrypted
// data as a Base85-encoded string that amounts to a CryptoString without the prefix.
func (kpair EncryptionPair) Encrypt(data []byte) (string, error) {
	if data == nil {
		return "", nil
	}

	pubKeyDecoded := kpair.PublicKey.RawData()
	if pubKeyDecoded == nil {
		return "", b85.ErrDecodingB85
	}

	// This kind of stupid is why this class is even necessary
	var tempPtr [32]byte
	ptrAdapter := tempPtr[0:32]
	copy(ptrAdapter, pubKeyDecoded)

	encryptedData, err := box.SealAnonymous(nil, data, &tempPtr, rand.Reader)
	if err != nil {
		return "", err
	}

	return b85.Encode(encryptedData), nil
}

// Decrypt decrypts a string of encrypted data which is Base85 encoded using the internal private
// key.
func (kpair EncryptionPair) Decrypt(data string) ([]byte, error) {
	if data == "" {
		return nil, nil
	}

	pubKeyDecoded := kpair.PublicKey.RawData()
	if pubKeyDecoded == nil {
		return nil, b85.ErrDecodingB85
	}
	var pubKeyPtr [32]byte

	ptrAdapter := pubKeyPtr[0:32]
	copy(ptrAdapter, pubKeyDecoded)

	privKeyDecoded := kpair.PrivateKey.RawData()
	if privKeyDecoded == nil {
		return nil, b85.ErrDecodingB85
	}
	var privKeyPtr [32]byte

	ptrAdapter = privKeyPtr[0:32]
	copy(ptrAdapter, privKeyDecoded)

	decodedData, err := b85.Decode(data)
	if err != nil {
		return nil, err
	}

	decryptedData, ok := box.OpenAnonymous(nil, decodedData, &pubKeyPtr, &privKeyPtr)

	if ok {
		return decryptedData, nil
	}
	return nil, ErrDecryptionFailure
}

// EncryptionKey defines an asymmetric encryption EncryptionPair
type EncryptionKey struct {
	PublicHash CryptoString
	PublicKey  CryptoString
}

// NewEncryptionKey creates a new EncryptionKey object from a CryptoString of the public key
func NewEncryptionKey(pubkey CryptoString) *EncryptionKey {
	var newkey EncryptionKey

	// All parameter validation is handled in Set
	if newkey.Set(pubkey) != nil {
		return nil
	}

	return &newkey
}

// GetEncryptionType returns the algorithm used by the key
func (ekey EncryptionKey) GetEncryptionType() string {
	return ekey.PublicKey.Prefix
}

// GetType returns the type of key -- asymmetric or symmetric
func (ekey EncryptionKey) GetType() string {
	return "asymmetric"
}

// Set assigns a pair of CryptoString values to the EncryptionKey
func (ekey *EncryptionKey) Set(pubkey CryptoString) error {

	if pubkey.Prefix != "CURVE25519" {
		return ErrUnsupportedAlgorithm
	}
	ekey.PublicKey = pubkey

	sum := blake2b.Sum256([]byte(pubkey.AsString()))
	ekey.PublicHash.SetFromBytes("BLAKE2B-256", sum[:])

	return nil
}

// Encrypt encrypts byte slice using the internal public key. It returns the resulting encrypted
// data as a Base85-encoded string that amounts to a CryptoString without the prefix.
func (ekey EncryptionKey) Encrypt(data []byte) (string, error) {
	if data == nil {
		return "", nil
	}

	pubKeyDecoded := ekey.PublicKey.RawData()
	if pubKeyDecoded == nil {
		return "", b85.ErrDecodingB85
	}

	// This kind of stupid is why this class is even necessary
	var tempPtr [32]byte
	ptrAdapter := tempPtr[0:32]
	copy(ptrAdapter, pubKeyDecoded)

	encryptedData, err := box.SealAnonymous(nil, data, &tempPtr, rand.Reader)
	if err != nil {
		return "", err
	}

	return b85.Encode(encryptedData), nil
}
