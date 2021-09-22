package goeznacl

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/darkwyrm/b85"
	"golang.org/x/crypto/blake2b"
)

// VerificationKey is an object to represent just a verification key, not a key pair
type VerificationKey struct {
	PublicHash CryptoString
	key        CryptoString
}

// NewVerificationKey creates a new verification key from a CryptoString
func NewVerificationKey(key CryptoString) *VerificationKey {
	var newkey VerificationKey
	if newkey.Set(key) != nil {
		return nil
	}

	return &newkey
}

// GetEncryptionType returns the algorithm used by the key
func (vkey VerificationKey) GetEncryptionType() string {
	return vkey.key.Prefix
}

// GetType returns the type of key -- asymmetric or symmetric
func (vkey VerificationKey) GetType() string {
	return "asymmetric"
}

// Verify uses the internal verification key with the passed data and signature and returns true
// if the signature has verified the data with that key.
func (vkey VerificationKey) Verify(data []byte, signature CryptoString) (bool, error) {
	if !signature.IsValid() {
		return false, errors.New("invalid signature")
	}

	if signature.Prefix != "ED25519" {
		return false, ErrUnsupportedAlgorithm
	}
	digest := signature.RawData()
	if digest == nil {
		return false, b85.ErrDecodingB85
	}

	verifyKeyDecoded := vkey.key.RawData()
	if verifyKeyDecoded == nil {
		return false, b85.ErrDecodingB85
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, data, digest)

	return verifyStatus, nil
}

// Set assigns a CryptoString value to the key
func (vkey *VerificationKey) Set(key CryptoString) error {
	if key.Prefix != "ED25519" {
		return ErrUnsupportedAlgorithm
	}
	vkey.key = key

	sum := blake2b.Sum256([]byte(vkey.key.AsString()))
	vkey.PublicHash.SetFromBytes("BLAKE2B-256", sum[:])

	return nil
}

// SigningPair defines an asymmetric signing key pair
type SigningPair struct {
	PublicHash  CryptoString
	PrivateHash CryptoString
	PublicKey   CryptoString
	PrivateKey  CryptoString
}

// NewSigningPair creates a new SigningPair object from two CryptoString objects
func NewSigningPair(pubkey CryptoString,
	privkey CryptoString) *SigningPair {
	var newpair SigningPair
	if newpair.Set(pubkey, privkey) != nil {
		return nil
	}

	return &newpair
}

// GetEncryptionType returns the algorithm used by the key
func (spair SigningPair) GetEncryptionType() string {
	return spair.PublicKey.Prefix
}

// GetType returns the type of key -- asymmetric or symmetric
func (spair SigningPair) GetType() string {
	return "signing"
}

// Set assigns a pair of CryptoString values to the SigningPair
func (spair *SigningPair) Set(pubkey CryptoString,
	privkey CryptoString) error {

	if pubkey.Prefix != "ED25519" || privkey.Prefix != "ED25519" {
		return ErrUnsupportedAlgorithm
	}
	spair.PublicKey = pubkey
	spair.PrivateKey = privkey

	sum := blake2b.Sum256([]byte(pubkey.AsString()))
	spair.PublicHash.SetFromBytes("BLAKE2B-256", sum[:])
	sum = blake2b.Sum256([]byte(privkey.AsString()))
	spair.PrivateHash.SetFromBytes("BLAKE2B-256", sum[:])

	return nil
}

// Generate initializes the object to a new key pair
func (spair SigningPair) Generate() error {
	verkey, signkey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return spair.Set(NewCSFromBytes("ED25519", verkey[:]),
		NewCSFromBytes("ED25519", signkey.Seed()))
}

// Sign cryptographically signs a byte slice.
func (spair SigningPair) Sign(data []byte) (CryptoString, error) {
	var out CryptoString

	signkeyDecoded := spair.PrivateKey.RawData()
	if signkeyDecoded == nil {
		return out, errors.New("bad signing key")
	}

	// We bypass the nacl/sign module because it requires a 64-bit private key. We, however, pass
	// around the 32-bit ed25519 seeds used to generate the keys. Thus, we have to skip using
	// nacl.Sign() and go directly to the equivalent code in the ed25519 module.
	signKeyPriv := ed25519.NewKeyFromSeed(signkeyDecoded)
	signature := ed25519.Sign(signKeyPriv, data)
	out.SetFromBytes("ED25519", signature)

	return out, nil
}

// Verify uses the internal verification key with the passed data and signature and returns true
// if the signature has verified the data with that key.
func (spair SigningPair) Verify(data []byte, signature CryptoString) (bool, error) {
	if !signature.IsValid() {
		return false, errors.New("invalid signature")
	}

	if signature.Prefix != "ED25519" {
		return false, ErrUnsupportedAlgorithm
	}
	digest := signature.RawData()
	if digest == nil {
		return false, b85.ErrDecodingB85
	}

	verifyKeyDecoded := spair.PublicKey.RawData()
	if verifyKeyDecoded == nil {
		return false, b85.ErrDecodingB85
	}

	verifyStatus := ed25519.Verify(verifyKeyDecoded, data, digest)

	return verifyStatus, nil
}
