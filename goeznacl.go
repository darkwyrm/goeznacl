package goeznacl

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/darkwyrm/b85"
	cs "github.com/darkwyrm/cryptostring"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// This module creates some classes which make working with NaCl in Go much less difficult.
// Currently the only supported algorithm is Curve25519 / ED25519 for encryption and signing and
// XSalsa20 for symmetric encryption. 256-bit BLAKE2 hashes are generated for key identification
// because it offers better performance over SHA2 without hardware acceleration.

var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

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

// VerificationKey is an object to represent just a verification key, not a key pair
type VerificationKey struct {
	PublicHash cs.CryptoString
	key        cs.CryptoString
}

// NewVerificationKey creates a new verification key from a CryptoString
func NewVerificationKey(key cs.CryptoString) *VerificationKey {
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
func (vkey VerificationKey) Verify(data []byte, signature cs.CryptoString) (bool, error) {
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
func (vkey *VerificationKey) Set(key cs.CryptoString) error {
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
	PublicHash  cs.CryptoString
	PrivateHash cs.CryptoString
	PublicKey   cs.CryptoString
	PrivateKey  cs.CryptoString
}

// NewSigningPair creates a new SigningPair object from two CryptoString objects
func NewSigningPair(pubkey cs.CryptoString,
	privkey cs.CryptoString) *SigningPair {
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
func (spair *SigningPair) Set(pubkey cs.CryptoString,
	privkey cs.CryptoString) error {

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
	return spair.Set(cs.NewFromBytes("ED25519", verkey[:]),
		cs.NewFromBytes("ED25519", signkey.Seed()))
}

// Sign cryptographically signs a byte slice.
func (spair SigningPair) Sign(data []byte) (cs.CryptoString, error) {
	var out cs.CryptoString

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
func (spair SigningPair) Verify(data []byte, signature cs.CryptoString) (bool, error) {
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

// EncryptionPair defines an asymmetric encryption EncryptionPair
type EncryptionPair struct {
	PublicHash  cs.CryptoString
	PrivateHash cs.CryptoString
	PublicKey   cs.CryptoString
	PrivateKey  cs.CryptoString
}

// NewEncryptionPair creates a new EncryptionPair object from two CryptoString objects
func NewEncryptionPair(pubkey cs.CryptoString, privkey cs.CryptoString) *EncryptionPair {
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
func (kpair *EncryptionPair) Set(pubkey cs.CryptoString,
	privkey cs.CryptoString) error {

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

	return kpair.Set(cs.NewFromBytes("CURVE25519", pubkey[:]),
		cs.NewFromBytes("CURVE25519", privkey[:]))
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
	return nil, errors.New("decryption error")
}

// EncryptionKey defines an asymmetric encryption EncryptionPair
type EncryptionKey struct {
	PublicHash cs.CryptoString
	PublicKey  cs.CryptoString
}

// NewEncryptionKey creates a new EncryptionKey object from a CryptoString of the public key
func NewEncryptionKey(pubkey cs.CryptoString) *EncryptionKey {
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
func (ekey *EncryptionKey) Set(pubkey cs.CryptoString) error {

	if pubkey.Prefix != "CURVE25519" {
		return errors.New("unsupported encryption algorithm")
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
		return "", errors.New("decoding error in public key")
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

// SymmetricKey defines a symmetric encryption key
type SymmetricKey struct {
	Hash cs.CryptoString
	Key  cs.CryptoString
}

// NewSymmetricKey creates a new NewSymmetricKey object from a CryptoString of the key
func NewSymmetricKey(keyString cs.CryptoString) *SymmetricKey {
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

	var keyString cs.CryptoString
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
func (key *SymmetricKey) Set(keyString cs.CryptoString) error {

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

// HashPassword turns a string into an Argon2 password hash. Set extra_strong to true if you're
// feeling particularly paranoid.
func HashPassword(password string, extra_strong bool) string {
	var argonRAM, argonIterations, argonSaltLength, argonKeyLength uint32
	var argonThreads uint8

	if extra_strong {
		// LUDICROUS SPEED! GO!
		argonRAM = 1073741824 // 1GB of RAM
		argonIterations = 10
		argonThreads = 8
		argonSaltLength = 24
		argonKeyLength = 48
	} else {
		argonRAM = 65536 // 64MB of RAM
		argonIterations = 3
		argonThreads = 4
		argonSaltLength = 16
		argonKeyLength = 32
	}

	salt := make([]byte, argonSaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return ""
	}

	passhash := argon2.IDKey([]byte(password), salt, argonIterations, argonRAM, argonThreads,
		argonKeyLength)

	// Although base85 encoding is used wherever possible, base64 is used here because of a
	// potential collision: base85 uses the $ character and argon2 hash strings use it as a
	// field delimiter. Not a huge deal here as the difference is just a few bytes.
	passString := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonRAM, argonIterations, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(passhash))
	return passString
}

// VerifyPasswordHash takes a password and the Argon2 hash to verify against, gets the parameters
// from the hash, applies them to the supplied password, and returns whether or not they match and
// if something went wrong
func VerifyPasswordHash(password string, hashPass string) (bool, error) {
	splitValues := strings.Split(hashPass, "$")
	if len(splitValues) != 6 {
		return false, errors.New("invalid argon hash string")
	}

	var version int
	_, err := fmt.Sscanf(splitValues[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, errors.New("unsupported argon version")
	}

	var ramUsage, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(splitValues[3], "m=%d,t=%d,p=%d", &ramUsage, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	var salt []byte
	salt, err = base64.RawStdEncoding.DecodeString(splitValues[4])
	if err != nil {
		return false, err
	}

	var savedHash []byte
	savedHash, err = base64.RawStdEncoding.DecodeString(splitValues[5])
	if err != nil {
		return false, err
	}

	passhash := argon2.IDKey([]byte(password), salt, iterations, ramUsage, parallelism,
		uint32(len(savedHash)))

	return (subtle.ConstantTimeCompare(passhash, savedHash) == 1), nil
}

// IsArgonHash checks to see if the string passed is an Argon2id password hash
func IsArgonHash(hashstr string) (bool, error) {
	if !strings.HasPrefix(hashstr, "$argon2id") {
		return false, errors.New("bad prefix")
	}
	if len(hashstr) > 128 {
		return false, errors.New("hash too long")
	}

	return true, nil
}
