package goeznacl

import (
	"crypto/sha256"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

// GetHash generates a CryptoString hash of the supplied data
func GetHash(algorithm string, data []byte) (CryptoString, error) {
	var out CryptoString

	switch algorithm {
	case "BLAKE2B-256":
		rawHash := blake2b.Sum256(data)
		out.SetFromBytes(algorithm, rawHash[:])
	case "BLAKE2B-512":
		rawHash := blake2b.Sum512(data)
		out.SetFromBytes(algorithm, rawHash[:])
	case "BLAKE3-256":
		rawHash := blake3.Sum256(data)
		out.SetFromBytes(algorithm, rawHash[:])
	case "SHA-256":
		rawHash := sha256.Sum256(data)
		out.SetFromBytes(algorithm, rawHash[:])
	default:
		return out, ErrUnsupportedAlgorithm
	}
	return out, nil
}

// CheckHash generates a CryptoString hash of the supplied data
func CheckHash(hash CryptoString, data []byte) (bool, error) {

	var test CryptoString
	switch hash.Prefix {
	case "BLAKE2B-256":
		rawHash := blake2b.Sum256(data)
		test.SetFromBytes(hash.Prefix, rawHash[:])
	case "BLAKE2B-512":
		rawHash := blake2b.Sum512(data)
		test.SetFromBytes(hash.Prefix, rawHash[:])
	case "BLAKE3-256":
		rawHash := blake3.Sum256(data)
		test.SetFromBytes(hash.Prefix, rawHash[:])
	case "SHA-256":
		rawHash := sha256.Sum256(data)
		test.SetFromBytes(hash.Prefix, rawHash[:])
	default:
		return false, ErrUnsupportedAlgorithm
	}

	return test.AsString() == hash.AsString(), nil
}
