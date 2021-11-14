package goeznacl

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
)

var hashIterations = 1000

func TestBlake2B_256(t *testing.T) {
	var hashBuffer = make([]uint8, 1048576)
	start := time.Now()
	for i := 0; i < hashIterations; i++ {
		blake2b.Sum256(hashBuffer)
	}
	elapsed := time.Since(start)
	t.Logf("BLAKE2B-256: %s", elapsed)
}

func TestBlake2B_512(t *testing.T) {
	var hashBuffer = make([]uint8, 1048576)
	start := time.Now()
	for i := 0; i < hashIterations; i++ {
		blake2b.Sum512(hashBuffer)
	}
	elapsed := time.Since(start)
	t.Logf("BLAKE2B-512: %s", elapsed)
}

func TestBlake3_256(t *testing.T) {
	var hashBuffer = make([]uint8, 1048576)
	start := time.Now()
	for i := 0; i < hashIterations; i++ {
		blake3.Sum256(hashBuffer)
	}
	elapsed := time.Since(start)
	t.Logf("BLAKE3-256: %s", elapsed)
}

func TestSHA_256(t *testing.T) {
	var hashBuffer = make([]uint8, 1048576)
	start := time.Now()
	for i := 0; i < hashIterations; i++ {
		sha256.Sum256(hashBuffer)
	}
	elapsed := time.Since(start)
	t.Logf("SHA256: %s", elapsed)
}

func TestSHA_512(t *testing.T) {
	var hashBuffer = make([]uint8, 1048576)
	start := time.Now()
	for i := 0; i < hashIterations; i++ {
		sha512.Sum512(hashBuffer)
	}
	elapsed := time.Since(start)
	t.Logf("SHA512: %s", elapsed)
}
