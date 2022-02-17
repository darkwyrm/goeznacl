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

func TestGetHash(t *testing.T) {

	testmap := map[string]string{
		"BLAKE2B-256": "BLAKE2B-256:?*e?y<{rF)B`7<5U8?bXQhNic6W4lmGlN}~Mu}la",
		"SHA-256":     "SHA-256:A3Wp)6`}|qqweQl!=L|-R>C51(W!W+B%4_+&b=VC",
		"BLAKE3-256":  `BLAKE3-256:vE_TL>ixs8I<**_vPE@wnTJom(OOqO$B(KLZ7n{E`,
		"BLAKE2B-512": "BLAKE2B-512:Dc660^4H`I3arYhx9i*D`R2+&UDv6-tV@Sr3npbaWJg;" +
			"Q@>!zIERGSfgy0^&t=24zT=09vm4s;bY+gH*",
	}

	for k, v := range testmap {
		cs, err := GetHash(k, []byte("aaaaaaaa"))
		if err != nil {
			t.Fatalf("TestGetHash: error getting hash: %s", err.Error())
		}
		if cs.AsString() != v {
			t.Fatalf("Hash test failure:\nWanted: %s\nGot: %s", v, cs.AsString())
		}
	}
}

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
