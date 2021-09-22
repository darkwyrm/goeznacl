package goeznacl

import (
	"errors"
	"regexp"
	"strings"

	"github.com/darkwyrm/b85"
)

// This module contains the Go implementation of CryptoString, similar to the original
// implementation in originally written for PyMensago, but also includes some special sauce for
// better interaction with Go's libsodium API.

// CryptoString is a compact way of handling cryptographic hashes, signatures, and keys such that
// (1) the algorithm used is obvious and (2) the data is encoded as text. The RFC 1924 variant of
// Base85 encoding is used because it is more compact than Base64 and friendly to source code.

// The format looks like this: ALGORITHM:xxxxxxxxxxxxxxxxxxxx, where ALGORITHM is the name of the
// algorithm and the Xs represent the Base85-encoded data. The prefix is limited to 24 characters
// including the colon separator. Only capital ASCII letters, numbers, and dashes may be used in
// the prefix.
//
// Examples:
//	- BLAKE3-256:^zPiV;CKvLd2(uwpIzmyMotYFsKM=cgbL=nSI2LN
//	- ED25519:6lXjej0C~!F&_`qnkPHrC`z8+>;#g*fNfjV@4ngGlp#xsr8}1rS2(NG
//

var ErrBadAlgorithm = errors.New("unsupported algorithm")

var reFormatPattern = regexp.MustCompile("^[A-Z0-9-]{1,24}")

type CryptoString struct {
	Prefix string
	Data   string
}

// New is just syntactic sugar for generating a quickie CryptoString from a string
func NewCS(str string) CryptoString {
	var out CryptoString
	out.Set(str)
	return out
}

// NewFromBytes creates a CryptoString object from an algorithm and buffer of data. The new
// instance makes a copy of the data buffer passed to it
func NewCSFromBytes(algorithm string, buffer []byte) CryptoString {
	var out CryptoString
	out.SetFromBytes(algorithm, buffer)
	return out
}

// Set takes a CryptoString-formatted string and sets the object to it.
func (cs *CryptoString) Set(str string) error {
	cs.Prefix = ""
	cs.Data = ""

	// Data checks

	if !reFormatPattern.MatchString(str) {
		return ErrBadAlgorithm
	}

	parts := strings.SplitN(str, ":", 2)
	if len(parts) != 2 || len(parts[1]) < 1 {
		return errors.New("crypto data missing")
	}

	_, err := b85.Decode(parts[1])
	if err != nil {
		return errors.New("base85 decoding error")
	}

	cs.Prefix = parts[0]
	cs.Data = parts[1]
	return nil
}

// SetFromBytes assigns an algorithm and the associated data to the object. The caller retains
// ownership of the underlying data passed to it.
func (cs *CryptoString) SetFromBytes(algorithm string, buffer []byte) error {

	if len(algorithm) > 0 {
		if !reFormatPattern.MatchString(algorithm) {
			return errors.New("bad algorithm given")
		}
		cs.Prefix = algorithm
	} else {
		cs.Prefix = ""
	}

	if buffer != nil {
		cs.Data = b85.Encode(buffer)
	} else {
		cs.Data = ""
	}

	return nil
}

// AsString returns the state of the object as a CryptoString-formatted string
func (cs *CryptoString) AsString() string {
	return cs.Prefix + ":" + cs.Data
}

// RawData returns the data of the object as a series of bytes. In the event of an error, nil is
// returned
func (cs *CryptoString) RawData() []byte {
	out, err := b85.Decode(cs.Data)
	if err != nil {
		return nil
	}
	return out
}

// AsBytes returns the CryptoString as a byte array
func (cs *CryptoString) AsBytes() []byte {
	return []byte(cs.Prefix + ":" + cs.Data)
}

// MakeEmpty returns the object to an uninitialized state
func (cs *CryptoString) MakeEmpty() {
	cs.Prefix = ""
	cs.Data = ""
}

// IsValid checks the internal data and returns True if it is valid
func (cs *CryptoString) IsValid() bool {
	if !reFormatPattern.MatchString(cs.Prefix) {
		return false
	}

	if len(cs.Data) < 1 {
		return false
	}

	if _, err := b85.Decode(cs.Data); err != nil {
		return false
	}

	return true
}
