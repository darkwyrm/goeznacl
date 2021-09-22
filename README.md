# goeznacl

goeznacl is an MIT-licensed Go library for making work with cryptography easier by providing an easy-to-use wrapper around the NaCl implementation provided in the Go main libraries.

## Description

Cryptography is really hard. Any code which implements it is equally hard. Anything which touches the implementation code isn't much easier. This library came from a need to work with crypto keys over a text-based protocol. It had the added benefit of easing debugging code which interacts with cryptography. The library as a whole should be considered beta, but is progressing toward maturity fairly quickly.

A new data type, CryptoString, is used heavily when interacting with this library. In short, CryptoStrings are Base85-encoded hashes or crypto keys with an algorithm name prepended and a colon separating the two. Debugging is much easier using this library. Work with the other classes, such as SecretKey, PublicKey, and so on is fairly straightforward and should be obvious from reading the sources.

**Please** don't use this code to place *important* crypto keys in your code or embed backdoors. No one needs that kind of drama.

## Usage


The code is heavily commented, the file is short, and usage should be pretty obvious. Nevertheless, here is an example:

```go
import "crypto/rand"
import "github.com/darkwyrm/goeznacl"


func GenerateSymmetricKey() goeznacl.CryptoString {
	
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)

	return goeznacl.NewCSFromBytes("XSALSA20", keyBytes)
}
```

To interact with the actual key generated in the above example, the `RawData()` method is called. Although the internal representation of the object is accessible from the outside to permit special cases, direct interaction with the `Prefix` and `Data` properties is not recommended.

