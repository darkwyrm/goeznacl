package goeznacl

import (
	"testing"
)

func TestEZCryptEncryptDecrypt(t *testing.T) {
	pubkey := NewCS("CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`")
	privkey := NewCS("CURVE25519:(Rj5)mmd1|YqlLCUP0vE;YZ#o;tJxtlAIzmPD7b&")
	keypair := NewEncryptionPair(pubkey, privkey)

	testData := "This is some encryption test data"
	encryptedData, err := keypair.Encrypt([]byte(testData))
	if err != nil || encryptedData == "" {
		t.Fatal("EncryptedPair.Encrypt() failed")
	}

	decryptedRaw, err := keypair.Decrypt(encryptedData)
	if err != nil || decryptedRaw == nil {
		t.Fatal("EncryptedPair.Decrypt() failed")
	}

	if string(decryptedRaw) != testData {
		t.Fatal("EncryptedPair decrypted data mismatch")
	}

}

func TestEZCryptSignVerify(t *testing.T) {
	verkey := NewCS("ED25519:PnY~pK2|;AYO#1Z;B%T$2}E$^kIpL=>>VzfMKsDx")
	signkey := NewCS("ED25519:{^A@`5N*T%5ybCU%be892x6%*Rb2rnYd=SGeO4jF")
	keypair := NewSigningPair(verkey, signkey)

	testData := "This is some signing test data"

	signature, err := keypair.Sign([]byte(testData))
	if err != nil || !signature.IsValid() {
		t.Fatal("SigningPair.Sign() failed")
	}

	verified, err := keypair.Verify([]byte(testData), signature)
	if err != nil || !verified {
		t.Fatal("SigningPair.Verify() failed")
	}
}

func TestEZCryptSymEncryptDecrypt(t *testing.T) {
	keystring := NewCS("XSALSA20:hlibDY}Ls{F!yG83!a#E$|Nd3?MQ@9G=Q{7PB(@O")
	secretkey := NewSymmetricKey(keystring)

	testData := "This is some encryption test data"
	encryptedData, err := secretkey.Encrypt([]byte(testData))
	if err != nil || encryptedData == "" {
		t.Fatal("SymmetricKey.Encrypt() failed")
	}

	decryptedRaw, err := secretkey.Decrypt(encryptedData)
	if err != nil || decryptedRaw == nil {
		t.Fatal("SymmetricKey.Decrypt() failed")
	}

	if string(decryptedRaw) != testData {
		t.Fatal("SymmetricKey decrypted data mismatch")
	}

}

func TestArgonHashing(t *testing.T) {
	sampleHash := "$argon2id$v=19$m=65536,t=2," +
		"p=1$azRGvkBtov+ML8kPEaBcIA$tW+o1B8XeLmbKzzN9EQHu9dNLW4T6ia4ha0Z5ZDh7f4"
	ok, err := IsArgonHash(sampleHash)
	if err != nil || !ok {
		t.Fatal("IsArgonHash rejected a valid Argon2 hash")
	}

	testHash := HashPassword("MyS3cretPassw*rd", false)
	ok, err = IsArgonHash(testHash)
	if err != nil || !ok {
		t.Fatal("HashPassword created a bad hash or had an error")
	}

	ok, err = VerifyPasswordHash("MyS3cretPassw*rd", sampleHash)
	if err != nil || !ok {
		t.Fatal("VerifyPasswordHash created a bad hash or had an error")
	}

	ok, _ = VerifyPasswordHash("BadPassw*rd", sampleHash)
	if ok {
		t.Fatal("VerifyPasswordHash failed to reject a password mismatch")
	}
}
