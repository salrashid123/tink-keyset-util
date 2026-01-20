package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"log"
	"os"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	// commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	// ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	// rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	// rspsspb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"

	keysetutil "github.com/salrashid123/tink-keyset-util"
)

var (
	insecureKeySetFile = flag.String("insecure-key-set", "", "Parse a cleartext keyset")
)

func main() {

	flag.Parse()

	keysetBytes, err := os.ReadFile(*insecureKeySetFile)
	if err != nil {
		log.Fatalf("Error error reading private key %v", err)
	}

	var ku *keysetutil.KeySetUtil
	ctx := context.Background()

	ku, err = keysetutil.NewTinkKeySetUtil(ctx, &keysetutil.KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	if err != nil {
		log.Fatal(err)
	}

	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))
	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := a.Encrypt([]byte("foo"), []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encrypted Data: %s", base64.StdEncoding.EncodeToString(ec))

	rk, hk, err := ku.ExportAesCtrHmacAeadKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("AES key: %s", base64.StdEncoding.EncodeToString(rk))
	log.Printf("HMAC key: %s", base64.StdEncoding.EncodeToString(hk))
	// https://github.com/tink-crypto/tink/blob/master/go/aead/aes_ctr_hmac_aead_key_manager.go#L54

	rawCipherTextWithMAC, err := ku.ExportCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt
	// https://developers.google.com/tink/wire-format#aes-ctr-hmac

	log.Printf("Full Raw Encrypted %s", base64.StdEncoding.EncodeToString(rawCipherTextWithMAC))

	rawCipherText := rawCipherTextWithMAC[:len(rawCipherTextWithMAC)-32]
	log.Printf("Raw ciphertext with IV: %s", base64.StdEncoding.EncodeToString(rawCipherText))
	block, err := aes.NewCipher(rk)
	if err != nil {
		log.Fatal(err)
	}
	iv := rawCipherText[:aes.BlockSize]
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(rawCipherText)-aes.BlockSize)
	stream.XORKeyStream(plaintext, rawCipherText[aes.BlockSize:])
	log.Printf("Plaintext: %s", string(plaintext))

	// calculate mac
	// AD || IV || ciphertext || bitlen(AD)
	mac := rawCipherTextWithMAC[len(rawCipherTextWithMAC)-32:]
	log.Printf("Raw mac from from encrypted data: %s", base64.StdEncoding.EncodeToString(mac))
	// https://github.com/tink-crypto/tink/blob/master/go/aead/aes_ctr_hmac_aead_key_manager.go#L54

	// compute the HMAC
	hmac := hmac.New(sha256.New, hk)
	associatedData := "some additional data"
	payload := rawCipherText
	adSizeInBits := uint64(len(associatedData)) * 8
	adSizeInBitsEncoded := uint64ToByte(adSizeInBits)
	toAuthData := make([]byte, 0, len(associatedData)+len(payload)+len(adSizeInBitsEncoded))
	toAuthData = append(toAuthData, associatedData...)
	toAuthData = append(toAuthData, payload...)
	toAuthData = append(toAuthData, adSizeInBitsEncoded...)

	hmac.Write(toAuthData)

	dataHmac := hmac.Sum(nil)
	log.Printf("calculated hmac using hmac key hmac( (AD || IV || ciphertext || bitlen(AD)), key): %s", base64.StdEncoding.EncodeToString(dataHmac))

}

func uint64ToByte(n uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}
