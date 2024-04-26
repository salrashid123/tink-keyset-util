package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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

	rk, err := ku.GetRawAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Raw key: %s", base64.StdEncoding.EncodeToString(rk))

	aesCipher, err := aes.NewCipher(rk)
	if err != nil {
		log.Fatal(err)
	}
	rawAES, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatal(err)
	}
	ecca, err := ku.GetRawCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := rawAES.Open(nil, ecca[:keysetutil.AESGCMIVSize], ecca[keysetutil.AESGCMIVSize:], []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(plaintext))
}
