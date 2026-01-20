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
	insecureKeySetFile = flag.String("insecure-key-set", "keysets/aes_gcm_1.bin", "Parse a cleartext keyset")
)

func main() {

	flag.Parse()

	// read the keyset
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
	// encrypt something with the keyset and tink
	a, err := aead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	tink_encrypted_ciphertext, err := a.Encrypt([]byte("foo"), []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("tink_encrypted_ciphertext Encrypted Data: %s", base64.StdEncoding.EncodeToString(tink_encrypted_ciphertext))

	// export the raw aes key from the keyset
	rk, err := ku.ExportAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Raw key: %s", base64.StdEncoding.EncodeToString(rk))

	// now create an ordinary aes gcm cipher with the raw exported key
	aesCipher, err := aes.NewCipher(rk)
	if err != nil {
		log.Fatal(err)
	}
	rawAES, err := cipher.NewGCM(aesCipher)
	if err != nil {
		log.Fatal(err)
	}

	// extract just the orignial ciphertext and exclude the tink prefix
	ecca, err := ku.ExportCipherText(tink_encrypted_ciphertext, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt that data with the exported key from the keyset.
	plaintext, err := rawAES.Open(nil, ecca[:keysetutil.AESGCMIVSize], ecca[keysetutil.AESGCMIVSize:], []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(plaintext))
}
