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

	gcpkms "github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"

	// commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	// ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	// rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	// rspsspb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pss_go_proto"

	keysetutil "github.com/salrashid123/tink-keyset-util"
)

var (
	encryptedKeySetFile = flag.String("encrypted-key-set", "", "Parse a cleartext keyset")
	kmsURI              = flag.String("master-key-uri", "", "MasterKeyURI for encrypted keyset")
)

func main() {

	flag.Parse()

	keysetBytes, err := os.ReadFile(*encryptedKeySetFile)
	if err != nil {
		log.Fatalf("Error error reading encryptedKeyset %v", err)
	}

	var ku *keysetutil.KeySetUtil
	ctx := context.Background()

	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}

	kmsaead, err := gcpClient.GetAEAD(*kmsURI)
	if err != nil {
		log.Fatal(err)
	}

	ku, err = keysetutil.NewTinkKeySetUtil(ctx, &keysetutil.KeySetUtilConfig{
		KekAEAD:     kmsaead,
		KeySetBytes: keysetBytes,
	})
	if err != nil {
		log.Fatal(err)
	}

	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))
	keysetHandle, err := keyset.Read(keysetReader, kmsaead)
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

	rk, err := ku.ExportAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
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
	ecca, err := ku.ExportCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := rawAES.Open(nil, ecca[:keysetutil.AESGCMIVSize], ecca[keysetutil.AESGCMIVSize:], []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(plaintext))
}
