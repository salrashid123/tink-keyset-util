package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"

	"encoding/base64"
	"flag"
	"log"
	"os"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"

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

	a, err := mac.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	plaintText := "foo"
	ec, err := a.ComputeMAC([]byte(plaintText))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Tink HMAC: %s", base64.StdEncoding.EncodeToString(ec))

	rk, err := ku.ExportHMACKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("rawKey key: %s", base64.StdEncoding.EncodeToString(rk))

	ecca, err := ku.ExportCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("TINK MAC without prefix: %s", base64.StdEncoding.EncodeToString(ecca))

	h := hmac.New(sha256.New, rk)
	h.Write([]byte(plaintText))

	log.Printf("Recreated HMAC from rawKey: %s\b", base64.StdEncoding.EncodeToString(h.Sum(nil)))

}
