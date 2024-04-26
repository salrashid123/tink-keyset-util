package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	keysetutil "github.com/salrashid123/tink-keyset-util"
)

var (
	key        = flag.String("key", "9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ=", "raw key")
	keyid      = flag.Uint64("keyid", 4112199248, "raw key")
	ciphertext = flag.String("ciphertext", "AfUbLlAStrnjdnfUOjpkgLoQ0hjfJQDbnHYWZKmGxh1J2WTB", "ciphertext")
)

func main() {

	flag.Parse()

	k, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		log.Fatal(err)
	}
	ek, err := keysetutil.CreateAES256_GCM(k, 4112199248, tinkpb.OutputPrefixType_TINK, nil)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}

	log.Println("Tink Keyset:\n", prettyJSON.String())

	buf := bytes.NewBuffer(ek)
	r := keyset.NewJSONReader(buf)
	nkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		log.Fatal(err)
	}

	b, err := aead.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := base64.StdEncoding.DecodeString(*ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	dec, err := b.Decrypt(ec, []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Tink Decrypted: %s", string(dec))

	// fmt.Printf("%v\n", ek)
}
