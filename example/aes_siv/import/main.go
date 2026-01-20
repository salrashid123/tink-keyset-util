package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"

	//"github.com/tink-crypto/tink-go/v2/aead"
	//"github.com/tink-crypto/tink-go/v2/daead"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"

	//gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	// aesctrhmac "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	// gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	keysetutil "github.com/salrashid123/tink-keyset-util"
	sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
)

var (
	//sivkey = flag.String("key", "qzHySk5hyBm1yf3hJX8h6pV/bsWX6cxIGy+28F+HGymokh4cx57J+MWpZ/MWzw15JKEJwmcszDENkKydk/AHTg==", "raw key") // for aes-siv
	key = flag.String("key", "9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ=", "raw key") // for aes-gcm, aes-gcm-ctr

	// hmackey       = flag.String("hmackey", "9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ=", "raw key") // for aes-gcm-ctr-hmac
	keyid         = flag.Uint("keyid", 4112199248, "raw key")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "some data to encrypt")
)

func main() {

	flag.Parse()

	kval, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		log.Fatal(err)
	}

	//aes-siv
	k := sivpb.AesSivKey{
		Version:  0,
		KeyValue: kval,
	}

	ek, err := keysetutil.ImportSymmetricKey(&k, uint32(*keyid), tinkpb.OutputPrefixType_TINK, nil)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", " ")
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

	// for siv
	b, err := daead.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := b.EncryptDeterministically([]byte(*dataToEncrypt), []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Tink Encrypted: %s", base64.StdEncoding.EncodeToString(ec))

	dec, err := b.DecryptDeterministically(ec, []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Tink Decrypted: %s", string(dec))

}
