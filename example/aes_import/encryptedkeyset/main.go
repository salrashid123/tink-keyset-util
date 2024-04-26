package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"

	"github.com/tink-crypto/tink-go-gcpkms/v2/integration/gcpkms"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	keysetutil "github.com/salrashid123/tink-keyset-util"
)

var (
	key = flag.String("key", "9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ=", "raw key")

	kmsURI = flag.String("master-key-uri", "", "MasterKeyURI for encrypted keyset")
)

func main() {

	flag.Parse()
	ctx := context.Background()
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	if err != nil {
		log.Fatal(err)
	}

	kmsaead, err := gcpClient.GetAEAD(*kmsURI)
	if err != nil {
		log.Fatal(err)
	}

	k, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		log.Fatal(err)
	}
	ek, err := keysetutil.CreateAES256_GCM(k, 4112199248, tinkpb.OutputPrefixType_TINK, kmsaead)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)

	}

	log.Println("Tink Keyset:\n", prettyJSON.String())

}
