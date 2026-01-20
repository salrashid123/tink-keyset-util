package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	"github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"

	keysetutil "github.com/salrashid123/tink-keyset-util"
)

// text = foo
// key = change this password to a secret
// b64(key) = Y2hhbmdlIHRoaXMgcGFzc3dvcmQgdG8gYSBzZWNyZXQ=

// hmacsha256(key,text) = 7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2
var (
	key        = flag.String("key", "Y2hhbmdlIHRoaXMgcGFzc3dvcmQgdG8gYSBzZWNyZXQ=", "raw key")
	format     = flag.String("format", "tink", "raw key")
	keyid      = flag.Uint("keyid", 4112199248, "raw key")
	plaintText = flag.String("plaintText", "foo", "some data to mac")
)

func main() {

	flag.Parse()

	hk, err := base64.StdEncoding.DecodeString(*key)
	if err != nil {
		panic(err)
	}

	keyformat := tinkpb.OutputPrefixType_TINK
	if *format == "raw" {
		keyformat = tinkpb.OutputPrefixType_RAW
	}
	// note, we're using output of OutputPrefixType_RAW just so we can easily confirm the key+data we used is correct.
	//  other than that, you can ofcourse just set the prefix to OutputPrefixType_TINK but then you'd have to process
	// the mac and account for the prefix.  See hmac_export/main.go about that
	ek, err := keysetutil.ImportHMACKey(hk, uint32(*keyid), common_go_proto.HashType_SHA256, keyformat, nil)
	if err != nil {
		panic(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "  ")
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

	a, err := mac.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := a.ComputeMAC([]byte(*plaintText))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Tink HMAC: %s", hex.EncodeToString(ec))

}
