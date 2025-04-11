package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"os"

	keysetutil "github.com/salrashid123/tink-keyset-util"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyFile = flag.String("keyFile", "keysets/ecc_public.pem", "raw Public PEM key")
	keyid   = flag.Uint("keyid", 1957864605, "raw key")
)

func main() {

	flag.Parse()

	b, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal(err)
	}

	k := &ecdsapb.EcdsaPublicKey{
		Version: 0,
		Params: &ecdsapb.EcdsaParams{
			HashType: common_go_proto.HashType_SHA256,
			Curve:    common_go_proto.EllipticCurveType_NIST_P256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		X: ecdsaPub.X.Bytes(),
		Y: append([]byte{0}, ecdsaPub.Y.Bytes()...),
	}

	// note, we're using output of OutputPrefixType_RAW just so we can easily confirm the key+data we used is correct.
	//  other than that, you can ofcourse just set the prefix to OutputPrefixType_TINK but then you'd have to process
	// the mac and account for the prefix.  See hmac_export/main.go about that
	ek, err := keysetutil.ImportPublicKey(k, uint32(*keyid), tinkpb.OutputPrefixType_TINK, nil)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "\t")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	log.Println(prettyJSON.String())

}
