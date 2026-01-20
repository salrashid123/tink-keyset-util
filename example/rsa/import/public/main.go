package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"

	keysetutil "github.com/salrashid123/tink-keyset-util"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyFile = flag.String("keyFile", "keysets/rsa_public.pem", "raw Public PEM key")
	keyout  = flag.String("keyout", "/tmp/rsa_1_public.json", "raw Public PEM key")
	keyid   = flag.Uint("keyid", 4198955199, "raw key")
)

func prependpad(in *big.Int) []byte {
	if (in.BitLen()/8)%3 == 0 {
		return append([]byte{0}, in.Bytes()...)
	}
	return in.Bytes()
}

func main() {

	flag.Parse()

	b, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)

	rsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	// https://github.com/tink-crypto/tink-go/blob/e9f750c0b09e0875dda1a7d9fca9c3a98b55479b/signature/rsassapkcs1/verifier_key_manager_test.go#L43
	k := &rsppb.RsaSsaPkcs1PublicKey{
		Version: 0,
		Params: &rsppb.RsaSsaPkcs1Params{
			HashType: common_go_proto.HashType_SHA256,
		},
		N: prependpad(rsaKey.N), //append([]byte{0}, rsaKey.N.Bytes()...), // remember to prepend null byte...
		// 	its the only way i could get this to work;  it seems to be the padding for b64 and hex encoding that proto does for[]byte fields.
		E: big.NewInt(int64(rsaKey.E)).Bytes(),
	}

	ek, err := keysetutil.ImportPublicKey(k, uint32(*keyid), tinkpb.OutputPrefixType_TINK, nil)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "  ")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	fmt.Println(prettyJSON.String())

	err = os.WriteFile(*keyout, ek, 0644)
	if err != nil {
		log.Fatal(err)
	}

}
