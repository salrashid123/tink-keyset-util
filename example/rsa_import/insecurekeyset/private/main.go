package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"

	keysetutil "github.com/salrashid123/tink-keyset-util"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var (
	keyFile = flag.String("keyFile", "keysets/rsa_private.pem", "raw Public PEM key")
	keyid   = flag.Uint("keyid", 4198955199, "raw key")
)

func main() {

	flag.Parse()

	b, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	rk := rsaKey.PublicKey
	pk := &rsppb.RsaSsaPkcs1PublicKey{
		Version: 0,
		Params: &rsppb.RsaSsaPkcs1Params{
			HashType: common_go_proto.HashType_SHA256,
		},
		N: append([]byte{0}, rk.N.Bytes()...),
		E: big.NewInt(int64(rk.E)).Bytes(),
	}

	k := &rsppb.RsaSsaPkcs1PrivateKey{
		Version:   0,
		PublicKey: pk,
		D:         rsaKey.D.Bytes(),
		P:         rsaKey.Primes[0].Bytes(),
		Q:         rsaKey.Primes[1].Bytes(),
		Dp:        rsaKey.Precomputed.Dp.Bytes(),
		Dq:        rsaKey.Precomputed.Dq.Bytes(),
		Crt:       rsaKey.Precomputed.Qinv.Bytes(),
	}

	// note, we're using output of OutputPrefixType_RAW just so we can easily confirm the key+data we used is correct.
	//  other than that, you can ofcourse just set the prefix to OutputPrefixType_TINK but then you'd have to process
	// the mac and account for the prefix.  See hmac_export/main.go about that
	ek, err := keysetutil.ImportPrivateKey(k, uint32(*keyid), tinkpb.OutputPrefixType_TINK, nil)
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
