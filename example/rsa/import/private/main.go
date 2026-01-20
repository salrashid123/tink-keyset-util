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
	keyFile = flag.String("keyFile", "/tmp/rsa_1_private.pem", "raw Public PEM key")
	keyid   = flag.Uint("keyid", 4198955199, "raw key")
	keyout  = flag.String("keyout", "/tmp/rsa_1_private.json", "raw Public PEM key")
	prefix  = flag.String("prefix", "tink", "output prefix for the key (tink|raw)")
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

	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	pk := &rsppb.RsaSsaPkcs1PublicKey{
		Version: 0,
		Params: &rsppb.RsaSsaPkcs1Params{
			HashType: common_go_proto.HashType_SHA256,
		},
		N: prependpad(rsaKey.N), //append([]byte{0}, rsaKey.N.Bytes()...),
		E: big.NewInt(int64(rsaKey.E)).Bytes(),
	}

	// remember to prepend the 0 byte...
	// // 	its the only way i could get this to work;  it seems to be the padding for b64 and hex encoding that proto does for[]byte fields.
	dpi := prependpad(rsaKey.Precomputed.Dp)
	dqi := prependpad(rsaKey.Precomputed.Dq)
	qi := prependpad(rsaKey.Precomputed.Qinv)

	k := &rsppb.RsaSsaPkcs1PrivateKey{
		Version:   0,
		PublicKey: pk,
		D:         rsaKey.D.Bytes(),
		P:         prependpad(rsaKey.Primes[0]), //append([]byte{0}, rsaKey.Primes[0].Bytes()...),
		Q:         prependpad(rsaKey.Primes[1]), //append([]byte{0}, rsaKey.Primes[1].Bytes()...),
		Dp:        dpi,                          //rsaKey.Precomputed.Dp.Bytes(),
		Dq:        dqi,                          //rsaKey.Precomputed.Dq.Bytes(),
		Crt:       qi,                           //rsaKey.Precomputed.Qinv.Bytes(),
	}

	format := tinkpb.OutputPrefixType_TINK

	if *prefix == "raw" {
		format = tinkpb.OutputPrefixType_RAW
	}

	// jsonData, err := protojson.Marshal(k)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(string(jsonData))

	ek, err := keysetutil.ImportPrivateKey(k, uint32(*keyid), format, nil)
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
