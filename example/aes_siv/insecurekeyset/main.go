package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/tink-crypto/tink-go/v2/daead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"google.golang.org/protobuf/proto"

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

	a, err := daead.New(keysetHandle)
	if err != nil {
		log.Fatal(err)
	}

	ec, err := a.EncryptDeterministically([]byte("foo"), []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encrypted Data: %s", hex.EncodeToString(ec))

	rk, err := ku.GetRawAesSivKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Raw key: %s", hex.EncodeToString(rk))

	re, err := ku.GetRawCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Raw Encrypted Data: %s", hex.EncodeToString(re))

	// i cound't find a reliable aes-siv library in golang but i did verify the
	//  output using https://artjomb.github.io/cryptojs-extension/
	// ciphertext: 5105f3e4c17aaad6349c2e73addae28a53704e
	// key:  ab31f24a4e61c819b5c9fde1257f21ea957f6ec597e9cc481b2fb6f05f871b29a8921e1cc79ec9f8c5a967f316cf0d7924a109c2672ccc310d90ac9d93f0074e
	// aad: some additional data

	// just to test the reverse
	// recreate the tink aes-siv keyset from scratch but specify the siv key we just go

	k := &sivpb.AesSivKey{
		Version:  0,
		KeyValue: rk,
	}

	serialized, err := proto.Marshal(k)
	if err != nil {
		log.Fatal(err)
	}

	ks := &tinkpb.Keyset{
		PrimaryKeyId: keysetHandle.KeysetInfo().PrimaryKeyId,
		Key: []*tinkpb.Keyset_Key{{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         "type.googleapis.com/google.crypto.tink.AesSivKey",
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value:           serialized,
			},
			KeyId:            keysetHandle.KeysetInfo().PrimaryKeyId,
			Status:           tinkpb.KeyStatusType_ENABLED,
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		},
		},
	}
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(ks); err != nil {
		log.Fatal(err)
	}

	buf2 := bytes.NewBuffer(buf.Bytes())
	r := keyset.NewJSONReader(buf2)
	nkh, err := insecurecleartextkeyset.Read(r)
	if err != nil {
		log.Fatal(err)
	}

	b, err := daead.New(nkh)
	if err != nil {
		log.Fatal(err)
	}

	dec, err := b.DecryptDeterministically(ec, []byte("some additional data"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Tink Decrypted: %s", string(dec))
}
