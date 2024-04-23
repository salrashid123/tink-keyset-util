package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"

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

	if ku.GetKeySetTypeURL() == keysetutil.EcdsaVerifierTypeURL {
		pk, err := ku.GetRawEcdsaPublicKey(keysetHandle.KeysetInfo().PrimaryKeyId)
		if err != nil {
			log.Fatal(err)
		}

		if ku.GetKeySetTypeURL() == keysetutil.EcdsaVerifierTypeURL {
			pemdata := pem.EncodeToMemory(
				&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pk,
				},
			)

			log.Printf("ECC Key: %s\n", string(pemdata))
		}
	} else if ku.GetKeySetTypeURL() == keysetutil.EcdsaPrivateKeyTypeURL {

		rk, err := ku.GetRawEcdsaPrivateKey(keysetHandle.KeysetInfo().PrimaryKeyId)
		if err != nil {
			log.Fatal(err)
		}

		if ku.GetKeySetTypeURL() == keysetutil.EcdsaPrivateKeyTypeURL {
			pemdata := pem.EncodeToMemory(
				&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: rk,
				},
			)

			log.Printf("ECC Key: %s\n", string(pemdata))

			s, err := signature.NewSigner(keysetHandle)
			if err != nil {
				log.Fatal(err)
			}

			msg := []byte("this data needs to be signed")
			sig, err := s.Sign(msg)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf(" signature: %s\n", base64.StdEncoding.EncodeToString(sig))

			key, err := x509.ParseECPrivateKey(rk)
			if err != nil {
				log.Fatal(err)
			}

			digest := sha256.Sum256(msg)

			st, err := ku.GetRawCipherText(sig, keysetHandle.KeysetInfo().PrimaryKeyId)
			if err != nil {
				log.Fatal(err)
			}

			ok := ecdsa.VerifyASN1(&key.PublicKey, digest[:], st)
			if !ok {
				log.Printf("Failed verification.")
				return
			}

			log.Printf(">>>>>> Signature ASN1 Verified")

			curveBits := elliptic.P256().Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes += 1
			}
			out := make([]byte, 2*keyBytes)
			var sigStruct struct{ R, S *big.Int }
			_, err = asn1.Unmarshal(st, &sigStruct)
			if err != nil {
				log.Printf("Failed verification.")
				return
			}
			sigStruct.R.FillBytes(out[0:keyBytes])
			sigStruct.S.FillBytes(out[keyBytes:])

			ok = ecdsa.Verify(&key.PublicKey, digest[:], sigStruct.R, sigStruct.S)
			if !ok {
				log.Printf("Failed verification.")
				return
			}

			log.Printf(">>>>>> Signature RAW Verified")

		}
	}

}
