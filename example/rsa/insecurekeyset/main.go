package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
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

	if ku.GetKeySetTypeURL() == keysetutil.RsaSsaPkcs1VerifierTypeURL {
		pk, err := ku.GetRawRsaSsaPkcs1PublicKey(keysetHandle.KeysetInfo().PrimaryKeyId)
		if err != nil {
			log.Fatal(err)
		}

		if ku.GetKeySetTypeURL() == keysetutil.RsaSsaPkcs1VerifierTypeURL {
			pemdata := pem.EncodeToMemory(
				&pem.Block{
					Type:  "RSA PUBLIC KEY",
					Bytes: pk,
				},
			)

			log.Printf("RSA Key: \n%s\n", string(pemdata))
		}
	} else if ku.GetKeySetTypeURL() == keysetutil.RsaSsaPkcs1PrivateKeyTypeURL {

		rk, err := ku.GetRawRsaSsaPkcs1PrivateKey(keysetHandle.KeysetInfo().PrimaryKeyId)
		if err != nil {
			log.Fatal(err)
		}

		if ku.GetKeySetTypeURL() == keysetutil.RsaSsaPkcs1PrivateKeyTypeURL {
			pemdata := pem.EncodeToMemory(
				&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: rk,
				},
			)

			log.Printf("RSA Key: \n%s\n", string(pemdata))

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

			key, err := x509.ParsePKCS1PrivateKey(rk)
			if err != nil {
				log.Fatal(err)
			}

			digest := sha256.Sum256(msg)

			st, err := ku.GetRawCipherText(sig, keysetHandle.KeysetInfo().PrimaryKeyId)
			if err != nil {
				log.Fatal(err)
			}

			err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], st)
			if err != nil {
				log.Fatal(err)
			} else {
				log.Println("verified")
			}

		}
	}

}
