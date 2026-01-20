package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	keysetutil "github.com/salrashid123/tink-keyset-util"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	tinkecdsa "github.com/tink-crypto/tink-go/v2/signature/ecdsa"
)

var (
	keyFile = flag.String("keyFile", "keysets/ecc_private.pem", "raw Public PEM key")
	keyid   = flag.Uint("keyid", 1957864605, "raw key")
)

func main() {

	flag.Parse()

	b, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)

	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaPub := ecKey.PublicKey

	//see https://github.com/tink-crypto/tink-go/blob/main/signature/ecdsa/protoserialization.go#L332
	// The private key value may be padded with leading zeros (see b/264525021).
	// We simply make sure the private key value is of the correct size.
	coordinateSize, err := coordinateSizeForCurve(tinkecdsa.NistP256)
	x, err := BigIntBytesToFixedSizeBuffer(ecdsaPub.X.Bytes(), coordinateSize+1)
	if err != nil {
		log.Fatal(err)
	}
	y, err := BigIntBytesToFixedSizeBuffer(ecdsaPub.Y.Bytes(), coordinateSize+1)
	if err != nil {
		log.Fatal(err)
	}

	pk := &ecdsapb.EcdsaPublicKey{
		Version: 0,
		Params: &ecdsapb.EcdsaParams{
			HashType: common_go_proto.HashType_SHA256,
			Curve:    common_go_proto.EllipticCurveType_NIST_P256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		X: x, //append([]byte{0}, ecdsaPub.X.Bytes()...), // Tink prepends an extra 0x00 byte to the coordinates (b/264525021).
		Y: y, //append([]byte{0}, ecdsaPub.Y.Bytes()...),
	}

	k := &ecdsapb.EcdsaPrivateKey{
		Version:   0,
		PublicKey: pk,
		KeyValue:  append([]byte{0}, ecKey.D.Bytes()...),
	}

	ek, err := keysetutil.ImportPrivateKey(k, uint32(*keyid), tinkpb.OutputPrefixType_TINK, nil)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, ek, "", "  ")
	if error != nil {
		log.Fatalf("JSON parse error: %v ", error)
	}

	fmt.Printf("\n%s\n", prettyJSON.String())

}

// BigIntBytesToFixedSizeBuffer converts a big integer representation to a
// fixed size buffer.
//
// If the bytes representation is smaller, it is padded with leading zeros.
// If the bytes representation is larger, the leading bytes are removed.
// If the bytes representation is larger than the given size, an error is
// returned.
func BigIntBytesToFixedSizeBuffer(bigIntBytes []byte, size int) ([]byte, error) {
	// Nothing to do if the big integer representation is already of the given size.
	if len(bigIntBytes) == size {
		return bigIntBytes, nil
	}
	if len(bigIntBytes) < size {
		// Pad the big integer representation with leading zeros to the given size.
		buf := make([]byte, size-len(bigIntBytes), size)
		return append(buf, bigIntBytes...), nil
	}
	// Remove the leading len(bigIntValue)-size bytes. Fail if any is not zero.
	for i := 0; i < len(bigIntBytes)-size; i++ {
		if bigIntBytes[i] != 0 {
			return nil, fmt.Errorf("big int has invalid size: %v, want %v", len(bigIntBytes)-i, size)
		}
	}
	return bigIntBytes[len(bigIntBytes)-size:], nil
}

func coordinateSizeForCurve(curveType tinkecdsa.CurveType) (int, error) {
	switch curveType {
	case tinkecdsa.NistP256:
		return 32, nil
	case tinkecdsa.NistP384:
		return 48, nil
	case tinkecdsa.NistP521:
		return 66, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", curveType)
	}
}
