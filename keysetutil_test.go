package keysetutil

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/mac"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	common_go_proto "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	"github.com/tink-crypto/tink-go/v2/signature"
)

var ()

const (
	AES_GCM_JSON_KEYSET   = "example/keysets/aes_gcm_1.json"
	AES_GCM_BINARY_KEYSET = "example/keysets/aes_gcm_1.bin"
	RSA_BINARY_KEYSET     = "example/keysets/rsa_1_private.bin"
	ECC_BINARY_KEYSET     = "example/keysets/ecc_1_private.bin"
	HMAC_BINARY_KEYSET    = "example/keysets/hmac_bittag.bin"

	RSA_PUBLIC_PEM_FILE  = "example/keysets/rsa_public.pem"
	RSA_PRIVATE_PEM_FILE = "example/keysets/rsa_private.pem"
	ECC_PUBLIC_PEM_FILE  = "example/keysets/ecc_public.pem"
	ECC_PRIVATE_PEM_FILE = "example/keysets/ecc_public.pem"
)

func TestReadJSONKeyset(t *testing.T) {

	keysetBytes, err := os.ReadFile(AES_GCM_JSON_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	_, err = insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

}

func TestReadBinaryKeyset(t *testing.T) {

	keysetBytes, err := os.ReadFile(AES_GCM_JSON_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	_, err = insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

}

func TestAESGCMKeyExport(t *testing.T) {

	keysetBytes, err := os.ReadFile(AES_GCM_JSON_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	ku, err := NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))

	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

	a, err := aead.New(keysetHandle)
	require.NoError(t, err)

	plainText := []byte("foo")

	ec, err := a.Encrypt(plainText, []byte("some additional data"))
	require.NoError(t, err)

	rk, err := ku.ExportAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	aesCipher, err := aes.NewCipher(rk)
	require.NoError(t, err)

	rawAES, err := cipher.NewGCM(aesCipher)
	require.NoError(t, err)

	ecca, err := ku.ExportCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	decryptedText, err := rawAES.Open(nil, ecca[:AESGCMIVSize], ecca[AESGCMIVSize:], []byte("some additional data"))
	require.NoError(t, err)

	require.Equal(t, plainText, decryptedText)
}

func TestAESGCMKeyImport(t *testing.T) {

	// $ tinkey list-keyset --in-format=json --in=keysets/aes_gcm_1.json
	// primary_key_id: 1651423683
	// key_info {
	//   type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
	//   status: ENABLED
	//   key_id: 1651423683
	//   output_prefix_type: TINK
	// }

	key := "i9A1WsjDhDzrf78O+oVQBTZjqhXMUN0QgYl9bvMsuRQ="
	keyid := 1651423683

	kval, err := base64.StdEncoding.DecodeString(key)
	require.NoError(t, err)

	// aes-gcm
	k := gcmpb.AesGcmKey{
		Version:  0,
		KeyValue: kval,
	}

	ek, err := ImportSymmetricKey(&k, uint32(keyid), tinkpb.OutputPrefixType_TINK, nil)
	require.NoError(t, err)

	buf := bytes.NewBuffer(ek)
	r := keyset.NewJSONReader(buf)
	nkh, err := insecurecleartextkeyset.Read(r)
	require.NoError(t, err)

	// for aes-gcm. aes-gcm-ctr
	b, err := aead.New(nkh)
	require.NoError(t, err)

	dataToEncrypt := []byte("foo")

	ec, err := b.Encrypt(dataToEncrypt, []byte("some additional data"))
	require.NoError(t, err)

	dec, err := b.Decrypt(ec, []byte("some additional data"))
	require.NoError(t, err)

	require.Equal(t, dec, dataToEncrypt)

	// now read the AES_GCM_JSON_KEYSET (which has the same encryption key)
	// from file and decrypt the original data

	keysetBytes, err := os.ReadFile(AES_GCM_JSON_KEYSET)
	require.NoError(t, err)

	keysetReader := keyset.NewJSONReader(bytes.NewReader(keysetBytes))
	kh, err := insecurecleartextkeyset.Read(keysetReader)

	bb, err := aead.New(kh)
	require.NoError(t, err)

	dec2, err := bb.Decrypt(ec, []byte("some additional data"))
	require.NoError(t, err)

	require.Equal(t, dec2, dataToEncrypt)
}

func TestRSASignatureExport(t *testing.T) {

	keysetBytes, err := os.ReadFile(RSA_BINARY_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	ku, err := NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))

	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

	s, err := signature.NewSigner(keysetHandle)
	require.NoError(t, err)

	rk, err := ku.ExportRsaSsaPkcs1PrivateKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	key, err := x509.ParsePKCS1PrivateKey(rk)
	require.NoError(t, err)

	msg := []byte("this data needs to be signed")

	sig, err := s.Sign(msg)
	require.NoError(t, err)

	digest := sha256.Sum256(msg)

	st, err := ku.ExportCipherText(sig, keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], st)
	require.NoError(t, err)
}

func TestECCSignatureExport(t *testing.T) {

	keysetBytes, err := os.ReadFile(ECC_BINARY_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	ku, err := NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))

	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

	s, err := signature.NewSigner(keysetHandle)
	require.NoError(t, err)

	rk, err := ku.ExportEcdsaPrivateKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	key, err := x509.ParseECPrivateKey(rk)
	require.NoError(t, err)

	msg := []byte("this data needs to be signed")

	sig, err := s.Sign(msg)
	require.NoError(t, err)

	digest := sha256.Sum256(msg)

	st, err := ku.ExportCipherText(sig, keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	ok := ecdsa.VerifyASN1(&key.PublicKey, digest[:], st)
	require.True(t, ok)
}

func TestRSAExportImportPublic(t *testing.T) {

	pubPEMBytes, err := os.ReadFile(RSA_PUBLIC_PEM_FILE)
	require.NoError(t, err)

	block, _ := pem.Decode(pubPEMBytes)
	rk, err := x509.ParsePKCS1PublicKey(block.Bytes)
	require.NoError(t, err)

	k := &rsppb.RsaSsaPkcs1PublicKey{
		Version: 0,
		Params: &rsppb.RsaSsaPkcs1Params{
			HashType: common_go_proto.HashType_SHA256,
		},
		N: append([]byte{0}, rk.N.Bytes()...),
		E: big.NewInt(int64(rk.E)).Bytes(),
	}

	_, err = ImportPublicKey(k, uint32(4198955199), tinkpb.OutputPrefixType_TINK, nil)
	require.NoError(t, err)

	// todo, unmarshal the bytes into a keyset and actually do something with it
}

func TestECCExportImportPublic(t *testing.T) {

	pubPEMBytes, err := os.ReadFile(ECC_PUBLIC_PEM_FILE)
	require.NoError(t, err)

	block, _ := pem.Decode(pubPEMBytes)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)

	k := &ecdsapb.EcdsaPublicKey{
		Version: 0,
		Params: &ecdsapb.EcdsaParams{
			HashType: common_go_proto.HashType_SHA256,
			Curve:    common_go_proto.EllipticCurveType_NIST_P256,
			Encoding: ecdsapb.EcdsaSignatureEncoding_DER,
		},
		X: ecdsaPub.X.Bytes(),
		Y: append([]byte{0}, ecdsaPub.Y.Bytes()...), // ecdsaPub.Y.Bytes(),
	}

	_, err = ImportPublicKey(k, uint32(1957864605), tinkpb.OutputPrefixType_TINK, nil)
	require.NoError(t, err)

	// todo, unmarshal the bytes into a keyset and actually do something with
	// alternatively, do the end  to end and push the returned bytes into
}

func TestHMACExport(t *testing.T) {

	keysetBytes, err := os.ReadFile(HMAC_BINARY_KEYSET)
	require.NoError(t, err)

	ctx := context.Background()

	ku, err := NewTinkKeySetUtil(ctx, &KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})
	require.NoError(t, err)

	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))

	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
	require.NoError(t, err)

	a, err := mac.New(keysetHandle)
	require.NoError(t, err)

	plaintText := "foo"
	ec, err := a.ComputeMAC([]byte(plaintText))
	require.NoError(t, err)

	rk, err := ku.ExportHMACKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	ecca, err := ku.ExportCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	h := hmac.New(sha256.New, rk)
	h.Write([]byte(plaintText))

	require.Equal(t, ecca, h.Sum(nil))

}
