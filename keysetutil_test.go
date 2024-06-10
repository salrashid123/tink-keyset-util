package keysetutil

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

var ()

const (
	AES_GCM_JSON_KEYSET   = "example/keysets/aes_gcm_1.json"
	AES_GCM_BINARY_KEYSET = "example/keysets/aes_gcm_1.bin"
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

	rk, err := ku.GetRawAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	require.NoError(t, err)

	aesCipher, err := aes.NewCipher(rk)
	require.NoError(t, err)

	rawAES, err := cipher.NewGCM(aesCipher)
	require.NoError(t, err)

	ecca, err := ku.GetRawCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)
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

	ek, err := CreateSymmetricKey(&k, uint32(keyid), tinkpb.OutputPrefixType_TINK, nil)
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
