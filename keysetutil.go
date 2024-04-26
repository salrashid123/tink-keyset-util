package keysetutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"

	aesctrhmac "github.com/tink-crypto/tink-go/v2/proto/aes_ctr_hmac_aead_go_proto"
	gcmpb "github.com/tink-crypto/tink-go/v2/proto/aes_gcm_go_proto"
	sivpb "github.com/tink-crypto/tink-go/v2/proto/aes_siv_go_proto"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	rsppb "github.com/tink-crypto/tink-go/v2/proto/rsa_ssa_pkcs1_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
)

type KeySetUtilConfig struct {
	KekAEAD     tink.AEAD
	KeySetBytes []byte
}

type KeySetUtil struct {
	kekAEAD      tink.AEAD
	keysetHandle *keyset.Handle
	keysetKeys   []*tinkpb.Keyset_Key
}

var ()

const (
	// AESGCMIVSize is the only IV size that TINK supports.
	// https://pkg.go.dev/github.com/mightyguava/tink/go/subtle/aead#pkg-constants
	AESGCMIVSize = 12

	// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
	// NonRawPrefixSize is the prefix size of Tink and Legacy key types.
	nonRawPrefixSize = 5

	// TinkPrefixSize is the prefix size of Tink key types.
	// The prefix starts with \x01 and followed by a 4-byte key id.
	tinkPrefixSize = nonRawPrefixSize
	// TinkStartByte is the first byte of the prefix of Tink key types.
	tinkStartByte = byte(1)

	// RawPrefixSize is the prefix size of Raw key types.
	// Raw prefix is empty.
	rawPrefixSize = 0
	// RawPrefix is the empty prefix of Raw key types.
	rawPrefix = ""

	AesGcmKeyTypeURL             = "type.googleapis.com/google.crypto.tink.AesGcmKey"
	AesSivKeyTypeURL             = "type.googleapis.com/google.crypto.tink.AesSivKey"
	AesCtrHmacTypeURL            = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey"
	RsaSsaPkcs1PrivateKeyTypeURL = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey"
	RsaSsaPkcs1VerifierTypeURL   = "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey"
	EcdsaVerifierTypeURL         = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey"
	EcdsaPrivateKeyTypeURL       = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
)

func NewTinkKeySetUtil(ctx context.Context, keysetConfig *KeySetUtilConfig) (*KeySetUtil, error) {

	if keysetConfig.KekAEAD == nil {
		keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetConfig.KeySetBytes))
		keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)
		if err != nil {
			return nil, err
		}
		tpb := &tinkpb.Keyset{}

		err = proto.Unmarshal(keysetConfig.KeySetBytes, tpb)
		if err != nil {
			return nil, err
		}
		return &KeySetUtil{
			keysetHandle: keysetHandle,
			keysetKeys:   tpb.Key,
		}, nil
	} else {
		kmsaead := keysetConfig.KekAEAD
		keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetConfig.KeySetBytes))
		keysetHandle, err := keyset.Read(keysetReader, kmsaead)
		if err != nil {
			return nil, err
		}

		etpb := &tinkpb.EncryptedKeyset{}

		err = proto.Unmarshal(keysetConfig.KeySetBytes, etpb)
		if err != nil {
			return nil, err
		}

		// https://github.com/tink-crypto/tink-go/issues/4
		ekeysetBytes, err := keysetConfig.KekAEAD.Decrypt(etpb.EncryptedKeyset, []byte{})
		if err != nil {
			return nil, err
		}
		tpb := &tinkpb.Keyset{}
		err = proto.Unmarshal(ekeysetBytes, tpb)
		if err != nil {
			return nil, err
		}
		return &KeySetUtil{
			keysetHandle: keysetHandle,
			keysetKeys:   tpb.Key,
		}, nil
	}
}

func (h *KeySetUtil) GetRawCipherText(ciphertext []byte, keyID uint32) ([]byte, error) {
	var ecca []byte
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.OutputPrefixType == tinkpb.OutputPrefixType_TINK {
				pf := createOutputPrefix(tinkPrefixSize, tinkStartByte, keyID)
				ecca = ciphertext[len([]byte(pf)):]
			} else if k.OutputPrefixType == tinkpb.OutputPrefixType_RAW {
				ecca = ciphertext
			} else {
				return nil, fmt.Errorf("unsupporte outputprefix %s", k.OutputPrefixType.String())
			}
			return ecca, nil
		}
	}
	return nil, fmt.Errorf("keyid ot found %d", keyID)
}

func (h *KeySetUtil) GetKeySetTypeURL() string {
	for _, k := range h.keysetKeys {
		return k.KeyData.TypeUrl
	}
	return ""
}

func (h *KeySetUtil) GetPrimaryKeyID() uint32 {
	return h.keysetHandle.KeysetInfo().PrimaryKeyId
}

func (h *KeySetUtil) GetKeys() []*tinkpb.Keyset_Key {
	return h.keysetKeys
}

func (h *KeySetUtil) GetRawAesGcmKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == AesGcmKeyTypeURL {
				aeskey := &gcmpb.AesGcmKey{}
				err := proto.Unmarshal(k.KeyData.Value, aeskey)
				if err != nil {
					return nil, err
				}
				return aeskey.KeyValue, nil
			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", AesGcmKeyTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

func (h *KeySetUtil) GetRawAesSivKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == AesSivKeyTypeURL {
				aeskey := &sivpb.AesSivKey{}
				err := proto.Unmarshal(k.KeyData.Value, aeskey)
				if err != nil {
					return nil, err
				}
				return aeskey.KeyValue, nil
			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", AesSivKeyTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

func (h *KeySetUtil) GetRawAesCtrHmacAeadKey(keyID uint32) ([]byte, []byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == AesCtrHmacTypeURL {
				aeskey := &aesctrhmac.AesCtrHmacAeadKey{}
				err := proto.Unmarshal(k.KeyData.Value, aeskey)
				if err != nil {
					return nil, nil, err
				}
				return aeskey.AesCtrKey.KeyValue, aeskey.HmacKey.KeyValue, nil
			} else {
				return nil, nil, fmt.Errorf(" KeyType expected %s, found  %s", AesCtrHmacTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

func (h *KeySetUtil) GetRawRsaSsaPkcs1PrivateKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == RsaSsaPkcs1PrivateKeyTypeURL {
				key := &rsppb.RsaSsaPkcs1PrivateKey{}
				if err := proto.Unmarshal(k.KeyData.Value, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}

				privKey := &rsa.PrivateKey{
					D: bytesToBigInt(key.GetD()),
					PublicKey: rsa.PublicKey{
						N: bytesToBigInt(key.GetPublicKey().GetN()),
						E: int(bytesToBigInt(key.GetPublicKey().GetE()).Int64()),
					},
					Primes: []*big.Int{
						bytesToBigInt(key.GetP()),
						bytesToBigInt(key.GetQ()),
					},
				}
				return x509.MarshalPKCS1PrivateKey(privKey), nil
			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", RsaSsaPkcs1PrivateKeyTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

func (h *KeySetUtil) GetRawRsaSsaPkcs1PublicKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == RsaSsaPkcs1VerifierTypeURL {
				kserialized := k.KeyData.Value
				key := &rsppb.RsaSsaPkcs1PublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}
				publicKey := &rsa.PublicKey{
					N: bytesToBigInt(key.GetN()),
					E: int(bytesToBigInt(key.GetE()).Int64()),
				}
				return x509.MarshalPKIXPublicKey(publicKey)
			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", RsaSsaPkcs1VerifierTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

// getECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
func getECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.GetHashType())]
	curveName := commonpb.EllipticCurveType_name[int32(params.GetCurve())]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.GetEncoding())]
	return hashName, curveName, encodingName
}

func (h *KeySetUtil) GetRawEcdsaPrivateKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == EcdsaPrivateKeyTypeURL {
				key := &ecdsapb.EcdsaPrivateKey{}
				if err := proto.Unmarshal(k.KeyData.Value, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}
				if key.PublicKey.Params.Curve == commonpb.EllipticCurveType_NIST_P256 {
					privKey := &ecdsa.PrivateKey{
						D: bytesToBigInt(key.KeyValue),
					}
					privKey.Curve = elliptic.P256()
					privKey.PublicKey.X, privKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(k.KeyData.Value)
					return x509.MarshalECPrivateKey(privKey)
				} else {
					return nil, fmt.Errorf(" only EllipticCurveType_NIST_P256 supported found  %s", key.PublicKey.Params.String())
				}
				// https://github.com/tink-crypto/tink-go/blob/1f822b1098ae59ba7df4e63ee3e333b9ba51c347/signature/subtle/ecdsa_signer.go#L43

			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", EcdsaPrivateKeyTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

func (h *KeySetUtil) GetRawEcdsaPublicKey(keyID uint32) ([]byte, error) {
	for _, k := range h.keysetKeys {
		if k.KeyId == keyID {
			if k.KeyData.TypeUrl == EcdsaVerifierTypeURL {
				kserialized := k.KeyData.Value
				key := &ecdsapb.EcdsaPublicKey{}
				if err := proto.Unmarshal(kserialized, key); err != nil {
					return nil, fmt.Errorf("could not write unmarshall publicKey %v", err)
				}
				if key.Params.Curve == commonpb.EllipticCurveType_NIST_P256 {
					publicKey := &ecdsa.PublicKey{
						Curve: elliptic.P256(),
						X:     bytesToBigInt(key.X),
						Y:     bytesToBigInt(key.Y),
					}
					return x509.MarshalPKIXPublicKey(publicKey)
				} else {
					return nil, fmt.Errorf(" only EllipticCurveType_NIST_P256 supported found  %s", key.Params.Curve.String())
				}
			} else {
				return nil, fmt.Errorf(" KeyType expected %s, found  %s", EcdsaVerifierTypeURL, k.KeyData.TypeUrl)
			}
		}
	}
	return nil, fmt.Errorf("keyID not found in keyset %d", keyID)
}

// https://github.com/google/tink/blob/master/go/core/cryptofmt/cryptofmt.go#L68
func createOutputPrefix(size int, startByte byte, keyID uint32) string {
	prefix := make([]byte, size)
	prefix[0] = startByte
	binary.BigEndian.PutUint32(prefix[1:], keyID)
	return string(prefix)
}

func bytesToBigInt(v []byte) *big.Int {
	return new(big.Int).SetBytes(v)
}

// *******************************************************

func CreateAES256_GCM(rawKey []byte, keyid uint32, format tinkpb.OutputPrefixType, kekaead tink.AEAD) ([]byte, error) {

	tk, err := subtle.NewAESGCM(rawKey)
	if err != nil {
		return nil, err
	}
	k := &gcmpb.AesGcmKey{
		Version:  0,
		KeyValue: tk.Key(),
	}

	keyserialized, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}

	var bufbytes []byte
	if kekaead == nil {
		keysetKey := &tinkpb.Keyset_Key{
			KeyData: &tinkpb.KeyData{
				TypeUrl:         AesGcmKeyTypeURL,
				KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
				Value:           keyserialized,
			},
			KeyId:            keyid,
			Status:           tinkpb.KeyStatusType_ENABLED,
			OutputPrefixType: tinkpb.OutputPrefixType_TINK,
		}

		ks := &tinkpb.Keyset{
			PrimaryKeyId: keyid,
			Key:          []*tinkpb.Keyset_Key{keysetKey},
		}

		buf := new(bytes.Buffer)
		w := keyset.NewJSONWriter(buf)
		if err := w.Write(ks); err != nil {
			return nil, err
		}
		bufbytes = buf.Bytes()
	} else {

		ciphertext, err := kekaead.Encrypt(keyserialized, []byte(""))
		if err != nil {
			return nil, err
		}

		ksi := &tinkpb.KeysetInfo{
			PrimaryKeyId: keyid,
			KeyInfo: []*tinkpb.KeysetInfo_KeyInfo{
				{
					TypeUrl:          AesGcmKeyTypeURL,
					Status:           tinkpb.KeyStatusType_ENABLED,
					KeyId:            keyid,
					OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				},
			},
		}

		eks := &tinkpb.EncryptedKeyset{
			EncryptedKeyset: ciphertext,
			KeysetInfo:      ksi,
		}
		buf := new(bytes.Buffer)
		w := keyset.NewJSONWriter(buf)
		if err := w.WriteEncrypted(eks); err != nil {
			return nil, err
		}
		bufbytes = buf.Bytes()

	}
	return bufbytes, nil
}
