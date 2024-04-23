## Tink Keyset Key Extractor


Utility function to extract the embedded AES, RSA or ECC key embedded inside a [tink-crypto](https://github.com/tink-crypto) cleartext or encrypted keyset.

This also allows you a way to remove the prefix added by Tink to most ciphertext data.

Use both these functions will allow you to encrypt or sign some data with Tink and use off the shelf libraries to decrypt/verify later.

This library and sample supplies methods to extract out the raw key and remove the prefixes for the ciphertext:


For key extraction:

* `GetRawAesGcmKey()`

  Extract the raw AES-GCM key from the keyset.  You can use this key to decrypt/encrypt data using standard google AES library

* `GetRawAesSivKey()`

   Extract the raw AES-SIV key from the keyset.  You can use this key to decrypt/encrypt data using standard google AES library

* `GetRawAesCtrHmacAeadKey()`

   Extract the raw AES and HMAC key from the keyset.

* `GetRawRsaSsaPkcs1PrivateKey()`

   Extract the RSA Private key from the keyset as DER bytes.

* `GetRawRsaSsaPkcs1PublicKey()`

   Extract the RSA Public key from the keyset as DER bytes.

* `GetRawEcdsaPrivateKey()`

   Extract the ECC Private key from the keyset as DER bytes.

* `GetRawEcdsaPublicKey()`
  
   Extract the ECC Public key from the keyset as DER bytes.


To process TINK encoded ciphertext or data

* `GetRawCipherText()`

  Returns the ciphertext or signature without the TINK prefix values.

  You can use this output with off the shelf crypto libraries to decrypt or verify.


see the [example/](example/) folder for details


---

>> this library is **NOT** supported by google

### Usage

For key extraction supply the keyset.


```golang
	// load the keyset
	keysetBytes, err := os.ReadFile(*insecureKeySetFile)
	var ku *keysetutil.KeySetUtil

	ku, err = keysetutil.NewTinkKeySetUtil(ctx, &keysetutil.KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})

	// print the raw key
   rk, err := ku.GetRawAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	log.Printf("Raw key: %s", base64.StdEncoding.EncodeToString(rk))
```

For prefix redaction, supply the ciphertext provided by a prior tink operation.

```golang

	// load the keyset
	keysetBytes, err := os.ReadFile(*insecureKeySetFile)
	keysetReader := keyset.NewBinaryReader(bytes.NewReader(keysetBytes))
	keysetHandle, err := insecurecleartextkeyset.Read(keysetReader)   
	a, err := aead.New(keysetHandle)

	// use tink to encrypt
	ec, err := a.Encrypt([]byte("foo"), []byte("some additional data"))   
	var ku *keysetutil.KeySetUtil

	// initialize this library
	ku, err = keysetutil.NewTinkKeySetUtil(ctx, &keysetutil.KeySetUtilConfig{
		KeySetBytes: keysetBytes,
	})

	// get the raw key from the keyset
	rk, err := ku.GetRawAesGcmKey(keysetHandle.KeysetInfo().PrimaryKeyId)
	log.Printf("Raw key: %s", base64.StdEncoding.EncodeToString(rk))

	// initialize aes cipher from this extracted key
	aesCipher, err := aes.NewCipher(rk)
	rawAES, err := cipher.NewGCM(aesCipher)

	// omit the ciphertext prefix
	ecca, err := ku.GetRawCipherText(ec, keysetHandle.KeysetInfo().PrimaryKeyId)

	// decrypt the tinkencrypted data using the raw ciphertext and raw aes key
	plaintext, err := rawAES.Open(nil, ecca[:keysetutil.AESGCMIVSize], ecca[keysetutil.AESGCMIVSize:], []byte("some additional data"))


```

THe following uses [tinkey](https://github.com/tink-crypto/tink-tinkey) to create binary keysets and then extract out the embedded keys

for reference:

* [tink-go-isseue#18: Extract PublicKey from signing keyset](https://github.com/tink-crypto/tink-go/issues/18)

### Insecure KeySet

```bash
$ tinkey list-key-templates
```

```bash
## AES128_GCM
$ tinkey create-keyset --key-template=AES256_GCM --out-format=binary --out=/tmp/1.bin

$ tinkey rotate-keyset --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/1.bin \
   --out-format=binary --out=/tmp/2.bin

$ tinkey rotate-keyset --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/2.bin \
   --out-format=binary --out=example/keysets/aes_gcm_1.bin

$ tinkey list-keyset --in-format=binary --in=example/keysets/aes_gcm_1.bin

primary_key_id: 4112199248
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 536538909
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 86374772
  output_prefix_type: TINK
}
key_info {
  type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
  status: ENABLED
  key_id: 4112199248
  output_prefix_type: TINK
}

$ go run aes/insecurekeyset/main.go --insecure-key-set keysets/aes_gcm_1.bin 

# AES256_SIV
$ tinkey create-keyset --key-template=AES256_SIV --out-format=binary --out=example/keysets/aes_siv.bin
$ go run aes_siv/insecurekeyset/main.go --insecure-key-set keysets/aes_siv.bin 

## AES256_CTR_HMAC_SHA256
$ tinkey create-keyset --key-template=AES256_CTR_HMAC_SHA256 --out-format=binary --out=example/keysets/aes_ctr_hmac_sha256.bin
$ go run aes_ctr/insecurekeyset/main.go --insecure-key-set keysets/aes_ctr_hmac_sha256.bin 

# RSA_SSA_PKCS1_3072_SHA256_F4
$ tinkey create-keyset --key-template=RSA_SSA_PKCS1_3072_SHA256_F4 --out-format=binary --out=example/keysets/rsa_1_private.bin
$ tinkey create-public-keyset --in-format=binary --in=example/keysets/rsa_1_private.bin --out-format=binary --out=example/keysets/rsa_1_public.bin
$ go run rsa/insecurekeyset/main.go --insecure-key-set keysets/rsa_1_private.bin 
$ go run rsa/insecurekeyset/main.go --insecure-key-set keysets/rsa_1_public.bin 

# ECDSA_P256
$ tinkey create-keyset --key-template=ECDSA_P256 --out-format=binary --out=example/keysets/ecc_1_private.bin
$ tinkey create-public-keyset --in=example/keysets/ecc_1_private.bin --in-format=binary --out-format=binary --out=example/keysets/ecc_1_public.bin
$ go run ecc/insecurekeyset/main.go --insecure-key-set keysets/ecc_1_private.bin 
$ go run ecc/insecurekeyset/main.go --insecure-key-set keysets/ecc_1_public.bin 
```

---

### Encrypted KeySet


To test encrypted keysets, you need to have access to a KMS

```bash

$ export PROJECT_ID=`gcloud config get-value core/project`
$ gcloud kms keyrings create kr1 --location=global
$ gcloud kms keys create --keyring=kr1 --location=global --purpose=encryption  k1

$ gcloud auth applicaton-default login

$ export MASTERKEY="gcp-kms://projects/$PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/k1"

$ tinkey create-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM --out-format=binary --out=/tmp/1.bin

$ tinkey rotate-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/1.bin \
   --out-format=binary --out=/tmp/2.bin

$ tinkey rotate-keyset --master-key-uri=$MASTERKEY --key-template=AES256_GCM \
   --in-format=binary \
   --in=/tmp/2.bin \
   --out-format=binary --out=example/keysets/aes_gcm_1_kms.bin


$ go run aes/encryptedkeyset/main.go --encrypted-key-set keysets/aes_gcm_1_kms.bin --master-key-uri=$MASTERKEY
```
