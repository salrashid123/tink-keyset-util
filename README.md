## Tink Keyset Key Utility 

Utility function to extract or the embedded AES, RSA or ECC key embedded inside a [tink-crypto](https://github.com/tink-crypto) cleartext or encrypted keyset.  In addition, use this library to _import_ an external key into a tink keyset.

This repo also also allows you a way to remove the prefix added by Tink to most ciphertext data generated by Tink.

Using both these functions will allow you to encrypt or sign some data with Tink and use off the shelf libraries to decrypt/verify later.


For key extraction, consider the following `AESGCM` keyset:

```bash
$ cat keysets/aes_gcm_1.json | jq '.'
{
  "primaryKeyId": 4112199248,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiD13XtsvWS5ZV8R+f2yQUjsJqiy39f9B/X9Zp+XXiDIZA==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 4112199248,
      "outputPrefixType": "TINK"
    }
  ]
}
```

The `value` isn't the raw  AESGCM Key but its actually the [AesGcmKey proto](https://github.com/tink-crypto/tink-go/blob/main/proto/aes_gcm.proto#L64).

This sample will decode the proto and show the raw encryption key which you can directly use with off the shelf `crypto/aes` library

```bash
$ go run aes_export/insecurekeyset/main.go --insecure-key-set keysets/aes_gcm_1.bin 
		Raw key: 9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ=
```

If you use TINK to encrypt any data, then the ciphertext can have various prefixes added in by Tink.  Which means even with the raw key, the ciphertext wont decrypt.  These prefixes are descried in [TINK wire format prefixes](https://developers.google.com/tink/wire-format)

This library will detect the output type declared in the keyset, then remove the prefix value if `outputPrefix=TINK` was set using the primary KEYID so you can decrypt easily.   

For an end-to-end example with AESGCM, see [example/aes_export/insecurekeyset/main.go](example/aes_export/insecurekeyset/main.go)

---

You can also use this library to embed an *external* AES-GCM key *into* a Tink insecure or encrypted keyset.  In other words, if you have a raw aes gcm key, you can embed that into a TINK keyset.  In other words, if you already have an AES-GCM key, you can use this library to create a tink keyset with that key.  see ]example/aes_import/insecurekeyset/main.go](example/aes_import/insecurekeyset/main.go)

---

This repo is a generic implementation of 

* [Importing and extracting external keys for BigQuery AEAD Tink KeySets](https://github.com/salrashid123/bq_aead_key)

---

### Key export

The key types supported are:

* `GetRawAesGcmKey()`

  Extract the raw AES-GCM key from the keyset.  You can use this key to decrypt/encrypt data using standard google AES library

* `GetRawAesSivKey()`

   Extract the raw AES-SIV key from the keyset.  You can use this key to decrypt/encrypt data using standard google AES library

* `GetRawAesCtrHmacAeadKey()`

   Extract the raw AES and HMAC key from the keyset.  Using off the shelf libraries requires reversing [this](https://developers.google.com/tink/streaming-aead/aes_ctr_hmac_streaming) process.

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

### Key Import

* `CreateAES256_GCM()`

  Supply the raw aes key, the keyID to use and the output prefix to apply for this keyset

  If an external KMS KEK is provided, the output will be an encryptedKeySet

* `CreateHMAC()`

   Unimplemented but easy to do.  see [tink_samples/external_hmac](https://github.com/salrashid123/tink_samples/tree/main/external_hmac)

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

for reference also see
* [tink_samples](https://github.com/salrashid123/tink_samples)
* [tink-go-isseue#18: Extract PublicKey from signing keyset](https://github.com/tink-crypto/tink-go/issues/18)

### Insecure KeySet

```bash
$ tinkey list-key-templates
```

```bash
## AES256_GCM
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

$ go run aes_export/insecurekeyset/main.go --insecure-key-set keysets/aes_gcm_1.bin 

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


$ go run aes_export/encryptedkeyset/main.go --encrypted-key-set keysets/aes_gcm_1_kms.bin --master-key-uri=$MASTERKEY
```

---

### Importing existing AES Key

To import an external AES_GCM key is pretty simple:

The following will create an AES_GCM Tink Keyset with the specified key, keyid and output prefix.

The return value is JSON keyset byte which you can convert to a JSON or Binary keyset for persistence.

```golang
	key := "9d17bL1kuWVfEfn9skFI7Caost/X/Qf1/Wafl14gyGQ="
	keyid := 4112199248
	ek, err := keysetutil.CreateAES128_GCM(k, 4112199248, tinkpb.OutputPrefixType_TINK, nil)
```

```log
$ go run aes_import/insecurekeyset/main.go 
2024/04/25 22:49:51 Tink Keyset:
 {
	"primaryKeyId": 4112199248,
	"key": [
		{
			"keyData": {
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"value": "GiD13XtsvWS5ZV8R+f2yQUjsJqiy39f9B/X9Zp+XXiDIZA==",
				"keyMaterialType": "SYMMETRIC"
			},
			"status": "ENABLED",
			"keyId": 4112199248,
			"outputPrefixType": "TINK"
		}
	]
}
2024/04/25 22:49:51 Tink Decrypted: foo

```

- Encrypted KeySet

For an encrypted keyset, supply the kek aead:

```golang
	gcpClient, err := gcpkms.NewClientWithOptions(ctx, "gcp-kms://")
	kmsaead, err := gcpClient.GetAEAD(*kmsURI)

	ek, err := keysetutil.CreateAES256_GCM(k, 4112199248, tinkpb.OutputPrefixType_TINK, kmsaead)
```

```log
$ go run aes_import/encryptedkeyset/main.go --master-key-uri=$MASTERKEY

2024/04/25 22:24:20 Tink Keyset:
 {
	"encryptedKeyset": "CiQAhitNP4eOsQPhMlF5W9YX4xM3PFl9r/UrmRl3zeqhEFcG+UoSSwCFB1VVAs6MzdRyQmkQm8mLlwkvv0z4cCPozxOUkx85IYqx+mnfwABE4yA7e7gIjIdQdf9kuUvydrKC+mjeD7TpgL9wNSPePRTcOg==",
	"keysetInfo": {
		"primaryKeyId": 4112199248,
		"keyInfo": [
			{
				"typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
				"status": "ENABLED",
				"keyId": 4112199248,
				"outputPrefixType": "TINK"
			}
		]
	}
}
```