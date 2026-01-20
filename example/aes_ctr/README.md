The following will create an aes_ctr keyset, then export the the aes and hmac keys

From there, you can import it back to the keyset

```bash
tinkey create-keyset --key-template=AES256_CTR_HMAC_SHA256 --out-format=binary --out=/tmp/aes_ctr_hmac_sha256.bin
tinkey convert-keyset --in-format=binary --in=/tmp/aes_ctr_hmac_sha256.bin --out-format=json --out=/tmp/aes_ctr_hmac_sha256.json

## print the json key
$ cat /tmp/aes_ctr_hmac_sha256.json | jq '.'
{
  "primaryKeyId": 865470627,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        "value": "EiYSAggQGiCG5/nBYl4n2Gj+D15+8borUhjchNPhd+Zz8paVrh0dBBooEgQIAxAgGiDJtqVgYrJbHUOnikUWxJV5Gj3Q3NiobM+DiG+WEb1TCw==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 865470627,
      "outputPrefixType": "TINK"
    }
  ]
}

### export
go run aes_ctr/export/main.go --insecure-key-set /tmp/aes_ctr_hmac_sha256.bin 

  Encrypted Data: ATOWCKOzt8VDJtnA9wwZCLc14FrYcA/hdAir0QjBJEgToZthT/ZrE3C2/knJLixA64eZpb8qDcE=
  AES key: huf5wWJeJ9ho/g9efvG6K1IY3ITT4Xfmc/KWla4dHQQ=
  HMAC key: ybalYGKyWx1Dp4pFFsSVeRo90NzYqGzPg4hvlhG9Uws=
  Full Raw Encrypted s7fFQybZwPcMGQi3NeBa2HAP4XQIq9EIwSRIE6GbYU/2axNwtv5JyS4sQOuHmaW/Kg3B
  Raw ciphertext with IV: s7fFQybZwPcMGQi3NeBa2HAP4Q==
  Plaintext: foo
  Raw mac from from encrypted data: dAir0QjBJEgToZthT/ZrE3C2/knJLixA64eZpb8qDcE=
  calculated hmac using hmac key hmac( (AD || IV || ciphertext || bitlen(AD)), key): dAir0QjBJEgToZthT/ZrE3C2/knJLixA64eZpb8qDcE=
```


to import, you need to specify both extracted keys.  for the example above

```bash
go run aes_ctr/import/main.go \
   --aeskey="huf5wWJeJ9ho/g9efvG6K1IY3ITT4Xfmc/KWla4dHQQ=" \
    --hmackey="ybalYGKyWx1Dp4pFFsSVeRo90NzYqGzPg4hvlhG9Uws="

### you'll see the same keyset as above

{
 "primaryKeyId": 4112199248,
 "key": [
  {
   "keyData": {
    "typeUrl": "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
    "value": "EiYSAggQGiCG5/nBYl4n2Gj+D15+8borUhjchNPhd+Zz8paVrh0dBBooEgQIAxAgGiDJtqVgYrJbHUOnikUWxJV5Gj3Q3NiobM+DiG+WEb1TCw==",
    "keyMaterialType": "SYMMETRIC"
   },
   "status": "ENABLED",
   "keyId": 4112199248,
   "outputPrefixType": "TINK"
  }
 ]
}
```