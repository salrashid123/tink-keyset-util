### ECC PUBLIC

The following will create  ecc keys, extract the raw key and then use those to regenreate the keyset again

note,  

 Tink prepends an extra 0x00 byte to the coordinates (b/264525021).

see [ecdsa/protoserialization_test.go](https://github.com/tink-crypto/tink-go/blob/e9f750c0b09e0875dda1a7d9fca9c3a98b55479b/signature/ecdsa/protoserialization_test.go#L420)

```bash
tinkey create-keyset --key-template=ECDSA_P256 --out-format=binary --out=/tmp/ecc_1_private.bin
tinkey create-public-keyset --in=/tmp/ecc_1_private.bin  --in-format=binary --out-format=binary --out=/tmp/ecc_1_public.bin

tinkey convert-keyset --in-format=binary --in=/tmp/ecc_1_public.bin --out-format=json --out=/tmp/ecc_1_public.json

cat /tmp/ecc_1_public.json | jq '.' 

{
  "primaryKeyId": 2053903911,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
        "value": "EgYIAxACGAIaIQC4FRlbyqRFko8cIr7ZEExVmV6ZwKOJ5/Na9BVabDjjhCIhALQrWm8/PipL6iOxvV6XGElMG793QS1jSj1GKGWxQCF+",
        "keyMaterialType": "ASYMMETRIC_PUBLIC"
      },
      "status": "ENABLED",
      "keyId": 2053903911,
      "outputPrefixType": "TINK"
    }
  ]
}

### extract the  public from the keyset
go run ecc/export/main.go --insecure-key-set /tmp/ecc_1_public.bin 


# gives:  then save this as  /tmp/ecc_1_public.pem


### now import it as a new keyset, the keysets should match
go run ecc/import/public/main.go -keyFile /tmp/ecc_1_public.pem

{
 "primaryKeyId": 1957864605,
 "key": [
  {
   "keyData": {
    "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
    "value": "EgYIAxACGAIaIQC4FRlbyqRFko8cIr7ZEExVmV6ZwKOJ5/Na9BVabDjjhCIhALQrWm8/PipL6iOxvV6XGElMG793QS1jSj1GKGWxQCF+",
    "keyMaterialType": "ASYMMETRIC_PUBLIC"
   },
   "status": "ENABLED",
   "keyId": 1957864605,
   "outputPrefixType": "TINK"
  }
 ]
}
```

### ECC PRIVATE

```bash
## create keyset
tinkey create-keyset --key-template=ECDSA_P256 --out-format=binary --out=/tmp/ecc_1_private.bin
tinkey convert-keyset --in-format=binary --in=/tmp/ecc_1_private.bin --out-format=json --out=/tmp/ecc_1_private.json

cat /tmp/ecc_1_private.json | jq '.'
{
  "primaryKeyId": 2756302218,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
        "value": "Ek4SBggDEAIYAhohAEe5QaqWFuLNhQDo+hn9RPTjdFa5MyLxwQjdkSp/A4EIIiEAWAGUP4IpewwmDJ0Dna8cTSOQ5KMn5zS0J+z/VDUuawoaIQCJm9GlGtsMFpdSDhskYuxovjDeaNbIQeadUYPt08CE4w==",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 2756302218,
      "outputPrefixType": "TINK"
    }
  ]
}

### extract the  private from the keyset
go run ecc/export/main.go --insecure-key-set /tmp/ecc_1_private.bin 

# gives:  then save this as  /tmp/ecc_1_private.pem
$ cat /tmp/ecc_1_private.pem
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIImb0aUa2wwWl1IOGyRi7Gi+MN5o1shB5p1Rg+3TwITjoAoGCCqGSM49
AwEHoUQDQgAEsOBP8D6dtv6VGe8bl3i3WZn4M4CUspjqxXWFwmwrO40C6dXkZtIK
d/t7bx11P/qsU8HUFfnev3KHHNipUlq3DQ==
-----END EC PRIVATE KEY-----

$ cat /tmp/ecc_1_public.pem 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAER7lBqpYW4s2FAOj6Gf1E9ON0Vrkz
IvHBCN2RKn8DgQhYAZQ/gil7DCYMnQOdrxxNI5DkoyfnNLQn7P9UNS5rCg==
-----END PUBLIC KEY-----



### now import it as a new keyset, the keysets should match
go run ecc/import/private/main.go -keyFile /tmp/ecc_1_private.pem

{
  "primaryKeyId": 1957864605,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
        "value": "Ek4SBggDEAIYAhohAEe5QaqWFuLNhQDo+hn9RPTjdFa5MyLxwQjdkSp/A4EIIiEAWAGUP4IpewwmDJ0Dna8cTSOQ5KMn5zS0J+z/VDUuawoaIQCJm9GlGtsMFpdSDhskYuxovjDeaNbIQeadUYPt08CE4w==",
        "keyMaterialType": "ASYMMETRIC_PRIVATE"
      },
      "status": "ENABLED",
      "keyId": 1957864605,
      "outputPrefixType": "TINK"
    }
  ]
}
```