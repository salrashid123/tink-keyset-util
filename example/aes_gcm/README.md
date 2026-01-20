The following will create an aes_ctr keyset, then export the the aes

From there, you can import it back to the keyset

```bash
tinkey create-keyset --key-template=AES256_GCM --out-format=binary --out=/tmp/aes_gcm_1.bin
tinkey convert-keyset --in-format=binary --in=/tmp/aes_gcm_1.bin --out-format=json --out=/tmp/aes_gcm_1.json

cat /tmp/aes_gcm_1.json  | jq '.'

{
  "primaryKeyId": 270475339,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiCKGzLPDIXZttypfYE/DVUvCHTtj3BVKHPxgN99cR4Cyg==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 270475339,
      "outputPrefixType": "TINK"
    }
  ]
}
```

Now extract the aes gcm key

```bash
go run aes_gcm/export/insecurekeyset/main.go --insecure-key-set /tmp/aes_gcm_1.bin

  Raw key: ihsyzwyF2bbcqX2BPw1VLwh07Y9wVShz8YDffXEeAso=
```

now use the raw key to regenerate the keyset


```bash
$ go run aes_gcm/import/insecurekeyset/main.go  --key="ihsyzwyF2bbcqX2BPw1VLwh07Y9wVShz8YDffXEeAso="

{
 "primaryKeyId": 4112199248,
 "key": [
  {
   "keyData": {
    "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
    "value": "GiCKGzLPDIXZttypfYE/DVUvCHTtj3BVKHPxgN99cR4Cyg==",
    "keyMaterialType": "SYMMETRIC"
   },
   "status": "ENABLED",
   "keyId": 4112199248,
   "outputPrefixType": "TINK"
  }
 ]
}
``` 

---

### AES GCM RAW 

For the RAW template `AES256_GCM_RAW`

```bash
tinkey create-keyset --key-template=AES256_GCM_RAW --out-format=binary --out=/tmp/aes_gcm_raw.bin
tinkey convert-keyset --in-format=binary --in=/tmp/aes_gcm_raw.bin --out-format=json --out=/tmp/aes_gcm_raw.json

cat /tmp/aes_gcm_raw.json  | jq '.'

{
  "primaryKeyId": 3883929764,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiCJ+aL5ZpsEOBqwED90tHJDCEuNn7A1krJidiMCAF/Rkg==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 3883929764,
      "outputPrefixType": "RAW"
    }
  ]
}

### extract
go run aesgcm/export/insecurekeyset/main.go --insecure-key-set /tmp/aes_gcm_raw.bin

   Raw key: ifmi+WabBDgasBA/dLRyQwhLjZ+wNZKyYnYjAgBf0ZI=


## import
$ go run aesgcm/import/insecurekeyset/main.go  --key="ifmi+WabBDgasBA/dLRyQwhLjZ+wNZKyYnYjAgBf0ZI=" --prefix=raw
2026/01/18 00:56:17 Tink Keyset:
 {
 "primaryKeyId": 4112199248,
 "key": [
  {
   "keyData": {
    "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
    "value": "GiCJ+aL5ZpsEOBqwED90tHJDCEuNn7A1krJidiMCAF/Rkg==",
    "keyMaterialType": "SYMMETRIC"
   },
   "status": "ENABLED",
   "keyId": 4112199248,
   "outputPrefixType": "RAW"
  }
 ]
}
```
