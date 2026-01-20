The following will create an hmac keyset, then export the the aes key

From there, you can import it back to the keyset


```bash
tinkey create-keyset --key-template=HMAC_SHA256_256BITTAG --out-format=binary --out=/tmp/hmac_bittag.bin
tinkey convert-keyset --in-format=binary --in=/tmp/hmac_bittag.bin --out-format=json --out=/tmp/hmac_bittag.json

cat /tmp/hmac_bittag.json | jq '.'

{
  "primaryKeyId": 785411596,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
        "value": "EgQIAxAgGiBgtveKXQkHTqjjr6Jk5QWL+/ii97JzyZru7QGq59g7/g==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 785411596,
      "outputPrefixType": "TINK"
    }
  ]
}

### extract the key
go run hmac/export/main.go --insecure-key-set /tmp/hmac_bittag.bin

  rawKey key: YLb3il0JB06o46+iZOUFi/v4oveyc8ma7u0BqufYO/4=


### now import it back to get the same hmac keyset
go run hmac/import/main.go --key="YLb3il0JB06o46+iZOUFi/v4oveyc8ma7u0BqufYO/4="

 {
  "primaryKeyId": 4112199248,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
        "value": "EgQIAxAgGiBgtveKXQkHTqjjr6Jk5QWL+/ii97JzyZru7QGq59g7/g==",
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


for the `HMAC_SHA256_256BITTAG_RAW` template

```bash
tinkey create-keyset --key-template=HMAC_SHA256_256BITTAG_RAW --out-format=binary --out=/tmp/hmac_bittag_raw.bin
tinkey convert-keyset --in-format=binary --in=/tmp/hmac_bittag_raw.bin --out-format=json --out=/tmp/hmac_bittag_raw.json

cat /tmp/hmac_bittag_raw.json | jq '.'
{
  "primaryKeyId": 2382872349,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
        "value": "EgQIAxAgGiDEfgnFWSR334QsOu9mkemHwvOLhC8I6U9LFkl6nBnTBw==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 2382872349,
      "outputPrefixType": "RAW"
    }
  ]
}


go run hmac/export/main.go --insecure-key-set /tmp/hmac_bittag_raw.bin

  rawKey key: xH4JxVkkd9+ELDrvZpHph8Lzi4QvCOlPSxZJepwZ0wc=


go run hmac/import/main.go --key="xH4JxVkkd9+ELDrvZpHph8Lzi4QvCOlPSxZJepwZ0wc=" --format="raw"

 {
  "primaryKeyId": 4112199248,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.HmacKey",
        "value": "EgQIAxAgGiDEfgnFWSR334QsOu9mkemHwvOLhC8I6U9LFkl6nBnTBw==",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 4112199248,
      "outputPrefixType": "RAW"
    }
  ]
}
```

