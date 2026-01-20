The following will create an aes_siv keyset, then export the the aes key

From there, you can import it back to the keyset

```bash
tinkey create-keyset --key-template=AES256_SIV --out-format=binary --out=/tmp/aes_siv.bin
tinkey convert-keyset --in-format=binary --in=/tmp/aes_siv.bin --out-format=json --out=/tmp/aes_siv.json



## print the json key
$ cat /tmp/aes_siv.json | jq '.'

{
  "primaryKeyId": 795027710,
  "key": [
    {
      "keyData": {
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
        "value": "EkB78EkQWGNuWmjEL2c7K+QI/ERNey521R+fbgNuD68FqVvETLJIuAjvWJuICFaMX01T8VzVuQtgjt7oYXC+FQER",
        "keyMaterialType": "SYMMETRIC"
      },
      "status": "ENABLED",
      "keyId": 795027710,
      "outputPrefixType": "TINK"
    }
  ]
}
```

to export

```bash
### export
go run aes_siv/export/main.go --insecure-key-set /tmp/aes_siv.bin 

  Encrypted Data: 012f6328fef6954f1da838d226b59c20bd2fb643f25919fe
  Raw key: e/BJEFhjblpoxC9nOyvkCPxETXsudtUfn24Dbg+vBalbxEyySLgI71ibiAhWjF9NU/Fc1bkLYI7e6GFwvhUBEQ==
  Raw Encrypted Data: f6954f1da838d226b59c20bd2fb643f25919fe
Tink Decrypted: foo

```


to import, you need to specify the extracted keys.  for the example above

```bash
go run aes_siv/import/main.go \
   --key="e/BJEFhjblpoxC9nOyvkCPxETXsudtUfn24Dbg+vBalbxEyySLgI71ibiAhWjF9NU/Fc1bkLYI7e6GFwvhUBEQ==" 
```

you'll see the same keyset as above


```json
{
 "primaryKeyId": 4112199248,
 "key": [
  {
   "keyData": {
    "typeUrl": "type.googleapis.com/google.crypto.tink.AesSivKey",
    "value": "EkB78EkQWGNuWmjEL2c7K+QI/ERNey521R+fbgNuD68FqVvETLJIuAjvWJuICFaMX01T8VzVuQtgjt7oYXC+FQER",
    "keyMaterialType": "SYMMETRIC"
   },
   "status": "ENABLED",
   "keyId": 4112199248,
   "outputPrefixType": "TINK"
  }
 ]
}
```