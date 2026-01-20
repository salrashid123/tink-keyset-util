The following will create an rsa public/private keyset, then export the various keys

From there, you can import it back to the keyset

```bash
rm -rf /tmp/rsa_*
tinkey create-keyset --key-template=RSA_SSA_PKCS1_3072_SHA256_F4 --out-format=binary --out=/tmp/rsa_1_private.bin
tinkey convert-keyset --in-format=binary --in=/tmp/rsa_1_private.bin --out-format=json --out=/tmp/rsa_1_private.json

tinkey create-public-keyset --in=/tmp/rsa_1_private.bin  --in-format=binary --out-format=binary --out=/tmp/rsa_1_public.bin
tinkey convert-keyset --in-format=binary --in=/tmp/rsa_1_public.bin --out-format=json --out=/tmp/rsa_1_public.json

go run export/main.go --insecure-key-set /tmp/rsa_1_public.bin --pubout /tmp/rsa_1_public.pem
go run import/public/main.go -keyFile /tmp/rsa_1_public.pem --keyout=/tmp/rsa_2_public.json

go run export/main.go --insecure-key-set /tmp/rsa_1_private.bin --privout /tmp/rsa_1_private.pem
go run import/private/main.go -keyFile /tmp/rsa_1_private.pem --prefix=raw --keyout=/tmp/rsa_2_private.json

### compare the keyset; they should be the same
cat /tmp/rsa_1_public.json | jq '.'
cat /tmp/rsa_2_public.json | jq '.'

cat /tmp/rsa_1_private.json | jq '.'
cat /tmp/rsa_2_private.json | jq '.'
```