# Key generation

Generate signify key for signing repository metadata:

    signify -G -n -p apps.0.pub -s apps.0.sec

The `0` refers to the generation of the key. This is used for key rotation.

Generate fs-verity signing key with `GrapheneOS` changed to an arbitrary name
representing your project (not used for anything):

    openssl req -newkey rsa:4096 -sha512 -noenc -keyout fsverify_private_key.0.pem -x509 -out fsverity_cert.0.pem -days 10000 -subj /CN=GrapheneOS/
    openssl x509 -in fsverity_cert.0.pem -out fsverity_cert.0.der -outform der

The `0` refers to the generation of the key. This is used for key rotation.
