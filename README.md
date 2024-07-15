# Key generation

Generate signify key for signing repository metadata:

    signify -G -n -p apps.0.pub -s apps.0.sec

The `0` refers to the generation of the key. This is used for key rotation.

If you have your own OS where you can include an fs-verity key in the supported
keys built into the OS, you can also generate an fs-verity signing key in order
to provide continuous verification via verified boot instead of only having the
APK signatures verified at boot (which is actually largely skipped for most
boots for apps without fs-verity due to the performance cost).

GrapheneOS requires fs-verity for system app updates as part of fully
extending verified boot to system app updates. Android doesn't enforce any
form of verified boot for system app updates so they can be used to bypass
verified boot by replacing system apps with arbitrary APKs since signature
checks and downgrade protection aren't enforced at boot. GrapheneOS adds
enforced checks and also enforces using fs-verity to provide continuous
verification instead of only one-time verification at boot where the SSD is
trusted afterwards in order to match the properties of verified boot for the
firmware and OS images.

Optionally, generate fs-verity signing key with `GrapheneOS` changed to an
arbitrary name representing your project (not used for anything):

    openssl req -newkey rsa:4096 -sha512 -noenc -keyout fsverity_private_key.0.pem -x509 -out fsverity_cert.0.pem -days 10000 -subj /CN=GrapheneOS/
    openssl x509 -in fsverity_cert.0.pem -out fsverity_cert.0.der -outform der

The `0` refers to the generation of the key. This is used for key rotation.

The `generate.py` script will automatically sign all the published apps with
the fs-verity key. You can also sign them manually:

    fsverity sign app-release.apk app-release.apk.fsv_sig --key fsverity_private_key.0.pem --cert fsverity_cert.0.pem
