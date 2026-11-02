# keyseal

Command-line tool that encrypts a file for a recipient public key and decrypts it with the matching private key.

```bash
dotnet tool install --global keyseal
keyseal keygen
keyseal encrypt <file> [--public-key <path>] [--replace]
keyseal decrypt <file.keyseal> [--private-key <path>] [--output <path>] [--replace]
```

`keygen` writes `private.pem` and `public.pem` in the current directory. Encryption reads `--public-key`, or `public.pem` when that option is omitted. Decryption reads `--private-key`, or `private.pem` when that option is omitted.
