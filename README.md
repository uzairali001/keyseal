# keyseal

Command-line tool that encrypts a file for a recipient public key and decrypts it with the matching private key.

```bash
dotnet tool install --global keyseal
keyseal keygen
keyseal encrypt <file> [--public-key <path>] [--replace]
keyseal decrypt <file.keyseal> [--output <path>] [--replace]
```

`keygen` writes `private.pem` and `public.pem` in the current directory. Encryption reads `--public-key`, or `public.pem` when that option is omitted. Decryption reads `private.pem`.
