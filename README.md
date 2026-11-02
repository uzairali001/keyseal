# keyseal

keyseal encrypts a file so that only the holder of a matching private key can read it. You encrypt with the recipient’s public key. They decrypt with their private key. The private key never has to leave their machine.

Each sealed file gets its own ephemeral P-256 key. keyseal agrees a shared secret with the recipient’s public key, derives an AES-256 key with HKDF-SHA256, and encrypts the file in 1 MiB chunks with AES-256-GCM. The file is streamed, so a large input is not loaded into memory all at once. A truncated or altered file fails authentication and is not written out as plaintext.

## Install

keyseal is a [.NET](https://dotnet.microsoft.com/download) tool and needs the .NET 11 SDK.

```bash
dotnet tool install --global keyseal
keyseal --help
```

Upgrade an existing install with `dotnet tool update --global keyseal`.

To try the tool from a clone of this repository, without installing it:

```bash
dotnet run --project src/Keyseal -- --help
```

## Send a file to someone

The recipient generates a key pair once and sends you only the public key.

```bash
keyseal keygen
```

That writes `private.pem` and `public.pem` in the current directory. They keep `private.pem` and send you `public.pem`. You can receive that file over ordinary email or chat.

Encrypt with their public key:

```bash
keyseal encrypt report.pdf --public-key public.pem
```

This creates `report.pdf.keyseal` beside the original. The original file is left unchanged. Send `report.pdf.keyseal`. It is useless without the private key that matches the public key you used.

The recipient decrypts it:

```bash
keyseal decrypt report.pdf.keyseal --private-key private.pem
```

That restores `report.pdf`. If a file of that name is already there, keyseal stops. Pass `--replace` to overwrite it.

When the public key is `public.pem` in the current directory, `--public-key` can be omitted. When the private key is `private.pem` in the current directory, `--private-key` can be omitted.

## Commands

Running `keyseal` with no command, or with `help`, `-h`, or `--help`, prints the usage summary.

### keyseal keygen

```text
keyseal keygen
```

Creates a new NIST P-256 key pair and writes:

| File | Contents | Who should have it |
| --- | --- | --- |
| `public.pem` | SubjectPublicKeyInfo PEM | Anyone who should be able to encrypt for you |
| `private.pem` | Unencrypted PKCS#8 PEM | Only you |

`keygen` takes no options. If `private.pem` or `public.pem` already exists in the current directory, it overwrites that file. Move a key you still need before generating another pair in the same directory.

### keyseal encrypt

```text
keyseal encrypt <file> [--public-key <path>] [--replace]
```

| Argument | Meaning |
| --- | --- |
| `<file>` | File to encrypt. |
| `--public-key <path>`, `-k <path>` | Recipient public key. Defaults to `public.pem`. `--public-key=<path>` and `-k=<path>` are accepted. |
| `--replace` | Overwrite `<file>.keyseal` when it already exists. |

The sealed file is always `<file>.keyseal`. keyseal refuses to replace an existing sealed file unless `--replace` is set. On failure, a partially written output is deleted. With `--replace`, the existing sealed file is replaced only after the new file has been written in full.

### keyseal decrypt

```text
keyseal decrypt <file> [--private-key <path>] [--output <path>] [--replace]
```

| Argument | Meaning |
| --- | --- |
| `<file>` | Sealed file, usually named `something.keyseal`. |
| `--private-key <path>`, `-k <path>` | Private key. Defaults to `private.pem`. `--private-key=<path>` and `-k=<path>` are accepted. |
| `--output <path>`, `-o <path>` | Where to write the plaintext. `--output=<path>` and `-o=<path>` are accepted. |
| `--replace` | Overwrite the output when it already exists. |

Without `--output`, a name that ends in `.keyseal` has that suffix removed (`notes.txt.keyseal` becomes `notes.txt`). Any other name gets `.dec` appended.

If `--output` is an existing directory, or the path ends in a slash, keyseal writes the default file name inside that directory. Parent directories of the output path are created when they are missing.

Decryption failure prints one of these and leaves no plaintext behind:

- `Decryption failed. The file was modified, or it was encrypted for a different key.` The authentication check failed.
- `Error: Encrypted file is truncated.` The file ended before a complete, final chunk.
- `Error: Unrecognized container. Expected an E1GC v1 file.` The file is not a keyseal container this version can read.

## Protect the private key

`private.pem` is the ability to read every file encrypted for its public key. keyseal stores it as an ordinary unencrypted PEM file.

- Keep `private.pem` on a machine you control. Do not send it with the sealed file, and do not commit it.
- A public key only lets someone encrypt. Confirm you are encrypting for the person you mean to, because keyseal does not check who a public key belongs to.
- Anyone who has the public key can create a sealed file that decrypts with the matching private key. keyseal does not identify the sender.
- The sealed name is the original file name plus `.keyseal`. Encrypt a copy under another name first when the file name itself is sensitive.
- keyseal encrypts one file per invocation. It does not walk directories.

## File format

A sealed file is a little-endian container. The magic is the four bytes `E1GC`.

Header, 115 bytes:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic `E1GC` |
| 4 | 1 | Version, `1` |
| 5 | 1 | Suite, `1` (P-256, HKDF-SHA256, AES-256-GCM) |
| 6 | 4 | Chunk size, currently 1 MiB (`1048576`) |
| 10 | 32 | HKDF salt |
| 42 | 8 | Nonce prefix. The 12-byte nonce is this prefix followed by the chunk index as a little-endian `u32` |
| 50 | 65 | Ephemeral public key, uncompressed SEC1 point (`04 \|\| X \|\| Y`) |

Each chunk follows the header:

| Size | Field |
| --- | --- |
| 4 | Ciphertext length, little-endian `u32` |
| 1 | Last-chunk flag, `1` on the final chunk and `0` on every earlier chunk |
| 16 | AES-GCM tag |
| length | Ciphertext |

The additional authenticated data for each chunk is the header, then the chunk index (`u32`), the last-chunk flag (`u8`), and the ciphertext length (`u32`). A file that ends on a chunk whose flag is `0`, or that has bytes after the chunk whose flag is `1`, is rejected. Every chunk before the last one is exactly the header’s chunk size. The last chunk may be shorter, including empty.

The AES-256 key is HKDF-SHA256 over the raw P-256 shared secret. The salt is the header salt. The info string is `E1GC-v1 P-256 HKDF-SHA256 AES-256-GCM`. The ephemeral private key is discarded after the shared secret is derived.

This version reads suite `1` only, and rejects a chunk size of `0` or a chunk size above 4 MiB.

## Build from source

```bash
dotnet build
dotnet test
```

After `dotnet build -c Release`, the program is `src/Keyseal/bin/Release/net11.0/keyseal` (`keyseal.exe` on Windows). Pack the .NET tool with `dotnet pack src/Keyseal -c Release`.
