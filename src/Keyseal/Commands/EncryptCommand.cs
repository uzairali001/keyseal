using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

static class EncryptCommand
{
    const string Usage = "Usage: keyseal encrypt <file-to-encrypt> [--public-key <path>] [--replace]";

    public static int Run(string[] args)
    {
        string? inputFile = null;
        string? publicKeyPath = null;
        bool replace = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg is "--replace")
            {
                replace = true;
                continue;
            }

            if (arg is "--public-key" or "-k")
            {
                if (publicKeyPath is not null)
                {
                    Console.WriteLine("Error: --public-key specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                {
                    Console.WriteLine("Error: --public-key requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                publicKeyPath = args[++i];
                continue;
            }

            if (arg.StartsWith("--public-key=", StringComparison.Ordinal) || arg.StartsWith("-k=", StringComparison.Ordinal))
            {
                if (publicKeyPath is not null)
                {
                    Console.WriteLine("Error: --public-key specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                publicKeyPath = arg[(arg.IndexOf('=') + 1)..];
                if (string.IsNullOrWhiteSpace(publicKeyPath))
                {
                    Console.WriteLine("Error: --public-key requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                continue;
            }

            if (arg.StartsWith('-'))
            {
                Console.WriteLine($"Error: Unknown option '{arg}'.");
                Console.WriteLine(Usage);
                return 1;
            }

            if (inputFile is not null)
            {
                Console.WriteLine($"Error: Unexpected argument '{arg}'.");
                Console.WriteLine(Usage);
                return 1;
            }

            inputFile = arg;
        }

        if (inputFile is null)
        {
            Console.WriteLine(Usage);
            return 1;
        }

        if (!File.Exists(inputFile))
        {
            Console.WriteLine($"Error: Input file '{inputFile}' not found.");
            return 1;
        }

        publicKeyPath ??= "public.pem";
        if (!File.Exists(publicKeyPath))
        {
            Console.WriteLine($"Error: Public key '{publicKeyPath}' not found.");
            return 1;
        }

        string outputFile = inputFile + ".keyseal";
        string writePath = outputFile;
        bool replacing = false;
        if (File.Exists(outputFile))
        {
            if (!replace)
            {
                Console.WriteLine($"Error: Output file '{outputFile}' already exists. Pass --replace to overwrite it.");
                return 1;
            }

            writePath = outputFile + ".partial";
            replacing = true;
            if (File.Exists(writePath))
                File.Delete(writePath);
        }

        // Container layout (little-endian), magic "E1GC":
        //   header (115 bytes):
        //     char[4]  magic = E1GC
        //     u8       version = 1
        //     u8       suite = 1           P-256, HKDF-SHA256, AES-256-GCM
        //     u32      chunkSize
        //     byte[32] hkdfSalt
        //     byte[8]  noncePrefix        nonce = prefix || u32le chunkIndex
        //     byte[65] ephemeralPublic    uncompressed SEC1 point (04 || X || Y)
        //   each chunk:
        //     u32      cipherLength
        //     u8       last                1 only on the final chunk
        //     byte[16] tag
        //     byte[cipherLength] ciphertext
        //   AAD = header || chunkIndex || last || cipherLength
        //   A last flag of 0 at EOF is rejected, so a truncated file cannot authenticate.
        const int HeaderSize = 115;
        const int ChunkSize = 1 << 20;
        const int TagSize = 16;
        const int SaltSize = 32;
        const int NoncePrefixSize = 8;
        const int PublicKeySize = 65;
        const int VersionOffset = 4;
        const int SuiteOffset = 5;
        const int ChunkSizeOffset = 6;
        const int SaltOffset = 10;
        const int NoncePrefixOffset = 42;
        const int PublicKeyOffset = 50;
        ReadOnlySpan<byte> info = "E1GC-v1 P-256 HKDF-SHA256 AES-256-GCM"u8;

        string publicKeyPem = File.ReadAllText(publicKeyPath);
        using var receiverPublicKey = ECDiffieHellman.Create();
        receiverPublicKey.ImportFromPem(publicKeyPem);

        using var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        byte[] header = new byte[HeaderSize];
        "E1GC"u8.CopyTo(header);
        header[VersionOffset] = 1;
        header[SuiteOffset] = 1;
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(ChunkSizeOffset), ChunkSize);
        RandomNumberGenerator.Fill(header.AsSpan(SaltOffset, SaltSize));
        RandomNumberGenerator.Fill(header.AsSpan(NoncePrefixOffset, NoncePrefixSize));
        ExportUncompressed(ephemeral, header.AsSpan(PublicKeyOffset, PublicKeySize));

        byte[] aesKey = new byte[32];
        byte[] sharedSecret = ephemeral.DeriveRawSecretAgreement(receiverPublicKey.PublicKey);
        try
        {
            HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, header.AsSpan(SaltOffset, SaltSize), info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }

        FileStream? output = null;
        bool created = false;
        bool success = false;
        byte[] plainA = ArrayPool<byte>.Shared.Rent(ChunkSize);
        byte[] plainB = ArrayPool<byte>.Shared.Rent(ChunkSize);
        byte[] cipher = ArrayPool<byte>.Shared.Rent(ChunkSize);
        try
        {
            using var aes = new AesGcm(aesKey, TagSize);
            using var input = new FileStream(
                inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);
            output = new FileStream(
                writePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
            created = true;
            output.Write(header);

            byte[] aad = new byte[HeaderSize + 4 + 1 + 4];
            header.CopyTo(aad);
            Span<byte> nonce = stackalloc byte[12];
            Span<byte> tag = stackalloc byte[TagSize];
            Span<byte> record = stackalloc byte[4 + 1 + TagSize];

            int filled = ReadAtMost(input, plainA, ChunkSize);
            uint index = 0;
            while (true)
            {
                int lookAhead = ReadAtMost(input, plainB, ChunkSize);
                bool isLast = lookAhead == 0;
                if (!isLast && filled != ChunkSize)
                    throw new InvalidDataException("Short read before end of file.");

                header.AsSpan(NoncePrefixOffset, NoncePrefixSize).CopyTo(nonce);
                BinaryPrimitives.WriteUInt32LittleEndian(nonce[NoncePrefixSize..], index);
                byte lastFlag = isLast ? (byte)1 : (byte)0;
                BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(HeaderSize), index);
                aad[HeaderSize + 4] = lastFlag;
                BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(HeaderSize + 5), (uint)filled);

                aes.Encrypt(nonce, plainA.AsSpan(0, filled), cipher.AsSpan(0, filled), tag, aad);

                BinaryPrimitives.WriteUInt32LittleEndian(record, (uint)filled);
                record[4] = lastFlag;
                tag.CopyTo(record[5..]);
                output.Write(record);
                output.Write(cipher, 0, filled);

                if (isLast)
                    break;
                if (index == uint.MaxValue)
                    throw new InvalidDataException("File exceeds the maximum number of chunks.");
                index++;
                (plainA, plainB) = (plainB, plainA);
                filled = lookAhead;
            }

            output.Dispose();
            output = null;
            if (replacing)
                File.Move(writePath, outputFile, overwrite: true);
            created = false;
            success = true;
            Console.WriteLine("Encryption complete!");
            Console.WriteLine($"Generated: {outputFile}");
            Console.WriteLine($"Plaintext bytes: {input.Length}");
            return 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            CryptographicOperations.ZeroMemory(plainA);
            CryptographicOperations.ZeroMemory(plainB);
            output?.Dispose();
            ArrayPool<byte>.Shared.Return(plainA);
            ArrayPool<byte>.Shared.Return(plainB);
            ArrayPool<byte>.Shared.Return(cipher);
            if (created && !success)
                File.Delete(writePath);
        }
    }

    static int ReadAtMost(Stream stream, byte[] buffer, int count)
    {
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n == 0)
                break;
            read += n;
        }

        return read;
    }

    static void ExportUncompressed(ECDiffieHellman ecdh, Span<byte> destination)
    {
        ECParameters parameters = ecdh.ExportParameters(false);
        destination[0] = 0x04;
        WriteCoordinate(parameters.Q.X, destination[1..33]);
        WriteCoordinate(parameters.Q.Y, destination[33..65]);
    }

    static void WriteCoordinate(byte[]? source, Span<byte> destination)
    {
        if (source is null || source.Length == 0 || source.Length > destination.Length)
            throw new CryptographicException("Invalid EC coordinate.");

        destination.Clear();
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }
}
