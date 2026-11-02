using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

static class DecryptCommand
{
    const string Usage = "Usage: keyseal decrypt <file.keyseal> [--private-key <path>] [--output <path>] [--replace]";

    public static int Run(string[] args)
    {
        string? inputFile = null;
        string? outputOption = null;
        string? privateKeyPath = null;
        bool replace = false;
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (arg is "--replace")
            {
                replace = true;
                continue;
            }

            if (arg is "--private-key" or "-k")
            {
                if (privateKeyPath is not null)
                {
                    Console.WriteLine("Error: --private-key specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                {
                    Console.WriteLine("Error: --private-key requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                privateKeyPath = args[++i];
                continue;
            }

            if (arg.StartsWith("--private-key=", StringComparison.Ordinal) || arg.StartsWith("-k=", StringComparison.Ordinal))
            {
                if (privateKeyPath is not null)
                {
                    Console.WriteLine("Error: --private-key specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                privateKeyPath = arg[(arg.IndexOf('=') + 1)..];
                if (string.IsNullOrWhiteSpace(privateKeyPath))
                {
                    Console.WriteLine("Error: --private-key requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                continue;
            }

            if (arg is "--output" or "-o")
            {
                if (outputOption is not null)
                {
                    Console.WriteLine("Error: --output specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                if (i + 1 >= args.Length)
                {
                    Console.WriteLine("Error: --output requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                outputOption = args[++i];
                if (string.IsNullOrWhiteSpace(outputOption))
                {
                    Console.WriteLine("Error: --output requires a path.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                continue;
            }

            if (arg.StartsWith("--output=", StringComparison.Ordinal) || arg.StartsWith("-o=", StringComparison.Ordinal))
            {
                if (outputOption is not null)
                {
                    Console.WriteLine("Error: --output specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                outputOption = arg[(arg.IndexOf('=') + 1)..];
                if (string.IsNullOrWhiteSpace(outputOption))
                {
                    Console.WriteLine("Error: --output requires a path.");
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

        privateKeyPath ??= "private.pem";
        if (!File.Exists(privateKeyPath))
        {
            Console.WriteLine($"Error: Private key '{privateKeyPath}' not found.");
            return 1;
        }

        string defaultOutput = inputFile.EndsWith(".keyseal", StringComparison.OrdinalIgnoreCase)
            ? inputFile[..^".keyseal".Length]
            : inputFile + ".dec";
        string outputFile = outputOption is null
            ? defaultOutput
            : ResolveOutputPath(outputOption, Path.GetFileName(defaultOutput));
        string? outputDirectory = Path.GetDirectoryName(Path.GetFullPath(outputFile));
        if (!string.IsNullOrEmpty(outputDirectory))
            Directory.CreateDirectory(outputDirectory);
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

        // Must match EncryptCommand. Header is 115 bytes; each chunk is length || last || tag || ciphertext.
        const int HeaderSize = 115;
        const int MaxChunkSize = 4 << 20;
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

        FileStream? output = null;
        bool created = false;
        bool success = false;
        byte[]? cipher = null;
        byte[]? plain = null;
        byte[] aesKey = new byte[32];
        try
        {
            using var input = new FileStream(
                inputFile, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.SequentialScan);

            byte[] header = new byte[HeaderSize];
            ReadExact(input, header);
            if (!header.AsSpan(0, 4).SequenceEqual("E1GC"u8) || header[VersionOffset] != 1 || header[SuiteOffset] != 1)
                throw new InvalidDataException("Unrecognized container. Expected an E1GC v1 file.");

            uint chunkSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(ChunkSizeOffset));
            if (chunkSize == 0 || chunkSize > MaxChunkSize)
                throw new InvalidDataException("Unsupported chunk size.");

            using var receiver = ECDiffieHellman.Create();
            receiver.ImportFromPem(File.ReadAllText(privateKeyPath));
            using var ephemeral = ImportUncompressed(header.AsSpan(PublicKeyOffset, PublicKeySize));

            byte[] sharedSecret = receiver.DeriveRawSecretAgreement(ephemeral.PublicKey);
            try
            {
                HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, aesKey, header.AsSpan(SaltOffset, SaltSize), info);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            using var aes = new AesGcm(aesKey, TagSize);
            output = new FileStream(
                writePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
            created = true;

            cipher = ArrayPool<byte>.Shared.Rent((int)chunkSize);
            plain = ArrayPool<byte>.Shared.Rent((int)chunkSize);
            byte[] aad = new byte[HeaderSize + 4 + 1 + 4];
            header.CopyTo(aad);
            Span<byte> nonce = stackalloc byte[12];
            Span<byte> record = stackalloc byte[4 + 1 + TagSize];
            uint index = 0;

            while (true)
            {
                ReadExact(input, record);
                uint length = BinaryPrimitives.ReadUInt32LittleEndian(record);
                byte lastFlag = record[4];
                if (lastFlag > 1 || length > chunkSize || (lastFlag == 0 && length != chunkSize))
                    throw new InvalidDataException("Invalid chunk framing.");

                header.AsSpan(NoncePrefixOffset, NoncePrefixSize).CopyTo(nonce);
                BinaryPrimitives.WriteUInt32LittleEndian(nonce[NoncePrefixSize..], index);
                BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(HeaderSize), index);
                aad[HeaderSize + 4] = lastFlag;
                BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(HeaderSize + 5), length);

                ReadExact(input, cipher.AsSpan(0, (int)length));
                aes.Decrypt(nonce, cipher.AsSpan(0, (int)length), record[5..], plain.AsSpan(0, (int)length), aad);
                output.Write(plain, 0, (int)length);

                if (lastFlag == 1)
                    break;
                if (index == uint.MaxValue)
                    throw new InvalidDataException("File exceeds the maximum number of chunks.");
                index++;
            }

            if (input.ReadByte() != -1)
                throw new InvalidDataException("Trailing data after the final chunk.");

            output.Dispose();
            output = null;
            if (replacing)
                File.Move(writePath, outputFile, overwrite: true);
            created = false;
            success = true;
            Console.WriteLine("Decryption complete!");
            Console.WriteLine($"Generated: {outputFile}");
            return 0;
        }
        catch (AuthenticationTagMismatchException)
        {
            Console.WriteLine("Decryption failed. The file was modified, or it was encrypted for a different key.");
            return 1;
        }
        catch (InvalidDataException ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return 1;
        }
        catch (EndOfStreamException)
        {
            Console.WriteLine("Error: Encrypted file is truncated.");
            return 1;
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Decryption failed. The file was modified, or it was encrypted for a different key.");
            return 1;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
            if (plain is not null)
                CryptographicOperations.ZeroMemory(plain);
            output?.Dispose();
            if (cipher is not null)
                ArrayPool<byte>.Shared.Return(cipher);
            if (plain is not null)
                ArrayPool<byte>.Shared.Return(plain);
            if (created && !success)
                File.Delete(writePath);
        }
    }

    static string ResolveOutputPath(string outputOption, string defaultFileName)
    {
        bool asDirectory = outputOption.EndsWith(Path.DirectorySeparatorChar)
            || outputOption.EndsWith(Path.AltDirectorySeparatorChar)
            || Directory.Exists(outputOption);
        return asDirectory ? Path.Combine(outputOption, defaultFileName) : outputOption;
    }

    static void ReadExact(Stream stream, Span<byte> destination)
    {
        int read = 0;
        while (read < destination.Length)
        {
            int n = stream.Read(destination[read..]);
            if (n == 0)
                throw new EndOfStreamException();
            read += n;
        }
    }

    static ECDiffieHellman ImportUncompressed(ReadOnlySpan<byte> raw)
    {
        if (raw.Length != 65 || raw[0] != 0x04)
            throw new CryptographicException("Invalid ephemeral public key.");

        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = raw.Slice(1, 32).ToArray(),
                Y = raw.Slice(33, 32).ToArray()
            }
        };
        return ECDiffieHellman.Create(parameters);
    }
}
