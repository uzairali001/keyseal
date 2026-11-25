using System.Buffers;
using System.Buffers.Binary;
using System.IO.Compression;
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
        string? scratchPath = null;
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
            if (!header.AsSpan(0, 4).SequenceEqual("E1GC"u8) || header[SuiteOffset] != 1
                || header[VersionOffset] is not (1 or 2))
                throw new InvalidDataException("Unrecognized container. Expected an E1GC v1 or v2 file.");
            bool versionedPayload = header[VersionOffset] == 2;

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
            string? folderZip = null;
            bool kindKnown = !versionedPayload;
            byte payloadKind = 1;
            bool replacingFile = false;
            if (!versionedPayload && !TryOpenFileOutput(outputFile, replace, out output, out scratchPath, out replacingFile, out string? openError))
            {
                Console.WriteLine(openError);
                return 1;
            }

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
                int offset = 0;
                if (!kindKnown)
                {
                    if (length == 0)
                        throw new InvalidDataException("Missing payload kind.");
                    payloadKind = plain[0];
                    if (payloadKind is not (1 or 2))
                        throw new InvalidDataException("Unrecognized payload.");
                    kindKnown = true;
                    offset = 1;
                    if (payloadKind == 2)
                    {
                        folderZip = Path.Combine(Path.GetTempPath(), "keyseal-" + Guid.NewGuid().ToString("n") + ".zip");
                        scratchPath = folderZip;
                        output = new FileStream(
                            folderZip, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
                    }
                    else if (!TryOpenFileOutput(outputFile, replace, out output, out scratchPath, out replacingFile, out string? kindOpenError))
                    {
                        Console.WriteLine(kindOpenError);
                        return 1;
                    }
                }

                if (length > (uint)offset)
                    output!.Write(plain, offset, (int)length - offset);

                if (lastFlag == 1)
                    break;
                if (index == uint.MaxValue)
                    throw new InvalidDataException("File exceeds the maximum number of chunks.");
                index++;
            }

            if (input.ReadByte() != -1)
                throw new InvalidDataException("Trailing data after the final chunk.");

            if (!kindKnown)
                throw new InvalidDataException("Missing payload kind.");

            output?.Dispose();
            output = null;
            if (payloadKind == 2)
            {
                try
                {
                    ExtractFolder(folderZip!, outputFile, replace);
                }
                catch (InvalidDataException)
                {
                    throw;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                    return 1;
                }

                File.Delete(folderZip!);
                scratchPath = null;
            }
            else if (replacingFile)
            {
                File.Move(scratchPath!, outputFile, overwrite: true);
                scratchPath = null;
            }
            else
            {
                scratchPath = null;
            }

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
            if (!success && scratchPath is not null && File.Exists(scratchPath))
                File.Delete(scratchPath);
        }
    }

    static bool TryOpenFileOutput(
        string outputFile, bool replace, out FileStream? output, out string? writePath, out bool replacing, out string? error)
    {
        output = null;
        writePath = null;
        replacing = false;
        error = null;
        if (Directory.Exists(outputFile))
        {
            error = $"Error: Output '{outputFile}' is a directory.";
            return false;
        }

        string? outputDirectory = Path.GetDirectoryName(Path.GetFullPath(outputFile));
        if (!string.IsNullOrEmpty(outputDirectory))
            Directory.CreateDirectory(outputDirectory);

        writePath = outputFile;
        if (File.Exists(outputFile))
        {
            if (!replace)
            {
                error = $"Error: Output file '{outputFile}' already exists. Pass --replace to overwrite it.";
                writePath = null;
                return false;
            }

            writePath = outputFile + ".partial";
            replacing = true;
            if (File.Exists(writePath))
                File.Delete(writePath);
        }

        output = new FileStream(
            writePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 128 * 1024, FileOptions.SequentialScan);
        return true;
    }

    static void ExtractFolder(string zipPath, string destination, bool replace)
    {
        string destRoot = Path.GetFullPath(destination);
        if (File.Exists(destRoot))
        {
            if (!replace)
                throw new IOException($"Output '{destination}' already exists. Pass --replace to overwrite it.");
            File.Delete(destRoot);
        }

        bool existed = Directory.Exists(destRoot);
        if (existed && !replace && Directory.EnumerateFileSystemEntries(destRoot).Any())
            throw new IOException($"Output directory '{destination}' already exists. Pass --replace to overwrite it.");

        Directory.CreateDirectory(destRoot);
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string target = SafeEntryPath(destRoot, entry.FullName);
                if (entry.FullName.EndsWith('/') || entry.FullName.EndsWith('\\'))
                {
                    Directory.CreateDirectory(target);
                    continue;
                }

                string? parent = Path.GetDirectoryName(target);
                if (!string.IsNullOrEmpty(parent))
                    Directory.CreateDirectory(parent);
                entry.ExtractToFile(target, overwrite: true);
            }
        }
        catch
        {
            if (!existed && Directory.Exists(destRoot))
                Directory.Delete(destRoot, recursive: true);
            throw;
        }
    }

    static string SafeEntryPath(string destRoot, string entryName)
    {
        string normalized = entryName.Replace('\\', '/').TrimEnd('/');
        if (normalized.Length == 0)
            return destRoot;
        if (normalized.Contains(':') || Path.IsPathRooted(entryName))
            throw new InvalidDataException("Archive entry path escapes the output directory.");

        string combined = Path.GetFullPath(Path.Combine(destRoot, normalized));
        string rootWithSeparator = destRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!combined.Equals(destRoot, StringComparison.OrdinalIgnoreCase)
            && !combined.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Archive entry path escapes the output directory.");
        return combined;
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
