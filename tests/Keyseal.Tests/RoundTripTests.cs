[CollectionDefinition("current-directory", DisableParallelization = true)]
public class CurrentDirectoryCollection;

[Collection("current-directory")]
public class KeygenTests
{
    [Fact]
    public void Keygen_refuses_to_overwrite_unless_forced()
    {
        string root = Path.Combine(Path.GetTempPath(), "keyseal-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(root);
        string previous = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(root);
            Assert.Equal(0, KeygenCommand.Run([]));
            string privateKey = File.ReadAllText("private.pem");
            string publicKey = File.ReadAllText("public.pem");

            Assert.Equal(1, KeygenCommand.Run([]));
            Assert.Equal(privateKey, File.ReadAllText("private.pem"));
            Assert.Equal(publicKey, File.ReadAllText("public.pem"));

            Assert.Equal(0, KeygenCommand.Run(["--force"]));
            Assert.NotEqual(privateKey, File.ReadAllText("private.pem"));
            Assert.NotEqual(publicKey, File.ReadAllText("public.pem"));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
            Directory.Delete(root, recursive: true);
        }
    }
}

[Collection("current-directory")]
public class RoundTripTests
{
    [Fact]
    public void Encrypt_then_decrypt_restores_plaintext()
    {
        string root = Path.Combine(Path.GetTempPath(), "keyseal-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(root);
        string previous = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(root);
            string plaintext = Path.Combine(root, "note.txt");
            File.WriteAllText(plaintext, "hello keyseal");

            Assert.Equal(0, KeygenCommand.Run([]));
            Assert.Equal(0, EncryptCommand.Run([plaintext]));
            File.Delete(plaintext);
            Assert.Equal(0, DecryptCommand.Run([plaintext + ".keyseal"]));
            Assert.Equal("hello keyseal", File.ReadAllText(plaintext));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Encrypt_folder_restores_files_and_empty_directories()
    {
        string root = Path.Combine(Path.GetTempPath(), "keyseal-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(root);
        string previous = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(root);
            string folder = Path.Combine(root, "secrets");
            Directory.CreateDirectory(Path.Combine(folder, "nested", "empty"));
            File.WriteAllText(Path.Combine(folder, "nested", "note.txt"), "inside");
            File.WriteAllBytes(Path.Combine(folder, "blob.bin"), [1, 2, 3, 4]);

            Assert.Equal(0, KeygenCommand.Run([]));
            Assert.Equal(0, EncryptCommand.Run([folder]));
            Directory.Delete(folder, recursive: true);
            Assert.Equal(0, DecryptCommand.Run([folder + ".keyseal"]));
            Assert.Equal("inside", File.ReadAllText(Path.Combine(folder, "nested", "note.txt")));
            Assert.Equal(new byte[] { 1, 2, 3, 4 }, File.ReadAllBytes(Path.Combine(folder, "blob.bin")));
            Assert.True(Directory.Exists(Path.Combine(folder, "nested", "empty")));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Encrypt_zip_file_does_not_unpack_on_decrypt()
    {
        string root = Path.Combine(Path.GetTempPath(), "keyseal-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(root);
        string previous = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(root);
            string zipPath = Path.Combine(root, "notes.zip");
            using (var zip = System.IO.Compression.ZipFile.Open(zipPath, System.IO.Compression.ZipArchiveMode.Create))
            {
                var entry = zip.CreateEntry("note.txt");
                using var writer = new StreamWriter(entry.Open());
                writer.Write("zipped");
            }

            byte[] original = File.ReadAllBytes(zipPath);
            Assert.Equal(0, KeygenCommand.Run([]));
            Assert.Equal(0, EncryptCommand.Run([zipPath]));
            File.Delete(zipPath);
            Assert.Equal(0, DecryptCommand.Run([zipPath + ".keyseal"]));
            Assert.Equal(original, File.ReadAllBytes(zipPath));
            Assert.False(Directory.Exists(Path.Combine(root, "notes")));
        }
        finally
        {
            Directory.SetCurrentDirectory(previous);
            Directory.Delete(root, recursive: true);
        }
    }
}
