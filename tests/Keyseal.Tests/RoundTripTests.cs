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
}
