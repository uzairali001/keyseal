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
