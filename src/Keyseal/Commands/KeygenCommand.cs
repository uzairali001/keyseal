using System.Security.Cryptography;

static class KeygenCommand
{
    public static int Run(string[] args)
    {
        if (args.Length > 0)
        {
            Console.WriteLine("Usage: keyseal keygen");
            return 1;
        }

        Console.WriteLine("Generating ECC (NIST P-256) keypair...");
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        string privateKeyPem = ecdh.ExportPkcs8PrivateKeyPem();
        string publicKeyPem = ecdh.ExportSubjectPublicKeyInfoPem();

        File.WriteAllText("private.pem", privateKeyPem);
        File.WriteAllText("public.pem", publicKeyPem);

        Console.WriteLine("Success! Saved 'private.pem' and 'public.pem'.");
        Console.WriteLine("Send 'public.pem' to your friend.");
        return 0;
    }
}
