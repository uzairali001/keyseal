using System.Security.Cryptography;

static class KeygenCommand
{
    const string Usage = "Usage: keyseal keygen [--force]";

    public static int Run(string[] args)
    {
        bool force = false;
        foreach (string arg in args)
        {
            if (arg is "--force")
            {
                if (force)
                {
                    Console.WriteLine("Error: --force specified more than once.");
                    Console.WriteLine(Usage);
                    return 1;
                }

                force = true;
                continue;
            }

            Console.WriteLine($"Error: Unknown option '{arg}'.");
            Console.WriteLine(Usage);
            return 1;
        }

        const string PrivateKeyPath = "private.pem";
        const string PublicKeyPath = "public.pem";
        bool privateExists = File.Exists(PrivateKeyPath);
        bool publicExists = File.Exists(PublicKeyPath);
        if (!force && (privateExists || publicExists))
        {
            string existing = privateExists && publicExists
                ? $"'{PrivateKeyPath}' and '{PublicKeyPath}' already exist"
                : privateExists
                    ? $"'{PrivateKeyPath}' already exists"
                    : $"'{PublicKeyPath}' already exists";
            Console.WriteLine($"Error: {existing}. Pass --force to overwrite.");
            return 1;
        }

        Console.WriteLine("Generating ECC (NIST P-256) keypair...");
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        string privateKeyPem = ecdh.ExportPkcs8PrivateKeyPem();
        string publicKeyPem = ecdh.ExportSubjectPublicKeyInfoPem();

        File.WriteAllText(PrivateKeyPath, privateKeyPem);
        File.WriteAllText(PublicKeyPath, publicKeyPem);

        Console.WriteLine("Success! Saved 'private.pem' and 'public.pem'.");
        Console.WriteLine("Send 'public.pem' to your friend.");
        return 0;
    }
}
