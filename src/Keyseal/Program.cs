if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintUsage();
    return args.Length == 0 ? 1 : 0;
}

string command = args[0];
string[] rest = args[1..];
return command switch
{
    "keygen" => KeygenCommand.Run(rest),
    "encrypt" => EncryptCommand.Run(rest),
    "decrypt" => DecryptCommand.Run(rest),
    _ => Unknown(command)
};

static int Unknown(string command)
{
    Console.WriteLine($"Error: Unknown command '{command}'.");
    PrintUsage();
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("""
        keyseal — encrypt a file for a recipient public key

          keyseal keygen
          keyseal encrypt <file> [--public-key <path>] [--replace]
          keyseal decrypt <file.keyseal> [--output <path>] [--replace]
        """);
}
