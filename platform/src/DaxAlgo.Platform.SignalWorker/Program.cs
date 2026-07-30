using System.Security.Cryptography;
using System.Text.Json;
using DaxAlgo.Platform.SignalWorker;

if (args is ["idle", "--work", _])
{
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return 0;
}

if (!TryReadRunOptions(args, out var options))
{
    Console.Error.WriteLine(
        "Usage: daxalgo-signal-worker run --package <file> --content-key <file> "
        + "--frames <file> --release-key <file> --release-key-id <id>");
    return 2;
}

byte[]? contentKey = null;
try
{
    var package = ReadBounded(options["--package"], 10 * 1024 * 1024);
    contentKey = ReadBounded(options["--content-key"], 32);
    if (contentKey.Length != 32)
    {
        throw new InvalidDataException("The content key must contain exactly 32 bytes.");
    }

    var frames = ReadBounded(options["--frames"], 64 * 1024 * 1024);
    var releaseKey = ReadBounded(options["--release-key"], 4 * 1024);
    DaxqSignalWorker.Execute(
        package,
        contentKey,
        frames,
        options["--release-key-id"],
        releaseKey,
        signal => Console.Out.WriteLine(JsonSerializer.Serialize(signal)));
    return 0;
}
catch (Exception exception) when (exception is
    IOException or
    InvalidDataException or
    JsonException or
    CryptographicException or
    ArgumentException or
    InvalidOperationException)
{
    Console.Error.WriteLine($"Signal worker rejected execution ({exception.GetType().Name}).");
    return 3;
}
finally
{
    if (contentKey is not null)
    {
        CryptographicOperations.ZeroMemory(contentKey);
    }
}

static bool TryReadRunOptions(string[] arguments, out Dictionary<string, string> options)
{
    options = new Dictionary<string, string>(StringComparer.Ordinal);
    if (arguments.Length != 11 || arguments[0] != "run")
    {
        return false;
    }

    for (var index = 1; index < arguments.Length; index += 2)
    {
        if (arguments[index] is not (
                "--package" or
                "--content-key" or
                "--frames" or
                "--release-key" or
                "--release-key-id")
            || string.IsNullOrWhiteSpace(arguments[index + 1])
            || !options.TryAdd(arguments[index], arguments[index + 1]))
        {
            return false;
        }
    }

    return options.Count == 5;
}

static byte[] ReadBounded(string path, int maximumBytes)
{
    var fullPath = Path.GetFullPath(path);
    var file = new FileInfo(fullPath);
    if (!file.Exists || file.Length <= 0 || file.Length > maximumBytes)
    {
        throw new InvalidDataException("A worker input is missing or outside its size bound.");
    }

    return File.ReadAllBytes(fullPath);
}
