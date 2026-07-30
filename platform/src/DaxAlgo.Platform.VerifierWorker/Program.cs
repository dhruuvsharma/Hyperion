using System.Text.Json;
using DaxAlgo.Platform.VerifierWorker;

if (args is ["idle", "--work", var workPath])
{
    var fullWorkPath = Path.GetFullPath(workPath);
    if (!Directory.Exists(fullWorkPath))
    {
        Console.Error.WriteLine("Verifier worker infrastructure error (work directory unavailable).");
        return 2;
    }

    Directory.SetCurrentDirectory(fullWorkPath);
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return 0;
}

if (args is ["stage", "--work", var stagingWorkPath])
{
    try
    {
        await VerifierInputStager.StageAsync(
            Console.OpenStandardInput(),
            stagingWorkPath);
        return 0;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"Verifier input staging failed ({exception.GetType().Name}).");
        return 5;
    }
}

if (args is [
        "replay",
        "--assembly", var assemblyPath,
        "--request", var replayRequestPath,
        "--result", var replayResultPath])
{
    try
    {
        return await CandidateReplayProcess.RunChildAsync(
            assemblyPath,
            replayRequestPath,
            replayResultPath);
    }
    catch (Exception)
    {
        Console.Error.WriteLine("Candidate replay child failed.");
        return 4;
    }
}

if (args is [
        "verify-stdout",
        "--request", var stdoutRequestPath,
        "--source", var stdoutSourcePath])
{
    try
    {
        var requestBytes = HeadlessStrategyVerifier.ReadBoundedFile(
            stdoutRequestPath,
            HeadlessStrategyVerifier.MaximumRequestBytes);
        var sourceBytes = HeadlessStrategyVerifier.ReadBoundedFile(
            stdoutSourcePath,
            HeadlessStrategyVerifier.MaximumSourceBytes);
        var result = await HeadlessStrategyVerifier.VerifyAsync(requestBytes, sourceBytes);
        var json = HeadlessStrategyVerifier.SerializeResult(result);
        if (json.Length > HeadlessStrategyVerifier.MaximumResultBytes)
        {
            throw new InvalidDataException("The verifier result exceeded its byte bound.");
        }

        await using var output = Console.OpenStandardOutput();
        await output.WriteAsync(json);
        await output.FlushAsync();
        return 0;
    }
    catch (Exception exception) when (exception is
        IOException or
        InvalidDataException or
        UnauthorizedAccessException or
        ArgumentException or
        NotSupportedException or
        JsonException)
    {
        Console.Error.WriteLine($"Verifier worker infrastructure error ({exception.GetType().Name}).");
        return 3;
    }
}

if (args is not ["verify", "--request", var requestPath, "--source", var sourcePath, "--output", var outputPath])
{
    Console.Error.WriteLine(
        "Usage: daxalgo-verifier-worker idle --work PATH | "
        + "stage --work PATH | "
        + "verify --request FILE --source FILE --output DIR | "
        + "verify-stdout --request FILE --source FILE | "
        + "replay --assembly FILE --request FILE --result FILE");
    return 2;
}

try
{
    var requestBytes = HeadlessStrategyVerifier.ReadBoundedFile(
        requestPath,
        HeadlessStrategyVerifier.MaximumRequestBytes);
    var sourceBytes = HeadlessStrategyVerifier.ReadBoundedFile(
        sourcePath,
        HeadlessStrategyVerifier.MaximumSourceBytes);
    var result = await HeadlessStrategyVerifier.VerifyAsync(requestBytes, sourceBytes);
    var outputDirectory = Path.GetFullPath(outputPath);
    Directory.CreateDirectory(outputDirectory);
    var resultPath = Path.Combine(outputDirectory, HeadlessStrategyVerifier.ResultFileName);
    var json = HeadlessStrategyVerifier.SerializeResult(result);
    if (json.Length > HeadlessStrategyVerifier.MaximumResultBytes)
    {
        throw new InvalidDataException("The verifier result exceeded its byte bound.");
    }

    await using var stream = new FileStream(
        resultPath,
        FileMode.CreateNew,
        FileAccess.Write,
        FileShare.None,
        bufferSize: 16 * 1024,
        options: FileOptions.Asynchronous | FileOptions.WriteThrough);
    await stream.WriteAsync(json);
    await stream.FlushAsync();
    return 0;
}
catch (Exception exception) when (exception is
    IOException or
    InvalidDataException or
    UnauthorizedAccessException or
    ArgumentException or
    NotSupportedException or
    JsonException)
{
    Console.Error.WriteLine($"Verifier worker infrastructure error ({exception.GetType().Name}).");
    return 3;
}
