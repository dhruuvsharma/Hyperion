using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DaxAlgo.Platform.Configuration;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace DaxAlgo.Platform.Features.VibeQuant;

internal sealed class VibeQuantModelDeploymentCatalog
{
    public const string SchemaVersion = "daxalgo.vibe-quant.serving-profile/v1";
    public const string ExecutionModelPrefix = "daxalgo-expert-sha256-";
    private const string ActivationDomain = "daxalgo-vibe-quant-execution-activation/v1";
    private const int MaxProfileBytes = 1_000_000;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public VibeQuantModelDeploymentCatalog(VibeQuantOptions options)
        : this(options, TimeProvider.System)
    {
    }

    public VibeQuantModelDeploymentCatalog(
        VibeQuantOptions options,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (options.Mode == "Mock")
        {
            ExecutionModelId = options.ModelId;
            PublicModelId = options.ModelId;
            Identity = null;
            strategyAuthoringAuthorized = true;
            ActivationSha256 = ComputeActivationSha256(options, null);
            return;
        }
        if (options.ModelDeploymentProfilePath is null ||
            options.ModelDeploymentProfileSha256 is null)
        {
            throw new InvalidOperationException("Live Vibe Quant model deployment activation is incomplete.");
        }

        var bytes = ReadProfile(options.ModelDeploymentProfilePath);
        var actualSha256 = ContentHasher.HashBytes(bytes);
        if (!StringComparer.Ordinal.Equals(actualSha256, options.ModelDeploymentProfileSha256))
        {
            throw new InvalidOperationException(
                "The configured Vibe Quant serving profile does not match its pinned SHA-256.");
        }
        var profile = DeserializeProfile(bytes);
        ValidateProfile(profile);
        var expectedModelId = CreateExecutionModelId(actualSha256);
        if (!StringComparer.Ordinal.Equals(options.ModelId, expectedModelId))
        {
            throw new InvalidOperationException(
                "The live Vibe Quant model ID must be derived from the pinned serving-profile SHA-256.");
        }

        ExecutionModelId = expectedModelId;
        PublicModelId = profile.ProfileId;
        var promotion = VibeQuantModelPromotionVerifier.Load(
            options,
            profile,
            actualSha256,
            expectedModelId,
            timeProvider);
        Identity = new VibeQuantModelDeploymentIdentity(
            actualSha256,
            profile.TrainingArtifact.ArtifactSha256,
            profile.TrainingArtifact.ArtifactTreeSha256,
            expectedModelId,
            promotion.EnvelopeSha256,
            promotion.PayloadSha256,
            promotion.DeploymentId,
            promotion.ProviderId,
            promotion.HostedPolicySha256,
            promotion.ExpiresAtUtc,
            promotion.ExpiresAtUtcText);
        strategyAuthoringAuthorized = promotion.StrategyAuthoringAuthorized;
        ActivationSha256 = ComputeActivationSha256(options, Identity);
    }

    public string ExecutionModelId { get; }

    public string PublicModelId { get; }

    public VibeQuantModelDeploymentIdentity? Identity { get; }

    internal string ActivationSha256 { get; }

    private readonly bool strategyAuthoringAuthorized;

    internal bool AuthorizesPurpose(CoordinatorRunPurpose purpose) => purpose switch
    {
        CoordinatorRunPurpose.Research => true,
        CoordinatorRunPurpose.StrategyAuthoring => strategyAuthoringAuthorized,
        _ => false,
    };

    public static string CreateExecutionModelId(string profileSha256)
    {
        RequireSha256(profileSha256, "Serving-profile SHA-256");
        return ExecutionModelPrefix + profileSha256;
    }

    private static string ComputeActivationSha256(
        VibeQuantOptions options,
        VibeQuantModelDeploymentIdentity? identity)
    {
        using var payload = new MemoryStream();
        Append(payload, ActivationDomain);
        Append(payload, options.Mode);
        if (identity is null)
        {
            Append(payload, options.ProviderId);
            Append(payload, options.ModelId);
            Append(payload, options.Protocol);
        }
        else
        {
            Append(payload, identity.ServingProfileSha256);
            Append(payload, identity.PromotionEnvelopeSha256);
            Append(payload, identity.PromotionPayloadSha256);
            Append(payload, identity.DeploymentId);
            Append(payload, identity.ProviderId);
            Append(payload, identity.HostedPolicySha256);
            Append(payload, identity.PromotionExpiresAtUtcText);
            Append(payload, options.BaseUrl!);
            Append(payload, options.ApiKeyEnvironmentVariable!);
            Append(payload, options.ModelAttestationAudience!);
            Append(payload, options.ModelAttestationKeyId!);
            Append(payload, options.ModelAttestationKeyEnvironmentVariable!);
        }
        return Convert.ToHexStringLower(SHA256.HashData(
            payload.GetBuffer().AsSpan(0, checked((int)payload.Length))));
    }

    private static void Append(Stream output, string value)
    {
        var bytes = StrictUtf8.GetBytes(value);
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
        output.Write(length);
        output.Write(bytes);
    }

    private static byte[] ReadProfile(string path)
    {
        var fullPath = Path.GetFullPath(path);
        RejectReparsePathComponents(fullPath);
        using var stream = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length is < 1 or > MaxProfileBytes)
        {
            throw new InvalidOperationException(
                $"Vibe Quant serving profile must contain 1 to {MaxProfileBytes:N0} bytes.");
        }
        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        if (bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }))
        {
            throw new InvalidOperationException("Vibe Quant serving profile must be BOM-less UTF-8 JSON.");
        }
        try
        {
            _ = StrictUtf8.GetString(bytes);
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidOperationException("Vibe Quant serving profile must be valid UTF-8.", exception);
        }
        return bytes;
    }

    private static VibeQuantServingProfile DeserializeProfile(byte[] bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 32
            });
            ValidateNoDuplicateProperties(document.RootElement, "serving profile");
            return JsonSerializer.Deserialize<VibeQuantServingProfile>(bytes, CoordinatorJson.Options)
                ?? throw new InvalidOperationException("Vibe Quant serving profile JSON was null.");
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException("Vibe Quant serving profile JSON is invalid.", exception);
        }
    }

    private static void ValidateProfile(VibeQuantServingProfile profile)
    {
        if (!StringComparer.Ordinal.Equals(profile.SchemaVersion, SchemaVersion))
        {
            throw new InvalidOperationException("Vibe Quant serving profile schema is unsupported.");
        }
        RequireSafeId(profile.ProfileId, "Serving profile ID", 100);
        RequireSha256(profile.CandidateCatalogSha256, "Candidate-catalog SHA-256");
        RequireSafeId(profile.CandidateId, "Candidate ID", 100);
        RequireModelId(profile.BaseModel.ModelId, "Base model ID");
        RequireRevision(profile.BaseModel.Revision, "Base model revision");
        RequireSha256(profile.TrainingArtifact.TrainingRunManifestSha256, "Training-run manifest SHA-256");
        RequireSha256(profile.TrainingArtifact.ArtifactSha256, "Training-artifact SHA-256");
        RequireSha256(profile.TrainingArtifact.ArtifactTreeSha256, "Training-artifact tree SHA-256");
        if (!StringComparer.Ordinal.Equals(profile.TrainingArtifact.Mode, "unpromoted-candidate"))
        {
            throw new InvalidOperationException("Training-artifact mode is unsupported for hosted evaluation.");
        }
        RequireSha256(profile.ChatTemplateSha256, "Chat-template SHA-256");
        if (!StringComparer.Ordinal.Equals(profile.Protocol, "openai-compatible"))
        {
            throw new InvalidOperationException("Vibe Quant serving profile protocol is unsupported.");
        }

        var runtime = profile.Runtime;
        RequireSafeId(runtime.Engine, "Serving engine", 100);
        RequireVersion(runtime.EngineVersion, "Serving engine version");
        if (runtime.ContainerImageDigest is not { Length: 71 } imageDigest ||
            !imageDigest.StartsWith("sha256:", StringComparison.Ordinal) ||
            !IsLowercaseHex(imageDigest.AsSpan(7)))
        {
            throw new InvalidOperationException(
                "Serving container image digest must be a lowercase sha256 OCI digest.");
        }
        if (runtime.Quantization is not (
                "none" or "bitsandbytes-nf4" or "awq" or "gptq" or "mxfp4"))
        {
            throw new InvalidOperationException("Serving quantization is unsupported.");
        }
        if (runtime.ComputeDtype is not ("float16" or "bfloat16" or "float32"))
        {
            throw new InvalidOperationException("Serving compute dtype is unsupported.");
        }
        if (runtime.MaxModelLength is < 128 or > 262_144 ||
            runtime.TensorParallelSize is < 1 or > 64)
        {
            throw new InvalidOperationException("Serving runtime limits are invalid.");
        }
        RequireSafeId(runtime.GpuProfile, "Serving GPU profile", 100);
        ValidateCandidateRuntime(profile.CandidateId, runtime);
    }

    private static void ValidateNoDuplicateProperties(JsonElement element, string path)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw new InvalidOperationException(
                        $"{path} contains duplicate property '{property.Name}'.");
                }
                ValidateNoDuplicateProperties(property.Value, $"{path}.{property.Name}");
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            var index = 0;
            foreach (var item in element.EnumerateArray())
            {
                ValidateNoDuplicateProperties(item, $"{path}[{index++}]");
            }
        }
    }

    private static void RejectReparsePathComponents(string fullPath)
    {
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidOperationException("Vibe Quant serving-profile path has no filesystem root.");
        var current = root;
        foreach (var segment in Path.GetRelativePath(root, fullPath)
                     .Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            var attributes = File.GetAttributes(current);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new InvalidOperationException(
                    "Vibe Quant serving-profile path must not traverse a reparse point.");
            }
        }
    }

    private static void RequireText(string value, string name, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{name} is invalid.");
        }
    }

    private static void RequireSafeId(string value, string name, int maximumLength)
    {
        RequireText(value, name, maximumLength);
        if (!char.IsAsciiLetterOrDigit(value[0]) || !value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
        {
            throw new InvalidOperationException($"{name} contains unsupported characters.");
        }
    }

    private static void RequireModelId(string value, string name)
    {
        RequireText(value, name, 200);
        if (!char.IsAsciiLetterOrDigit(value[0]) || !value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '/'))
        {
            throw new InvalidOperationException($"{name} contains unsupported characters.");
        }
    }

    private static void RequireVersion(string value, string name)
    {
        RequireText(value, name, 100);
        if (!char.IsAsciiLetterOrDigit(value[0]) || !value.All(character =>
                char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.' or '+' or ':'))
        {
            throw new InvalidOperationException($"{name} contains unsupported characters.");
        }
    }

    private static void ValidateCandidateRuntime(
        string candidateId,
        VibeQuantServingRuntime runtime)
    {
        var (maximumLength, quantizations) = candidateId switch
        {
            "qwen2.5-coder-7b-instruct" or "qwen2.5-coder-14b-instruct" =>
                (32_768, new[] { "none", "bitsandbytes-nf4" }),
            "gpt-oss-20b" => (131_072, new[] { "mxfp4" }),
            "qwen3-coder-30b-a3b-instruct" =>
                (262_144, new[] { "none", "bitsandbytes-nf4" }),
            _ => throw new InvalidOperationException("Serving candidate is not in the reviewed shortlist.")
        };
        if (runtime.MaxModelLength > maximumLength ||
            !quantizations.Contains(runtime.Quantization, StringComparer.Ordinal))
        {
            throw new InvalidOperationException("Serving runtime is incompatible with the reviewed candidate.");
        }
    }

    private static void RequireRevision(string value, string name)
    {
        if (value is not { Length: 40 } || !IsLowercaseHex(value))
        {
            throw new InvalidOperationException($"{name} must be an immutable lowercase commit.");
        }
    }

    private static void RequireSha256(string value, string name)
    {
        if (value is not { Length: 64 } || !IsLowercaseHex(value))
        {
            throw new InvalidOperationException($"{name} must be a lowercase SHA-256 value.");
        }
    }

    private static bool IsLowercaseHex(ReadOnlySpan<char> value)
    {
        foreach (var character in value)
        {
            if (character is not (>= '0' and <= '9' or >= 'a' and <= 'f'))
            {
                return false;
            }
        }
        return true;
    }
}

internal sealed record VibeQuantModelDeploymentIdentity(
    string ServingProfileSha256,
    string ArtifactSha256,
    string ArtifactTreeSha256,
    string ExecutionModelId,
    string PromotionEnvelopeSha256,
    string PromotionPayloadSha256,
    string DeploymentId,
    string ProviderId,
    string HostedPolicySha256,
    DateTimeOffset PromotionExpiresAtUtc,
    string PromotionExpiresAtUtcText);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantServingProfile
{
    public required string SchemaVersion { get; init; }

    public required string ProfileId { get; init; }

    public required string CandidateCatalogSha256 { get; init; }

    public required string CandidateId { get; init; }

    public required VibeQuantServingBaseModel BaseModel { get; init; }

    public required VibeQuantServingTrainingArtifact TrainingArtifact { get; init; }

    public required string ChatTemplateSha256 { get; init; }

    public required VibeQuantServingRuntime Runtime { get; init; }

    public required string Protocol { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantServingBaseModel
{
    public required string ModelId { get; init; }

    public required string Revision { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantServingTrainingArtifact
{
    public required string Mode { get; init; }

    public required string TrainingRunManifestSha256 { get; init; }

    public required string ArtifactSha256 { get; init; }

    public required string ArtifactTreeSha256 { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record VibeQuantServingRuntime
{
    public required string Engine { get; init; }

    public required string EngineVersion { get; init; }

    public required string ContainerImageDigest { get; init; }

    public required string Quantization { get; init; }

    public required string ComputeDtype { get; init; }

    public required int MaxModelLength { get; init; }

    public required int TensorParallelSize { get; init; }

    public required string GpuProfile { get; init; }
}
