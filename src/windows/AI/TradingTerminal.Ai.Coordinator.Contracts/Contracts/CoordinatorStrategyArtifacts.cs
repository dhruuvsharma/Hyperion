using TradingTerminal.Ai.Coordinator.Security;

namespace TradingTerminal.Ai.Coordinator.Contracts;

public sealed record CoordinatorStrategyDraftFile(
    string RelativePath,
    string Content);

public sealed record CoordinatorStrategyDraft
{
    public required string StrategyId { get; init; }
    public required string DisplayName { get; init; }
    public IReadOnlyList<CoordinatorStrategyDraftFile> Files { get; init; } = [];
}

public sealed record CoordinatorStrategySourceFile(
    string RelativePath,
    string Content,
    string ContentSha256);

public sealed record CoordinatorStrategySourceArtifact
{
    public required string SchemaVersion { get; init; }
    public required Guid RunId { get; init; }
    public required string ObjectiveSha256 { get; init; }
    public required string StrategyId { get; init; }
    public required string DisplayName { get; init; }
    public IReadOnlyList<CoordinatorStrategySourceFile> Files { get; init; } = [];
    public IReadOnlyList<string> EvidenceSourceIds { get; init; } = [];
    public required string SynthesizerArtifactSha256 { get; init; }
    public required string RiskJudgeArtifactSha256 { get; init; }
    public required string DeliveryState { get; init; }
    public required string CompilerProfile { get; init; }
    public bool RequiresHumanRelease { get; init; }
    public bool RequiresTerminalCompileConsent { get; init; }
    public bool InstallEligible { get; init; }
}

public static class CoordinatorStrategyArtifactValidation
{
    private static readonly HashSet<string> WindowsReservedDeviceNames = new(
        ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
         "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"],
        StringComparer.OrdinalIgnoreCase);

    public const int MaximumFiles = 16;
    public const int MaximumFileCharacters = 200_000;
    public const int MaximumAggregateCharacters = 1_000_000;

    public static void ValidateDraft(CoordinatorStrategyDraft draft)
    {
        if (draft is null ||
            !IsSafeIdentifier(draft.StrategyId, 100) ||
            !IsText(draft.DisplayName, 200) ||
            draft.Files is null ||
            draft.Files.Count is < 1 or > MaximumFiles)
        {
            throw new InvalidDataException("Strategy draft metadata or file count is invalid.");
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var aggregateCharacters = 0;
        foreach (var file in draft.Files)
        {
            if (file is null ||
                !IsSafeRelativeCSharpPath(file.RelativePath) ||
                string.IsNullOrWhiteSpace(file.Content) ||
                file.Content.Length > MaximumFileCharacters ||
                file.Content.IndexOf('\0') >= 0 ||
                !paths.Add(file.RelativePath))
            {
                throw new InvalidDataException("Strategy draft contains an invalid or duplicate C# file.");
            }

            aggregateCharacters = checked(aggregateCharacters + file.Content.Length);
            if (aggregateCharacters > MaximumAggregateCharacters)
            {
                throw new InvalidDataException(
                    $"Strategy draft exceeds {MaximumAggregateCharacters:N0} aggregate characters.");
            }
        }
    }

    public static void Validate(CoordinatorStrategySourceArtifact artifact)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        if (artifact.SchemaVersion != CoordinatorVersions.StrategyArtifactSchema ||
            artifact.RunId == Guid.Empty ||
            !IsSha256(artifact.ObjectiveSha256) ||
            !IsSafeIdentifier(artifact.StrategyId, 100) ||
            !IsText(artifact.DisplayName, 200) ||
            !IsSha256(artifact.SynthesizerArtifactSha256) ||
            !IsSha256(artifact.RiskJudgeArtifactSha256) ||
            artifact.DeliveryState != CoordinatorVersions.StrategyDeliveryState ||
            artifact.CompilerProfile != CoordinatorVersions.StrategyCompilerProfile ||
            !artifact.RequiresHumanRelease ||
            !artifact.RequiresTerminalCompileConsent ||
            artifact.InstallEligible)
        {
            throw new InvalidDataException("Strategy source artifact metadata is invalid or grants execution authority.");
        }

        if (artifact.Files is null || artifact.Files.Count is < 1 or > MaximumFiles)
        {
            throw new InvalidDataException(
                $"Strategy source artifact must contain 1 to {MaximumFiles} files.");
        }

        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var aggregateCharacters = 0;
        foreach (var file in artifact.Files)
        {
            if (file is null || !IsSafeRelativeCSharpPath(file.RelativePath) ||
                string.IsNullOrWhiteSpace(file.Content) ||
                file.Content.Length > MaximumFileCharacters ||
                file.Content.IndexOf('\0') >= 0 ||
                !StringComparer.Ordinal.Equals(file.ContentSha256, ContentHasher.HashUtf8(file.Content)) ||
                !paths.Add(file.RelativePath))
            {
                throw new InvalidDataException("Strategy source artifact contains an invalid or duplicate C# file.");
            }

            aggregateCharacters = checked(aggregateCharacters + file.Content.Length);
            if (aggregateCharacters > MaximumAggregateCharacters)
            {
                throw new InvalidDataException(
                    $"Strategy source artifact exceeds {MaximumAggregateCharacters:N0} aggregate characters.");
            }
        }

        if (artifact.EvidenceSourceIds is null ||
            artifact.EvidenceSourceIds.Count > 100 ||
            artifact.EvidenceSourceIds.Any(sourceId => !IsSafeIdentifier(sourceId, 100)) ||
            artifact.EvidenceSourceIds.Distinct(StringComparer.Ordinal).Count() != artifact.EvidenceSourceIds.Count)
        {
            throw new InvalidDataException("Strategy source artifact evidence-source identities are invalid.");
        }
    }

    public static void ValidateForRun(
        CoordinatorStrategySourceArtifact artifact,
        CoordinatorRunSpec spec,
        IReadOnlyList<CoordinatorArtifactReference> artifactReferences)
    {
        Validate(artifact);
        ArgumentNullException.ThrowIfNull(spec);
        ArgumentNullException.ThrowIfNull(artifactReferences);

        var allowedSourceIds = spec.Sources?.Select(source => source.Id).ToHashSet(StringComparer.Ordinal)
            ?? throw new InvalidDataException("Strategy run sources are missing.");
        var artifactSha256 = ContentHasher.HashJson(artifact);
        if (spec.Purpose != CoordinatorRunPurpose.StrategyAuthoring ||
            artifact.RunId != spec.RunId ||
            !StringComparer.Ordinal.Equals(artifact.ObjectiveSha256, ContentHasher.HashUtf8(spec.Objective)) ||
            artifact.EvidenceSourceIds.Any(sourceId => !allowedSourceIds.Contains(sourceId)) ||
            artifactReferences.Count(reference =>
                reference.Role == CoordinatorRole.Synthesizer &&
                reference.SchemaVersion == CoordinatorVersions.ArtifactSchema &&
                StringComparer.Ordinal.Equals(reference.Sha256, artifact.SynthesizerArtifactSha256)) != 1 ||
            artifactReferences.Count(reference =>
                reference.Role == CoordinatorRole.RiskJudge &&
                reference.SchemaVersion == CoordinatorVersions.ArtifactSchema &&
                StringComparer.Ordinal.Equals(reference.Sha256, artifact.RiskJudgeArtifactSha256)) != 1 ||
            artifactReferences.Count(reference =>
                reference.Role == CoordinatorRole.Synthesizer &&
                reference.Kind == CoordinatorVersions.StrategyArtifactKind &&
                reference.SchemaVersion == CoordinatorVersions.StrategyArtifactSchema &&
                StringComparer.Ordinal.Equals(reference.Sha256, artifactSha256)) != 1)
        {
            throw new InvalidDataException("Strategy source artifact is not bound to the exact run evidence.");
        }
    }

    public static bool IsSha256(string? value) =>
        value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static bool IsText(string? value, int maximumCharacters) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumCharacters &&
        value == value.Trim() &&
        value.IndexOf('\0') < 0;

    public static bool IsSafeIdentifier(string? value, int maximumCharacters) =>
        IsText(value, maximumCharacters) &&
        value![0] is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') &&
        value.All(character =>
            character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');

    private static bool IsSafeRelativeCSharpPath(string? value)
    {
        if (!IsText(value, 200) || value!.Contains('\\') || value[0] == '/' ||
            !value.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return value.Split('/').All(IsSafePathSegment);
    }

    private static bool IsSafePathSegment(string segment)
    {
        if (segment.Length == 0 || segment is "." or ".." || segment.EndsWith('.') ||
            segment[0] is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9') ||
            segment.Any(character =>
                character is not (>= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_')))
        {
            return false;
        }

        var deviceStem = segment.Split('.')[0];
        return !WindowsReservedDeviceNames.Contains(deviceStem);
    }
}
