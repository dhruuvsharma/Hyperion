using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Client;

public interface IVibeQuantApiClient
{
    Task<VibeQuantCreditBalanceResponse> GetCreditsAsync(CancellationToken cancellationToken = default);

    Task<VibeQuantRunSpecResponse> CreateRunAsync(
        CreateVibeQuantRunRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default);

    Task<VibeQuantRunSpecResponse> GetSpecificationAsync(
        Guid runId,
        CancellationToken cancellationToken = default);

    Task<VibeQuantRunStatusResponse> StartAsync(
        Guid runId,
        string specSha256,
        CancellationToken cancellationToken = default);

    Task<VibeQuantRunStatusResponse> GetStatusAsync(
        Guid runId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<VibeQuantRunStatusResponse>> ListAsync(
        CancellationToken cancellationToken = default);

    Task<VibeQuantArtifactResponse> GetArtifactAsync(
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken = default);

    Task<VibeQuantRunStatusResponse> ReleaseAsync(
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken = default);

    Task<VibeQuantRunStatusResponse> CancelAsync(
        Guid runId,
        CancellationToken cancellationToken = default);
}

public sealed class VibeQuantApiClient(HttpClient httpClient) : IVibeQuantApiClient
{
    private const int MaximumResponseBytes = VibeQuantApiVersions.MaximumResponseBytes;

    public async Task<VibeQuantCreditBalanceResponse> GetCreditsAsync(CancellationToken cancellationToken = default) =>
        ValidateCredits(await SendAsync<VibeQuantCreditBalanceResponse>(
            HttpMethod.Get,
            "/api/v1/vibe-quant/credits",
            null,
            null,
            cancellationToken).ConfigureAwait(false));

    public async Task<VibeQuantRunSpecResponse> CreateRunAsync(
        CreateVibeQuantRunRequest request,
        string idempotencyKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!Enum.IsDefined(request.Purpose))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Vibe Quant run purpose is not supported.");
        }
        ValidateIdempotencyKey(idempotencyKey);
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, CoordinatorJson.Options);
        if (requestBytes.Length > VibeQuantApiVersions.MaximumRequestBytes)
        {
            throw new InvalidDataException(
                $"Vibe Quant create request exceeds the {VibeQuantApiVersions.MaximumRequestBytes:N0}-byte limit.");
        }
        var response = ValidateSpecification(await SendAsync<VibeQuantRunSpecResponse>(
            HttpMethod.Post,
            "/api/v1/vibe-quant/runs",
            request,
            idempotencyKey,
            cancellationToken).ConfigureAwait(false), expectedRunId: null);
        if (!StringComparer.Ordinal.Equals(request.Objective, response.Spec.Objective))
        {
            throw InvalidResponse("the run objective does not match the submitted objective");
        }
        var purposeMatches = request.Purpose switch
        {
            CoordinatorRunPurpose.Research =>
                response.Spec.PolicyVersion == CoordinatorVersions.Policy &&
                response.Spec.WorkflowVersion == CoordinatorVersions.Workflow &&
                response.Spec.PromptCatalogSha256 == CoordinatorVersions.ResearchPromptCatalogSha256,
            CoordinatorRunPurpose.StrategyAuthoring =>
                response.Spec.PolicyVersion == CoordinatorVersions.StrategyPolicy &&
                response.Spec.WorkflowVersion == CoordinatorVersions.StrategyWorkflow &&
                response.Spec.PromptCatalogSha256 == CoordinatorVersions.StrategyPromptCatalogSha256 &&
                response.Spec.Provider.Protocol is "mock" or "openai-compatible",
            _ => false
        };
        if (!purposeMatches)
        {
            throw InvalidResponse("the run profile does not match the submitted purpose");
        }
        ValidateSubmittedSources(request.Sources, response.Spec.Sources);
        return response;
    }

    public async Task<VibeQuantRunSpecResponse> GetSpecificationAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        return ValidateSpecification(await SendAsync<VibeQuantRunSpecResponse>(
            HttpMethod.Get,
            $"/api/v1/vibe-quant/runs/{runId:D}/spec",
            null,
            null,
            cancellationToken).ConfigureAwait(false), runId);
    }

    public async Task<VibeQuantRunStatusResponse> StartAsync(
        Guid runId,
        string specSha256,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        specSha256 = RequireSha256(specSha256);
        var response = ValidateStatus(await SendAsync<VibeQuantRunStatusResponse>(
            HttpMethod.Post,
            $"/api/v1/vibe-quant/runs/{runId:D}/start",
            new StartVibeQuantRunRequest(specSha256),
            null,
            cancellationToken).ConfigureAwait(false), runId);
        if (!StringComparer.Ordinal.Equals(response.SpecSha256, specSha256) ||
            response.Status is not (CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running or
                CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed or
                CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected))
        {
            throw InvalidResponse("the start response does not match the approved specification");
        }
        return response;
    }

    public async Task<VibeQuantRunStatusResponse> GetStatusAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        return ValidateStatus(await SendAsync<VibeQuantRunStatusResponse>(
            HttpMethod.Get,
            $"/api/v1/vibe-quant/runs/{runId:D}",
            null,
            null,
            cancellationToken).ConfigureAwait(false), runId);
    }

    public async Task<IReadOnlyList<VibeQuantRunStatusResponse>> ListAsync(
        CancellationToken cancellationToken = default) =>
        ValidateList(await SendAsync<List<VibeQuantRunStatusResponse>>(
            HttpMethod.Get,
            "/api/v1/vibe-quant/runs",
            null,
            null,
            cancellationToken).ConfigureAwait(false));

    public async Task<VibeQuantArtifactResponse> GetArtifactAsync(
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        artifactSha256 = RequireSha256(artifactSha256);
        return ValidateArtifact(await SendAsync<VibeQuantArtifactResponse>(
            HttpMethod.Get,
            $"/api/v1/vibe-quant/runs/{runId:D}/artifacts/{artifactSha256}",
            null,
            null,
            cancellationToken).ConfigureAwait(false), runId, artifactSha256);
    }

    public async Task<VibeQuantRunStatusResponse> ReleaseAsync(
        Guid runId,
        string artifactSha256,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        artifactSha256 = RequireSha256(artifactSha256);
        var response = ValidateStatus(await SendAsync<VibeQuantRunStatusResponse>(
            HttpMethod.Post,
            $"/api/v1/vibe-quant/runs/{runId:D}/release",
            new ReleaseVibeQuantRunRequest(artifactSha256),
            null,
            cancellationToken).ConfigureAwait(false), runId);
        if (response.Status != CoordinatorRunStatus.Completed ||
            !StringComparer.Ordinal.Equals(response.FinalArtifactSha256, artifactSha256))
        {
            throw InvalidResponse("the release response does not match the approved artifact");
        }
        return response;
    }

    public async Task<VibeQuantRunStatusResponse> CancelAsync(
        Guid runId,
        CancellationToken cancellationToken = default)
    {
        runId = RequireRunId(runId);
        var response = ValidateStatus(await SendAsync<VibeQuantRunStatusResponse>(
            HttpMethod.Post,
            $"/api/v1/vibe-quant/runs/{runId:D}/cancel",
            new { },
            null,
            cancellationToken).ConfigureAwait(false), runId);
        if (response.Status == CoordinatorRunStatus.Running && !response.CancellationRequested ||
            response.Status is not (CoordinatorRunStatus.Running or CoordinatorRunStatus.Cancelled or
                CoordinatorRunStatus.Completed or CoordinatorRunStatus.Rejected))
        {
            throw InvalidResponse("the cancellation response is inconsistent");
        }
        return response;
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        string? idempotencyKey,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: CoordinatorJson.Options);
        }
        if (idempotencyKey is not null)
        {
            request.Headers.Add("Idempotency-Key", idempotencyKey);
        }

        using var response = await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        var bytes = await ReadBoundedAsync(response, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new VibeQuantApiException(response.StatusCode, ReadProblemDetail(bytes));
        }

        try
        {
            return JsonSerializer.Deserialize<T>(bytes, CoordinatorJson.Options)
                ?? throw new VibeQuantApiException(response.StatusCode, "The server returned JSON null.");
        }
        catch (JsonException exception)
        {
            throw new VibeQuantApiException(
                response.StatusCode,
                "The server returned an invalid Vibe Quant response.",
                exception);
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaximumResponseBytes)
        {
            throw new VibeQuantApiException(response.StatusCode, "The server response exceeded the client limit.");
        }

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            if (output.Length + read > MaximumResponseBytes)
            {
                throw new VibeQuantApiException(response.StatusCode, "The server response exceeded the client limit.");
            }
            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
        return output.ToArray();
    }

    private static string ReadProblemDetail(byte[] bytes)
    {
        try
        {
            using var document = JsonDocument.Parse(bytes);
            return document.RootElement.TryGetProperty("detail", out var detail) && detail.ValueKind == JsonValueKind.String
                ? detail.GetString() ?? "The Vibe Quant request failed."
                : "The Vibe Quant request failed.";
        }
        catch (JsonException)
        {
            return "The Vibe Quant request failed.";
        }
    }

    private static VibeQuantCreditBalanceResponse ValidateCredits(VibeQuantCreditBalanceResponse response)
    {
        if (response.AvailableCredits < 0 || response.ReservedCredits < 0 ||
            response.ConsumedCredits < 0 || string.IsNullOrWhiteSpace(response.CreditPricingVersion) ||
            response.UpdatedAtUtc == default)
        {
            throw InvalidResponse("the credit balance is outside the supported range");
        }
        return response;
    }

    private static VibeQuantRunSpecResponse ValidateSpecification(
        VibeQuantRunSpecResponse response,
        Guid? expectedRunId)
    {
        if (response.Spec is null || response.Spec.RunId == Guid.Empty ||
            expectedRunId is { } expected && response.Spec.RunId != expected ||
            response.Spec.SchemaVersion != VibeQuantApiVersions.RunSpecification ||
            string.IsNullOrWhiteSpace(response.Spec.Objective) ||
            response.Spec.CreatedAtUtc == default ||
            response.Spec.Sources is null ||
            response.Spec.Provider is null ||
            string.IsNullOrWhiteSpace(response.Spec.Provider.ProviderId) ||
            string.IsNullOrWhiteSpace(response.Spec.Provider.ModelId) ||
            string.IsNullOrWhiteSpace(response.Spec.Provider.Protocol) ||
            response.Spec.Budget is null ||
            !IsValidBudget(response.Spec.Budget) ||
            response.Spec.MaximumCreditCharge < 1 ||
            string.IsNullOrWhiteSpace(response.Spec.CreditPricingVersion) ||
            string.IsNullOrWhiteSpace(response.Spec.PolicyVersion) ||
            string.IsNullOrWhiteSpace(response.Spec.WorkflowVersion) ||
            !IsCanonicalSha256(response.Spec.PromptCatalogSha256) ||
            !IsCanonicalSha256(response.Spec.ExecutionProfileBinding) ||
            !IsCanonicalSha256(response.SpecSha256) ||
            !StringComparer.Ordinal.Equals(ContentHasher.HashJson(response.Spec), response.SpecSha256) ||
            !AreValidSources(response.Spec.Sources))
        {
            throw InvalidResponse("the run specification failed semantic or hash validation");
        }
        return response;
    }

    private static bool AreValidSources(IReadOnlyList<VibeQuantSourceView> sources)
    {
        if (sources.Count > 64)
        {
            return false;
        }
        var identifiers = new HashSet<string>(StringComparer.Ordinal);
        return sources.All(source =>
            source is not null &&
            !string.IsNullOrWhiteSpace(source.Id) && identifiers.Add(source.Id) &&
            !string.IsNullOrWhiteSpace(source.Title) &&
            source.ContentCharacters >= 0 &&
            source.Uri is null or { Length: <= 2_048 } &&
            source.License is null or { Length: >= 1 and <= 200 } &&
            IsCanonicalSha256(source.ContentSha256));
    }

    private static void ValidateSubmittedSources(
        IReadOnlyList<CoordinatorContextSource>? submitted,
        IReadOnlyList<VibeQuantSourceView> returned)
    {
        if (submitted is null || submitted.Count != returned.Count)
        {
            throw InvalidResponse("the source manifest does not match the submitted source set");
        }
        for (var index = 0; index < submitted.Count; index++)
        {
            var source = submitted[index];
            var view = returned[index];
            if (source is null || source.Content is null ||
                source.Id != view.Id || source.Title != view.Title ||
                source.Content.Length != view.ContentCharacters ||
                !StringComparer.Ordinal.Equals(ContentHasher.HashUtf8(source.Content), view.ContentSha256) ||
                source.Uri != view.Uri || source.License != view.License ||
                source.RetrievedAtUtc != view.RetrievedAtUtc)
            {
                throw InvalidResponse("the source manifest does not match the submitted source set");
            }
        }
    }

    private static VibeQuantRunStatusResponse ValidateStatus(
        VibeQuantRunStatusResponse response,
        Guid? expectedRunId)
    {
        if (response.RunId == Guid.Empty ||
            expectedRunId is { } expected && response.RunId != expected ||
            !IsCanonicalSha256(response.SpecSha256) ||
            response.CompletedRoleCount is < 0 or > 5 ||
            response.ReservedCredits < 0 || response.ChargedCredits < 0 ||
            response.FinalArtifactSha256 is not null && !IsCanonicalSha256(response.FinalArtifactSha256) ||
            response.CreatedAtUtc == default || response.UpdatedAtUtc < response.CreatedAtUtc)
        {
            throw InvalidResponse("the run status is inconsistent");
        }
        return response;
    }

    private static IReadOnlyList<VibeQuantRunStatusResponse> ValidateList(
        IReadOnlyList<VibeQuantRunStatusResponse> responses)
    {
        if (responses is null || responses.Count > 100)
        {
            throw InvalidResponse("the run list is outside the supported range");
        }
        var runIds = new HashSet<Guid>();
        foreach (var response in responses)
        {
            ValidateStatus(response, expectedRunId: null);
            if (!runIds.Add(response.RunId))
            {
                throw InvalidResponse("the run list contains a duplicate run ID");
            }
        }
        return responses;
    }

    private static VibeQuantArtifactResponse ValidateArtifact(
        VibeQuantArtifactResponse response,
        Guid expectedRunId,
        string expectedSha256)
    {
        var validRoleOutput = response.Output is not null &&
            response.StrategyArtifact is null &&
            response.Role == response.Output.Role &&
            response.Output.SchemaVersion == CoordinatorVersions.ArtifactSchema &&
            StringComparer.Ordinal.Equals(ContentHasher.HashJson(response.Output), expectedSha256);
        var validStrategyArtifact = response.Output is null &&
            response.StrategyArtifact is not null &&
            response.Role == CoordinatorRole.Synthesizer &&
            response.StrategyArtifact.RunId == expectedRunId &&
            StringComparer.Ordinal.Equals(ContentHasher.HashJson(response.StrategyArtifact), expectedSha256) &&
            IsValidStrategyArtifact(response.StrategyArtifact);
        if (response.RunId != expectedRunId ||
            !StringComparer.Ordinal.Equals(response.Sha256, expectedSha256) ||
            !(validRoleOutput || validStrategyArtifact))
        {
            throw InvalidResponse("the artifact failed run, role, or hash validation");
        }
        return response;
    }

    private static bool IsValidStrategyArtifact(CoordinatorStrategySourceArtifact artifact)
    {
        try
        {
            CoordinatorStrategyArtifactValidation.Validate(artifact);
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static bool IsValidBudget(VibeQuantBudgetView budget) =>
        budget.MaxRequests > 0 &&
        budget.MaxAttemptsPerRole > 0 &&
        budget.MaxPromptTokens > 0 &&
        budget.MaxOutputTokens > 0 &&
        budget.MaxOutputTokensPerRequest > 0 &&
        budget.MaxResponseBytes > 0 &&
        budget.MaxArtifactBytes > 0 &&
        budget.MaxElapsedSeconds > 0 &&
        budget.RequestTimeoutSeconds > 0;

    private static bool IsCanonicalSha256(string? value) =>
        value is { Length: 64 } &&
        value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static InvalidDataException InvalidResponse(string reason) =>
        new($"The server returned an invalid Vibe Quant response: {reason}.");

    private static Guid RequireRunId(Guid runId) =>
        runId == Guid.Empty ? throw new ArgumentException("Run ID must not be empty.", nameof(runId)) : runId;

    private static string RequireSha256(string value)
    {
        if (value is not { Length: 64 } || !value.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("A 64-character SHA-256 value is required.", nameof(value));
        }
        return value.ToLowerInvariant();
    }

    private static void ValidateIdempotencyKey(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 100 || value.Any(character => character is < '!' or > '~'))
        {
            throw new ArgumentException(
                "Idempotency key must contain 1 to 100 printable ASCII characters without spaces.",
                nameof(value));
        }
    }
}

public sealed class VibeQuantApiException : Exception
{
    public VibeQuantApiException(HttpStatusCode statusCode, string message, Exception? innerException = null)
        : base(message, innerException) => StatusCode = statusCode;

    public HttpStatusCode StatusCode { get; }
}
