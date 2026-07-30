using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DaxAlgo.Platform.Domain;

namespace DaxAlgo.Platform.Features.Marketplace;

public sealed record MarketplaceAttestationSignature(string KeyId, byte[] Signature);

public interface IMarketplaceAttestationSigner
{
    ValueTask<MarketplaceAttestationSignature> SignAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);
}

public sealed class DisabledMarketplaceAttestationSigner : IMarketplaceAttestationSigner
{
    public ValueTask<MarketplaceAttestationSignature> SignAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        throw new InvalidOperationException(
            "A production marketplace-attestation KMS signer is not configured.");
    }
}

public sealed class DevelopmentMarketplaceAttestationSigner :
    IMarketplaceAttestationSigner,
    IDisposable
{
    private readonly Lock signingLock = new();
    private readonly ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly string keyId;

    public DevelopmentMarketplaceAttestationSigner()
    {
        var key = signingKey.ExportSubjectPublicKeyInfo();
        keyId = "development-marketplace-attestation-"
            + Convert.ToHexStringLower(SHA256.HashData(key))[..16];
    }

    public ValueTask<MarketplaceAttestationSignature> SignAsync(
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (payload.IsEmpty)
        {
            throw new ArgumentException("A DSSE pre-authentication encoding is required.", nameof(payload));
        }

        byte[] signature;
        lock (signingLock)
        {
            signature = signingKey.SignData(
                payload.Span,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return ValueTask.FromResult(new MarketplaceAttestationSignature(keyId, signature));
    }

    public void Dispose()
    {
        signingKey.Dispose();
        GC.SuppressFinalize(this);
    }
}

public sealed class MarketplaceAttestationService(
    IMarketplaceAttestationSigner signer,
    TimeProvider timeProvider)
{
    public const string PayloadType = "application/vnd.in-toto+json";
    public const string PredicateType = "https://daxalgo.com/attestations/marketplace-review/v1";

    public async ValueTask<byte[]> CreateAsync(
        MarketplaceSubmission submission,
        MarketplaceStrategyRelease release,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(submission);
        ArgumentNullException.ThrowIfNull(release);
        if (submission.Status != SubmissionStatus.AwaitingReview
            || release.Status != MarketplaceReleaseStatus.Quarantined)
        {
            throw new InvalidOperationException("Only a fully reviewed quarantined release can be attested.");
        }

        var payload = WritePayload(submission, release, timeProvider.GetUtcNow());
        var signature = await signer.SignAsync(
            WritePreAuthenticationEncoding(PayloadType, payload),
            cancellationToken);
        return WriteEnvelope(payload, signature);
    }

    private static byte[] WritePayload(
        MarketplaceSubmission submission,
        MarketplaceStrategyRelease release,
        DateTimeOffset issuedAt)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("_type", "https://in-toto.io/Statement/v1");
            writer.WriteStartArray("subject");
            writer.WriteStartObject();
            writer.WriteString("name", $"{submission.Slug}/{submission.Version}.daxq");
            writer.WriteStartObject("digest");
            writer.WriteString("sha256", release.ArtifactSha256);
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteString("predicateType", PredicateType);
            writer.WriteStartObject("predicate");
            writer.WriteString("submissionId", submission.Id);
            writer.WriteString("releaseId", release.Id);
            writer.WriteString("publisherAccountId", submission.PublisherAccountId);
            writer.WriteString("sourceSha256", release.SourceSha256);
            writer.WriteString("policyVersion", submission.BuildPolicyVersion);
            writer.WriteString("executionClass", release.ExecutionClass);
            writer.WriteString("diversificationSeedSha256", release.DiversificationSeedSha256);
            writer.WriteString("parityStatisticsSha256", release.ParityStatisticsSha256);
            writer.WriteString("listingMetricsSha256", release.ListingMetricsSha256);
            writer.WriteString("sbomSha256", release.SbomSha256);
            writer.WriteBoolean("sourceReviewed", submission.SourceReview == MarketplaceHumanReviewState.Passed);
            writer.WriteBoolean(
                "declaredBehaviorReviewed",
                submission.DeclaredBehaviorReview == MarketplaceHumanReviewState.Passed);
            writer.WriteBoolean("diffReviewed", submission.DiffReview == MarketplaceHumanReviewState.Passed);
            writer.WriteString("issuedAt", issuedAt);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    private static byte[] WritePreAuthenticationEncoding(string payloadType, byte[] payload)
    {
        var typeBytes = Encoding.UTF8.GetBytes(payloadType);
        var prefix = Encoding.ASCII.GetBytes(
            $"DSSEv1 {typeBytes.Length} {payloadType} {payload.Length} ");
        return [.. prefix, .. payload];
    }

    private static byte[] WriteEnvelope(
        byte[] payload,
        MarketplaceAttestationSignature signature)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("payloadType", PayloadType);
            writer.WriteString("payload", Convert.ToBase64String(payload));
            writer.WriteStartArray("signatures");
            writer.WriteStartObject();
            writer.WriteString("keyid", signature.KeyId);
            writer.WriteString("sig", Convert.ToBase64String(signature.Signature));
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }
}
