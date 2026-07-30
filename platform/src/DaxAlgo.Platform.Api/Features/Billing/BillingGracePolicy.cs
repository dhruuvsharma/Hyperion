using DaxAlgo.Platform.Configuration;

namespace DaxAlgo.Platform.Features.Billing;

public sealed class BillingGracePolicy
{
    public const int CurrentVersion = 1;

    public BillingGracePolicy(BillingGracePolicyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Version != CurrentVersion)
        {
            throw new InvalidOperationException(
                $"Billing:GracePolicy:Version must be {CurrentVersion}.");
        }

        if (options.PastDueGraceDays is < 0 or > 30)
        {
            throw new InvalidOperationException(
                "Billing:GracePolicy:PastDueGraceDays must be between 0 and 30.");
        }

        Version = options.Version;
        MaximumPastDueGrace = TimeSpan.FromDays(options.PastDueGraceDays);
    }

    public int Version { get; }

    public TimeSpan MaximumPastDueGrace { get; }

    public DateTimeOffset GetPastDueValidUntil(DateTimeOffset currentPeriodEnd) =>
        currentPeriodEnd.Add(MaximumPastDueGrace);
}
