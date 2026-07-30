using DaxAlgo.Platform.Features.Profiles;

namespace DaxAlgo.Platform.Features.Marketplace;

public static class MarketplaceExecutionClasses
{
    public const string RestrictedOnly = "restricted_only";

    public const string ServerSignal = "server_signal";

    public static string NormalizeRequested(string? value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? RestrictedOnly : value.Trim();
        return normalized switch
        {
            RestrictedOnly => RestrictedOnly,
            ServerSignal => ServerSignal,
            _ => throw new PlatformValidationException(
                "execution_class must be restricted_only or server_signal."),
        };
    }
}
