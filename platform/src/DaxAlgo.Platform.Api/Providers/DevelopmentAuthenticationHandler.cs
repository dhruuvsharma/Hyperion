using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace DaxAlgo.Platform.Providers;

public sealed class DevelopmentAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Development";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Dev-Subject", out var subject)
            || string.IsNullOrWhiteSpace(subject))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var subjectValue = subject.ToString();
        var email = Request.Headers["X-Dev-Email"].FirstOrDefault()
            ?? $"{subjectValue}@development.invalid";
        var displayName = Request.Headers["X-Dev-Name"].FirstOrDefault() ?? subjectValue;

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, subjectValue),
            new(ClaimTypes.Email, email),
            new(ClaimTypes.Name, displayName),
        };

        foreach (var role in Request.Headers["X-Dev-Roles"]
                     .SelectMany(value => value?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                         ?? []))
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
