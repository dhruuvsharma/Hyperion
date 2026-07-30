using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace DaxAlgo.Platform.Providers;

public sealed class GoogleAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    GoogleManagedIdentityProvider identityProvider)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Google";
    public const string IdTokenHeader = "X-Google-Id-Token";
    private static readonly Action<ILogger, Exception?> LogValidationUnavailable =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(1, nameof(LogValidationUnavailable)),
            "Google identity validation could not complete.");

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization.FirstOrDefault();
        var headerToken = Request.Headers[IdTokenHeader].FirstOrDefault();
        if (authorization is null && headerToken is null)
        {
            return AuthenticateResult.NoResult();
        }

        if (authorization is not null && headerToken is not null)
        {
            return AuthenticateResult.Fail("Supply the Google ID token only once.");
        }

        string token;
        if (authorization is not null)
        {
            const string prefix = "Bearer ";
            if (!authorization.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail("A bearer Google ID token is required.");
            }

            token = authorization[prefix.Length..];
        }
        else
        {
            token = headerToken!;
        }

        if (string.IsNullOrWhiteSpace(token)
            || token.Any(char.IsWhiteSpace)
            || token.Contains(',', StringComparison.Ordinal))
        {
            return AuthenticateResult.Fail("The Google ID token transport is invalid.");
        }

        try
        {
            var managedIdentity = await identityProvider.ValidateAsync(token, Context.RequestAborted);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, managedIdentity.Subject),
                new Claim(ClaimTypes.Email, managedIdentity.Email),
                new Claim(ClaimTypes.Name, managedIdentity.DisplayName),
                new Claim(GoogleManagedIdentityProvider.ValidatedIdentityClaim, bool.TrueString),
            };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
            return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
        }
        catch (UnauthorizedAccessException)
        {
            return AuthenticateResult.Fail("The Google ID token is invalid.");
        }
        catch (Exception exception) when (exception is HttpRequestException
            or IOException
            or CryptographicException)
        {
            LogValidationUnavailable(Logger, exception);
            return AuthenticateResult.Fail("Google identity validation could not complete.");
        }
        catch (OperationCanceledException exception)
            when (!Context.RequestAborted.IsCancellationRequested)
        {
            LogValidationUnavailable(Logger, exception);
            return AuthenticateResult.Fail("Google identity validation could not complete.");
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.ContentType = "application/problem+json";
        Response.Headers.WWWAuthenticate = "Bearer";
        Response.Headers.CacheControl = "no-store";
        await JsonSerializer.SerializeAsync(
            Response.Body,
            new ProblemDetails
            {
                Status = StatusCodes.Status401Unauthorized,
                Title = "Unauthorized",
                Detail = "A valid Google ID token is required.",
                Instance = Request.Path,
            },
            cancellationToken: Context.RequestAborted);
    }
}
