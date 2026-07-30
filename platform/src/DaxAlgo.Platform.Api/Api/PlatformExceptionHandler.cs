using DaxAlgo.Platform.Features.Profiles;
using DaxAlgo.Platform.Providers;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace DaxAlgo.Platform.Api;

public sealed class PlatformExceptionHandler : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var status = exception switch
        {
            PlatformValidationException => StatusCodes.Status400BadRequest,
            BillingWebhookException => StatusCodes.Status400BadRequest,
            UnauthorizedAccessException => StatusCodes.Status401Unauthorized,
            PlatformForbiddenException => StatusCodes.Status403Forbidden,
            PlatformPaymentRequiredException => StatusCodes.Status402PaymentRequired,
            PlatformNotFoundException => StatusCodes.Status404NotFound,
            PlatformConflictException => StatusCodes.Status409Conflict,
            PlatformServiceUnavailableException => StatusCodes.Status503ServiceUnavailable,
            _ => 0,
        };
        if (status == 0)
        {
            return false;
        }

        httpContext.Response.StatusCode = status;
        await httpContext.Response.WriteAsJsonAsync(
            new ProblemDetails
            {
                Status = status,
                Title = GetTitle(status),
                Detail = exception.Message,
            },
            options: null,
            contentType: "application/problem+json",
            cancellationToken);
        return true;
    }

    private static string GetTitle(int status) => status switch
    {
        StatusCodes.Status400BadRequest => "Bad Request",
        StatusCodes.Status401Unauthorized => "Unauthorized",
        StatusCodes.Status403Forbidden => "Forbidden",
        StatusCodes.Status402PaymentRequired => "Payment Required",
        StatusCodes.Status404NotFound => "Not Found",
        StatusCodes.Status409Conflict => "Conflict",
        _ => "Request failed",
    };
}
