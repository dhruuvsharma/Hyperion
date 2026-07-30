namespace DaxAlgo.Platform.Features.Billing;

public static class BillingEndpoints
{
    private const int MaximumWebhookBytes = 64 * 1024;

    public static IEndpointRouteBuilder MapBillingEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(
                "/api/v1/plans",
                (IPlanCatalog plans) => Results.Ok(plans.Plans))
            .WithTags("Plans")
            .WithName("GetPlans")
            .RequireAuthorization();

        endpoints.MapPost(
                "/api/v1/billing/webhooks",
                async (
                    HttpRequest request,
                    BillingWebhookProcessor processor,
                    CancellationToken cancellationToken) =>
                {
                    if (request.ContentLength > MaximumWebhookBytes)
                    {
                        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                    }

                    await using var payload = new MemoryStream();
                    var buffer = new byte[8192];
                    while (true)
                    {
                        var read = await request.Body.ReadAsync(buffer, cancellationToken);
                        if (read == 0)
                        {
                            break;
                        }

                        if (payload.Length + read > MaximumWebhookBytes)
                        {
                            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                        }

                        await payload.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                    }

                    var outcome = await processor.ProcessAsync(
                        payload.ToArray(),
                        request.Headers,
                        cancellationToken);
                    return Results.Ok(new BillingWebhookResponse(outcome));
                })
            .WithTags("Billing")
            .WithName("ProcessBillingWebhook")
            .AllowAnonymous();
        return endpoints;
    }
}

public sealed record BillingWebhookResponse(BillingWebhookOutcome Outcome);
