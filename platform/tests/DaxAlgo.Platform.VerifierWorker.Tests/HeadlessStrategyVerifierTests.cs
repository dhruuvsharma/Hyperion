using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace DaxAlgo.Platform.VerifierWorker.Tests;

public sealed class HeadlessStrategyVerifierTests
{
    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task ActualSdkStrategyCompilesAndReplaysDeterministically()
    {
        var source = StrategySource(
            """
            _tickCount++;
            if (_tickCount == 1)
            {
                _ = await router.PlaceOrderAsync(
                    new OrderRequest(
                        "order-1",
                        _contract,
                        OrderSide.Buy,
                        OrderType.Limit,
                        2,
                        LimitPrice: tick.Bid),
                    ct);
            }
            else
            {
                await router.CancelOrderAsync("order-1", ct);
            }
            """,
            "private int _tickCount;");
        var sourceBytes = Encoding.UTF8.GetBytes(source);

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.True(
            result.Accepted,
            Encoding.UTF8.GetString(HeadlessStrategyVerifier.SerializeResult(result)));
        Assert.True(result.Request.Valid);
        Assert.True(result.Source.HashMatched);
        Assert.True(result.Compile.Succeeded);
        Assert.True(result.Policy.SourcePassed);
        Assert.True(result.Policy.IlPassed);
        var caseResult = Assert.Single(result.Cases);
        Assert.True(caseResult.Succeeded);
        Assert.True(caseResult.Deterministic);
        Assert.Equal(caseResult.FirstTraceSha256, caseResult.SecondTraceSha256);
        Assert.Equal(caseResult.Trace, caseResult.SecondTrace);
        Assert.Collection(
            caseResult.Trace,
            place =>
            {
                Assert.Equal("place", place.Kind);
                Assert.Equal("order-1", place.ClientOrderId);
                Assert.Equal("AAPL", place.Contract?.Symbol);
                Assert.Equal("Buy", place.Side);
                Assert.Equal("Limit", place.Type);
                Assert.Equal(2, place.Quantity);
                Assert.Equal(100d, place.LimitPrice);
            },
            cancel =>
            {
                Assert.Equal("cancel", cancel.Kind);
                Assert.Equal("order-1", cancel.ClientOrderId);
                Assert.Null(cancel.Contract);
            });
    }

    [Fact]
    public async Task SyntaxFailureIsACompletedRejectedResult()
    {
        var sourceBytes = Encoding.UTF8.GetBytes("public sealed class Broken {");

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        Assert.True(result.Compile.Attempted);
        Assert.False(result.Compile.Succeeded);
        Assert.Contains(result.Compile.Diagnostics, item => item.Code.StartsWith("CS", StringComparison.Ordinal));
        Assert.Empty(result.Cases);
    }

    [Theory]
    [InlineData(
        "_ = System.IO.File.ReadAllText(\"probe\"); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = NativeProbe(); await Task.CompletedTask;",
        "[System.Runtime.InteropServices.DllImport(\"kernel32\")] private static extern int NativeProbe();")]
    [InlineData(
        "Counter++; await Task.CompletedTask;",
        "private static int Counter;")]
    [InlineData(
        "_ = DateTime.UtcNow; await Task.CompletedTask;",
        "")]
    [InlineData(
        "await Task.Run(() => { });",
        "")]
    [InlineData(
        "_ = new System.Net.Http.HttpClient(); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = System.Diagnostics.Process.GetCurrentProcess(); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = Environment.MachineName; await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = typeof(CandidateStrategy); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = System.Reflection.Assembly.Load(\"probe\"); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = System.Runtime.Loader.AssemblyLoadContext.Default; await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = new Random().Next(); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = Console.Out; await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = new Thread(() => { }); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = Task.FromResult(1).Result; await Task.CompletedTask;",
        "")]
    [InlineData(
        "Task.FromResult(1).Wait(); await Task.CompletedTask;",
        "")]
    [InlineData(
        "_ = new TaskCompletionSource<int>(); await Task.CompletedTask;",
        "")]
    public async Task ForbiddenApisAndStaticStateAreRejectedByPolicy(
        string body,
        string extraMember)
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(body, extraMember));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        Assert.False(result.Policy.SourcePassed);
        Assert.NotEmpty(result.Policy.Diagnostics);
        Assert.Empty(result.Cases);
    }

    [Theory]
    [InlineData(
        "_ = TradingTerminal.Core.Backtest.MonteCarlo.Run(new double[] { -1d, 1d }, 100d, 100); await Task.CompletedTask;")]
    [InlineData(
        "_ = _contract.Symbol.GetHashCode(); await Task.CompletedTask;")]
    public async Task TrustedWrapperAndHashNondeterminismAreRejectedByBothPolicies(string body)
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(body));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.False(result.Accepted);
        Assert.False(result.Policy.SourcePassed);
        Assert.False(result.Policy.IlPassed);
        Assert.Empty(result.Cases);
        Assert.Contains(result.Policy.Diagnostics, item => item.Code == "DAXV2120");
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Code is "DAXV2202" or "DAXV2203");
    }

    [Theory]
    [InlineData(
        "Task.CompletedTask.GetAwaiter().OnCompleted(() => { }); await Task.CompletedTask;",
        "")]
    [InlineData(
        "using var registration = ct.Register(() => { }); await Task.CompletedTask;",
        "")]
    [InlineData(
        "var progress = new Progress<int>(_ => { }); ((IProgress<int>)progress).Report(1); await Task.CompletedTask;",
        "")]
    [InlineData(
        "Escape(); await Task.CompletedTask;",
        "private async void Escape() { await Task.CompletedTask; }")]
    [InlineData(
        "await Task.CompletedTask;",
        "~CandidateStrategy() { }")]
    [InlineData(
        "await Task.CompletedTask;",
        "[System.Runtime.CompilerServices.ModuleInitializer] internal static void InitializeModule() { }")]
    public async Task DeferredExecutionAndFinalizationEscapesAreRejectedByBothPolicies(
        string body,
        string extraMember)
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(body, extraMember));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Compile.Succeeded);
        Assert.False(result.Accepted);
        Assert.False(result.Policy.SourcePassed);
        Assert.False(result.Policy.IlPassed);
        Assert.Empty(result.Cases);
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Stage == "source-policy");
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Stage == "il-policy");
    }

    [Fact]
    public async Task GenericTaskResultIsRejectedBySourceAndDecodedIlPolicies()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            "_ = Task.FromResult(1).Result; await Task.CompletedTask;"));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.False(result.Accepted);
        Assert.False(result.Policy.SourcePassed);
        Assert.False(result.Policy.IlPassed);
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Stage == "source-policy" && item.Code == "DAXV2120");
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Stage == "il-policy"
                && item.Code == "DAXV2203"
                && item.Message.Contains("Task`1.get_Result", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("constructor")]
    [InlineData("static-initializer")]
    [InlineData("exception-message")]
    public async Task UnboundedCandidateHooksBecomeCompletedReplayTimeouts(string scenario)
    {
        var source = scenario switch
        {
            "constructor" => StrategySource(
                "await Task.CompletedTask;",
                constructorBody: "while (true) { }"),
            "static-initializer" => StrategySource(
                "await Task.CompletedTask;",
                extraMember: "static CandidateStrategy() { while (true) { } }"),
            "exception-message" => StrategySource(
                "throw new HangingMessageException();",
                extraMember:
                "private sealed class HangingMessageException : Exception "
                + "{ public override string Message { get { while (true) { } } } }"),
            _ => throw new InvalidOperationException("Unknown adversarial scenario."),
        };
        var sourceBytes = Encoding.UTF8.GetBytes(source);

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        var caseResult = Assert.Single(result.Cases);
        Assert.False(caseResult.Succeeded);
        Assert.True(caseResult.Deterministic);
        Assert.Equal("replay-timeout", caseResult.FirstError?.Code);
        Assert.Equal("replay-timeout", caseResult.SecondError?.Code);
        Assert.Equal(caseResult.FirstTraceSha256, caseResult.SecondTraceSha256);
    }

    [Fact]
    public async Task CandidateProcessCrashBecomesACompletedNegativeResult()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            "_ = Recurse(0); await Task.CompletedTask;",
            "private int Recurse(int value) => Recurse(value + 1) + 1;"));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        var caseResult = Assert.Single(result.Cases);
        Assert.False(caseResult.Succeeded);
        Assert.NotNull(caseResult.FirstError);
        Assert.NotNull(caseResult.SecondError);
        Assert.StartsWith("replay-", caseResult.FirstError.Code, StringComparison.Ordinal);
        Assert.StartsWith("replay-", caseResult.SecondError.Code, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReplayWorkspaceCleanupRetriesAReleasedSharingViolation()
    {
        var work = Directory.CreateTempSubdirectory("daxalgo-verifier-cleanup-test-");
        var sentinelPath = Path.Combine(work.FullName, "sentinel.bin");
        FileStream? held = null;
        try
        {
            held = new FileStream(
                sentinelPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None);
            var retryCount = 0;

            await CandidateReplayProcess.DeleteWorkDirectoryAsync(
                work.FullName,
                _ =>
                {
                    retryCount++;
                    held.Dispose();
                    held = null;
                    return Task.CompletedTask;
                },
                maximumAttempts: 3);

            Assert.Equal(1, retryCount);
            Assert.False(Directory.Exists(work.FullName));
        }
        finally
        {
            held?.Dispose();
            if (Directory.Exists(work.FullName))
            {
                Directory.Delete(work.FullName, recursive: true);
            }
        }
    }

    [Fact]
    public async Task ReplayWorkspaceCleanupFailsClosedWhenLockPersists()
    {
        var work = Directory.CreateTempSubdirectory("daxalgo-verifier-cleanup-test-");
        var sentinelPath = Path.Combine(work.FullName, "sentinel.bin");
        try
        {
            using (new FileStream(
                       sentinelPath,
                       FileMode.CreateNew,
                       FileAccess.ReadWrite,
                       FileShare.None))
            {
                var retryCount = 0;
                await Assert.ThrowsAsync<IOException>(() =>
                    CandidateReplayProcess.DeleteWorkDirectoryAsync(
                        work.FullName,
                        _ =>
                        {
                            retryCount++;
                            return Task.CompletedTask;
                        },
                        maximumAttempts: 3));

                Assert.Equal(2, retryCount);
                Assert.True(Directory.Exists(work.FullName));
            }
        }
        finally
        {
            if (Directory.Exists(work.FullName))
            {
                Directory.Delete(work.FullName, recursive: true);
            }
        }
    }

    [Fact]
    public async Task ReplayResourceCleanupTerminatesStartedProcessBeforeDeletingWorkspace()
    {
        var work = Directory.CreateTempSubdirectory("daxalgo-verifier-cleanup-test-");
        Process? process = null;
        try
        {
            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.SystemDirectory, "ping.exe"),
                    WorkingDirectory = work.FullName,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };
            process.StartInfo.ArgumentList.Add("-n");
            process.StartInfo.ArgumentList.Add("30");
            process.StartInfo.ArgumentList.Add("127.0.0.1");
            Assert.True(process.Start());

            var cleanupException = await CandidateReplayProcess.CleanupReplayResourcesAsync(
                process,
                processStarted: true,
                work.FullName,
                static delay => Task.Delay(delay),
                maximumAttempts: 21);
            process = null;

            Assert.Null(cleanupException);
            Assert.False(Directory.Exists(work.FullName));
        }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        await process.WaitForExitAsync();
                    }
                }
                finally
                {
                    process.Dispose();
                }
            }

            if (Directory.Exists(work.FullName))
            {
                Directory.Delete(work.FullName, recursive: true);
            }
        }
    }

    [Fact]
    public void ReplayCleanupPreservesPrimaryAndCleanupFailures()
    {
        var primary = new InvalidOperationException("primary-lifecycle-failure");
        var cleanup = new IOException("cleanup-failure");

        var exception = Assert.Throws<AggregateException>(() =>
            CandidateReplayProcess.ThrowCleanupFailure(primary, cleanup));

        Assert.Collection(
            exception.InnerExceptions,
            item => Assert.Same(primary, item),
            item => Assert.Same(cleanup, item));
    }

    [Fact]
    public async Task CoreApisOutsideTheClosedStrategyProfileAreRejected()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            """
            if (++_tickCount == 1)
            {
                TradingTerminal.Core.Strategies.PluginFaultEvents.Report(
                    new InvalidOperationException("fresh-process-probe"));
            }
            await Task.CompletedTask;
            """,
            extraMember: "private int _reportedCount; private int _tickCount;",
            onStartBody:
                "TradingTerminal.Core.Strategies.PluginFaultEvents.Reported += _ => "
                + "{ _reportedCount++; if (_reportedCount > 1) { while (true) { } } }; "
                + "return Task.CompletedTask;"));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.False(result.Accepted);
        Assert.False(result.Policy.SourcePassed);
        Assert.False(result.Policy.IlPassed);
        Assert.Empty(result.Cases);
        Assert.Contains(result.Policy.Diagnostics, item => item.Code == "DAXV2120");
        Assert.Contains(
            result.Policy.Diagnostics,
            item => item.Code is "DAXV2202" or "DAXV2203");
    }

    [Fact]
    public async Task RuntimeThrowIsRecordedForBothFreshExecutions()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            "throw new InvalidOperationException(\"deliberate\");"));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        var caseResult = Assert.Single(result.Cases);
        Assert.False(caseResult.Succeeded);
        Assert.True(caseResult.Deterministic);
        Assert.Equal("candidate-exception", caseResult.FirstError?.Code);
        Assert.Equal("candidate-exception", caseResult.SecondError?.Code);
        Assert.Equal(caseResult.FirstTraceSha256, caseResult.SecondTraceSha256);
        Assert.Equal(caseResult.Trace, caseResult.SecondTrace);
    }

    [Fact]
    public async Task PolicyRejectsAnUnstableIdentityHashTrace()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            """
            var quantity = (long)(uint)new object().GetHashCode() + 1;
            _ = await router.PlaceOrderAsync(
                new OrderRequest(
                    "unstable",
                    _contract,
                    OrderSide.Buy,
                    OrderType.Market,
                    quantity),
                ct);
            """));

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.False(result.Accepted);
        Assert.Empty(result.Cases);
        Assert.False(result.Policy.SourcePassed);
        Assert.False(result.Policy.IlPassed);
        Assert.Contains(result.Policy.Diagnostics, item => item.Code == "DAXV2120");
        Assert.Contains(result.Policy.Diagnostics, item => item.Code == "DAXV2203");
    }

    [Fact]
    public async Task OneByteSourceMismatchStopsBeforeCompilation()
    {
        var declaredSource = Encoding.UTF8.GetBytes(StrategySource("await Task.CompletedTask;"));
        var suppliedSource = declaredSource.ToArray();
        suppliedSource[^1] = suppliedSource[^1] == (byte)'\n' ? (byte)' ' : (byte)'\n';

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(declaredSource),
            suppliedSource);

        Assert.True(result.Completed);
        Assert.False(result.Accepted);
        Assert.False(result.Request.Valid);
        Assert.False(result.Source.HashMatched);
        Assert.False(result.Compile.Attempted);
        Assert.Contains(result.Request.Diagnostics, item => item.Code == "DAXV1103");
    }

    [Fact]
    public async Task DuplicateUnknownAndOutOfBoundRequestsAreRejectedStrictly()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource("await Task.CompletedTask;"));
        var validJson = Encoding.UTF8.GetString(CreateRequest(sourceBytes));
        var duplicate = Encoding.UTF8.GetBytes(validJson.Replace(
            "\"profile\":",
            "\"profile\":\"daxalgo-sdk-headless-source/v1\",\"profile\":",
            StringComparison.Ordinal));
        var unknown = Encoding.UTF8.GetBytes(validJson.Replace(
            "\"requestId\":",
            "\"unknown\":true,\"requestId\":",
            StringComparison.Ordinal));
        var tooManyCases = CreateRequest(sourceBytes, caseCount: 9);

        foreach (var requestBytes in new[] { duplicate, unknown, tooManyCases })
        {
            var result = await HeadlessStrategyVerifier.VerifyAsync(requestBytes, sourceBytes);
            Assert.False(result.Request.Valid);
            Assert.False(result.Accepted);
            Assert.False(result.Compile.Attempted);
            Assert.NotEmpty(result.Request.Diagnostics);
        }
    }

    [Fact]
    public async Task BomNulAndInvalidUtf8InputsAreRejected()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource("await Task.CompletedTask;"));
        var validRequest = CreateRequest(sourceBytes);
        var requestWithBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(validRequest).ToArray();
        var requestWithNul = validRequest.Concat(new byte[] { 0 }).ToArray();
        var sourceWithBom = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(sourceBytes).ToArray();
        var invalidSource = sourceBytes.Concat(new byte[] { 0xC3, 0x28 }).ToArray();

        var bomRequestResult = await HeadlessStrategyVerifier.VerifyAsync(requestWithBom, sourceBytes);
        var nulRequestResult = await HeadlessStrategyVerifier.VerifyAsync(requestWithNul, sourceBytes);
        var bomSourceResult = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceWithBom),
            sourceWithBom);
        var invalidSourceResult = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(invalidSource),
            invalidSource);

        Assert.False(bomRequestResult.Request.Valid);
        Assert.False(nulRequestResult.Request.Valid);
        Assert.False(bomSourceResult.Source.EncodingValid);
        Assert.False(invalidSourceResult.Source.EncodingValid);
    }

    [Fact]
    public async Task DiagnosticsAreSortedAndBounded()
    {
        var source = string.Join('\n', Enumerable.Repeat("???", 400));
        var sourceBytes = Encoding.UTF8.GetBytes(source);

        var result = await HeadlessStrategyVerifier.VerifyAsync(
            CreateRequest(sourceBytes),
            sourceBytes);

        Assert.False(result.Accepted);
        Assert.True(result.Compile.Diagnostics.Length <= HeadlessStrategyVerifier.MaximumDiagnostics);
        Assert.True(result.Compile.DiagnosticsTruncated);
        var sorted = result.Compile.Diagnostics
            .OrderBy(item => item.Stage, StringComparer.Ordinal)
            .ThenBy(item => item.Code, StringComparer.Ordinal)
            .ThenBy(item => item.Severity, StringComparer.Ordinal)
            .ThenBy(item => item.Line)
            .ThenBy(item => item.Column)
            .ThenBy(item => item.Message, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(sorted, result.Compile.Diagnostics);
    }

    [Fact]
    public async Task CompilerClosureAssemblyAndTraceHashesAreStable()
    {
        var sourceBytes = Encoding.UTF8.GetBytes(StrategySource(
            "_ = await router.PlaceOrderAsync(new OrderRequest(\"stable\", _contract, OrderSide.Sell, OrderType.Market, 1), ct);"));
        var requestBytes = CreateRequest(sourceBytes);

        var first = await HeadlessStrategyVerifier.VerifyAsync(requestBytes, sourceBytes);
        var second = await HeadlessStrategyVerifier.VerifyAsync(requestBytes, sourceBytes);

        Assert.True(
            first.Accepted,
            Encoding.UTF8.GetString(HeadlessStrategyVerifier.SerializeResult(first)));
        Assert.True(
            second.Accepted,
            Encoding.UTF8.GetString(HeadlessStrategyVerifier.SerializeResult(second)));
        Assert.Equal(first.Request.Sha256, second.Request.Sha256);
        Assert.Equal(first.Source.Sha256, second.Source.Sha256);
        Assert.Equal(first.Toolchain.CompilerClosureSha256, second.Toolchain.CompilerClosureSha256);
        Assert.Equal(first.Compile.AssemblySha256, second.Compile.AssemblySha256);
        Assert.Equal(first.Cases[0].FirstTraceSha256, second.Cases[0].FirstTraceSha256);
        Assert.Equal(
            HeadlessStrategyVerifier.SerializeResult(first),
            HeadlessStrategyVerifier.SerializeResult(second));
        var json = HeadlessStrategyVerifier.SerializeResult(first);
        Assert.False(json.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
        using var document = JsonDocument.Parse(json);
        Assert.Equal(HeadlessStrategyVerifier.ResultSchema, document.RootElement.GetProperty("schemaVersion").GetString());
    }

    [Fact]
    public async Task StageModeWritesExactNoClobberSnapshotsWithoutStdout()
    {
        var work = Directory.CreateTempSubdirectory("daxalgo-verifier-stage-test-");
        try
        {
            var requestBytes = Encoding.UTF8.GetBytes("{\"request\":1}");
            var sourceBytes = Encoding.UTF8.GetBytes("source-one");
            var first = await RunWorkerAsync(
                ["stage", "--work", work.FullName],
                CreateStagingFrame(requestBytes, sourceBytes));

            Assert.Equal(0, first.ExitCode);
            Assert.Empty(first.Stdout);
            Assert.Empty(first.Stderr);
            Assert.Equal(requestBytes, await File.ReadAllBytesAsync(Path.Combine(work.FullName, "request.json")));
            Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(Path.Combine(work.FullName, "source.cs")));

            var second = await RunWorkerAsync(
                ["stage", "--work", work.FullName],
                CreateStagingFrame(
                    Encoding.UTF8.GetBytes("{\"request\":2}"),
                    Encoding.UTF8.GetBytes("source-two")));

            Assert.NotEqual(0, second.ExitCode);
            Assert.Empty(second.Stdout);
            Assert.Equal(requestBytes, await File.ReadAllBytesAsync(Path.Combine(work.FullName, "request.json")));
            Assert.Equal(sourceBytes, await File.ReadAllBytesAsync(Path.Combine(work.FullName, "source.cs")));
        }
        finally
        {
            Directory.Delete(work.FullName, recursive: true);
        }
    }

    [Fact]
    public async Task StageModeRejectsBadMagicBoundsTruncationAndTrailingBytes()
    {
        var valid = CreateStagingFrame(
            Encoding.UTF8.GetBytes("{}"),
            Encoding.UTF8.GetBytes("source"));
        var badMagic = valid.ToArray();
        badMagic[0] ^= 0xFF;
        var oversized = CreateStagingHeader(
            HeadlessStrategyVerifier.MaximumRequestBytes + 1u,
            1);
        var truncated = valid[..^1];
        var trailing = valid.Concat(new byte[] { 0x00 }).ToArray();

        foreach (var frame in new[] { badMagic, oversized, truncated, trailing })
        {
            var work = Directory.CreateTempSubdirectory("daxalgo-verifier-stage-invalid-");
            try
            {
                var result = await RunWorkerAsync(
                    ["stage", "--work", work.FullName],
                    frame);

                Assert.NotEqual(0, result.ExitCode);
                Assert.Empty(result.Stdout);
                Assert.False(File.Exists(Path.Combine(work.FullName, "request.json")));
                Assert.False(File.Exists(Path.Combine(work.FullName, "source.cs")));
            }
            finally
            {
                Directory.Delete(work.FullName, recursive: true);
            }
        }
    }

    [Fact]
    public async Task VerifyStdoutReturnsOnlyExactBoundedWorkerJson()
    {
        var work = Directory.CreateTempSubdirectory("daxalgo-verifier-stdout-test-");
        try
        {
            var sourceBytes = Encoding.UTF8.GetBytes(StrategySource("await Task.CompletedTask;"));
            var requestBytes = CreateRequest(sourceBytes);
            var staged = await RunWorkerAsync(
                ["stage", "--work", work.FullName],
                CreateStagingFrame(requestBytes, sourceBytes));
            Assert.Equal(0, staged.ExitCode);
            Assert.Empty(staged.Stdout);

            var verified = await RunWorkerAsync(
                [
                    "verify-stdout",
                    "--request", Path.Combine(work.FullName, "request.json"),
                    "--source", Path.Combine(work.FullName, "source.cs"),
                ],
                stdin: []);

            Assert.Equal(0, verified.ExitCode);
            Assert.Empty(verified.Stderr);
            Assert.InRange(
                verified.Stdout.Length,
                1,
                HeadlessStrategyVerifier.MaximumResultBytes);
            Assert.False(verified.Stdout.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }));
            var result = JsonSerializer.Deserialize<HeadlessVerifierResult>(
                verified.Stdout,
                WebJson);
            Assert.NotNull(result);
            Assert.True(result.Accepted);
            Assert.Equal(verified.Stdout, HeadlessStrategyVerifier.SerializeResult(result));
        }
        finally
        {
            Directory.Delete(work.FullName, recursive: true);
        }
    }

    private static byte[] CreateRequest(byte[] sourceBytes, int caseCount = 1)
    {
        var sourceSha256 = Convert.ToHexString(SHA256.HashData(sourceBytes)).ToLowerInvariant();
        var cases = Enumerable.Range(1, caseCount)
            .Select(index => new
            {
                caseId = $"case-{index}",
                startUtc = "2026-01-02T03:04:05Z",
                ticks = new[]
                {
                    new
                    {
                        offsetMilliseconds = 0,
                        bid = 100d,
                        ask = 100.25d,
                        bidSize = 10L,
                        askSize = 12L,
                    },
                    new
                    {
                        offsetMilliseconds = 1000,
                        bid = 100.5d,
                        ask = 100.75d,
                        bidSize = 11L,
                        askSize = 13L,
                    },
                },
            })
            .ToArray();
        return JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = "daxalgo.verifier.headless-strategy-request/v1",
            profile = "daxalgo-sdk-headless-source/v1",
            requestId = "request-1",
            sourceSha256,
            contract = new
            {
                symbol = "AAPL",
                secType = "STK",
                exchange = "SMART",
                currency = "USD",
                primaryExchange = "NASDAQ",
            },
            cases,
        });
    }

    private static byte[] CreateStagingFrame(byte[] requestBytes, byte[] sourceBytes)
    {
        var header = CreateStagingHeader(
            checked((uint)requestBytes.Length),
            checked((uint)sourceBytes.Length));
        return header.Concat(requestBytes).Concat(sourceBytes).ToArray();
    }

    private static byte[] CreateStagingHeader(uint requestLength, uint sourceLength)
    {
        var header = new byte[16];
        "DAXVSTG1"u8.CopyTo(header);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(8, 4), requestLength);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(12, 4), sourceLength);
        return header;
    }

    private static async Task<WorkerInvocation> RunWorkerAsync(
        string[] arguments,
        byte[] stdin)
    {
        var appHostName = OperatingSystem.IsWindows()
            ? "DaxAlgo.Platform.VerifierWorker.exe"
            : "DaxAlgo.Platform.VerifierWorker";
        var startInfo = new ProcessStartInfo
        {
            FileName = Path.Combine(AppContext.BaseDirectory, appHostName),
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        Assert.True(process.Start());
        var stdoutTask = ReadAllBytesAsync(process.StandardOutput.BaseStream);
        var stderrTask = ReadAllBytesAsync(process.StandardError.BaseStream);
        await process.StandardInput.BaseStream.WriteAsync(stdin);
        process.StandardInput.Close();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        return new(
            process.ExitCode,
            await stdoutTask,
            await stderrTask);
    }

    private static async Task<byte[]> ReadAllBytesAsync(Stream stream)
    {
        using var buffer = new MemoryStream();
        await stream.CopyToAsync(buffer);
        return buffer.ToArray();
    }

    private static string StrategySource(
        string onTickBody,
        string extraMember = "",
        string constructorBody = "",
        string onStartBody = "return Task.CompletedTask;") =>
        $$"""
        using System;
        using System.Threading;
        using System.Threading.Tasks;
        using DaxAlgo.Sdk;
        using TradingTerminal.Core.Backtest;
        using TradingTerminal.Core.Domain;
        using TradingTerminal.Core.Time;
        using TradingTerminal.Core.Trading;

        public sealed class CandidateStrategy : IBacktestStrategy
        {
            private readonly Contract _contract;
            {{extraMember}}

            public CandidateStrategy(Contract contract)
            {
                _contract = contract;
                if (SdkInfo.Version.Length == 0)
                {
                    throw new InvalidOperationException("SDK identity is unavailable.");
                }
                {{constructorBody}}
            }

            public Task OnStartAsync(IClock clock, IOrderRouter router, CancellationToken ct)
            {
                {{onStartBody}}
            }

            public async Task OnTickAsync(Tick tick, IClock clock, IOrderRouter router, CancellationToken ct)
            {
                {{onTickBody}}
            }

            public Task OnOrderEventAsync(OrderEvent evt, CancellationToken ct) =>
                Task.CompletedTask;

            public Task OnEndAsync(IClock clock, IOrderRouter router, CancellationToken ct) =>
                Task.CompletedTask;
        }
        """;

    private sealed record WorkerInvocation(
        int ExitCode,
        byte[] Stdout,
        byte[] Stderr);
}
