using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using TradingTerminal.Ai.Coordinator.Client;
using TradingTerminal.Ai.Coordinator.Contracts;
using TradingTerminal.Ai.Coordinator.Security;
using TradingTerminal.Core.Strategies.Authoring;

namespace TradingTerminal.App.Authoring;

public sealed record HostedStrategySourceFileView(
    string RelativePath,
    string Content,
    string ContentSha256)
{
    public string ShortHash => ContentSha256[..12];
}

/// <summary>
/// Pro-only hosted authoring state machine. It deliberately stops at importing released inert source
/// into the existing editor. Compilation, review, registration, and any execution remain behind the
/// editor's separate local consent gate.
/// </summary>
public sealed partial class HostedStrategyAuthoringViewModel : ObservableObject, IDisposable
{
    private const int MaximumObjectiveCharacters = 20_000;
    private readonly IVibeQuantDesktopClientFactory _clientFactory;
    private readonly IHostedStrategyPollDelay _pollDelay;
    private readonly IHostedStrategyRunBookmarkStore _bookmarkStore;
    private readonly StrategyAuthoringViewModel _workspace;
    private readonly ILogger<HostedStrategyAuthoringViewModel> _logger;
    private readonly CancellationTokenSource _lifetime = new();
    private HostedStrategyRunBookmarkReadResult _bookmarkRead;
    private IVibeQuantApiClient? _client;
    private VibeQuantRunSpecResponse? _specification;
    private VibeQuantRunStatusResponse? _lastStatus;
    private CoordinatorStrategySourceArtifact? _artifact;
    private CoordinatorRoleOutput? _riskReview;
    private CancellationTokenSource? _monitor;
    private string? _connectionBinding;
    private string? _idempotencyKey;
    private string? _releasedArtifactSha256;
    private int _generation;
    private bool _hasRecoveryBarrier;
    private bool _isMonitoring;
    private bool _restoringBookmark;
    private bool _disposed;

    public HostedStrategyAuthoringViewModel(
        IVibeQuantDesktopClientFactory clientFactory,
        IHostedStrategyPollDelay pollDelay,
        IHostedStrategyRunBookmarkStore bookmarkStore,
        StrategyAuthoringViewModel workspace,
        ILogger<HostedStrategyAuthoringViewModel> logger)
    {
        _clientFactory = clientFactory;
        _pollDelay = pollDelay;
        _bookmarkStore = bookmarkStore;
        _workspace = workspace;
        _logger = logger;
        _workspace.PropertyChanged += OnWorkspacePropertyChanged;
        _bookmarkRead = bookmarkStore.Read() ?? new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable);
        _hasRecoveryBarrier = _bookmarkRead.State != HostedStrategyRunBookmarkReadState.Missing;

        var availability = clientFactory.GetAvailability();
        IsConfigured = availability.IsAvailable;
        ConfigurationMessage = availability.Message;
        _connectionBinding = availability.IsAvailable ? availability.ConnectionBinding : null;
        Message = _bookmarkRead.State == HostedStrategyRunBookmarkReadState.InvalidOrUnreadable
            ? "The hosted-run recovery bookmark is unreadable. New runs are blocked until it is explicitly discarded."
            : availability.Message;
    }

    public event EventHandler? CloseRequested;

    public ObservableCollection<HostedStrategySourceFileView> Files { get; } = [];

    public ObservableCollection<string> RiskReviewItems { get; } = [];

    [ObservableProperty] private HostedStrategySourceFileView? _selectedFile;
    [ObservableProperty] private string _objective = string.Empty;
    [ObservableProperty] private bool _isConfigured;
    [ObservableProperty] private string _configurationMessage = string.Empty;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _isCancelling;
    [ObservableProperty] private Guid? _runId;
    [ObservableProperty] private CoordinatorRunStatus? _runStatus;
    [ObservableProperty] private string? _specificationSha256;
    [ObservableProperty] private string? _previewedArtifactSha256;
    [ObservableProperty] private long _availableCredits;
    [ObservableProperty] private long _reservedCredits;
    [ObservableProperty] private long _consumedCredits;
    [ObservableProperty] private long _runReservedCredits;
    [ObservableProperty] private long _runChargedCredits;
    [ObservableProperty] private string? _creditPricingVersion;
    [ObservableProperty] private string _riskReviewSummary = "Risk review has not been loaded.";
    [ObservableProperty] private bool _isDiscardRecoveryArmed;
    [ObservableProperty] private string _recoveryDiscardConfirmation = string.Empty;
    [ObservableProperty] private string _message = string.Empty;

    public string RunStatusText => RunStatus?.ToString() ?? "Not submitted";

    public bool ReleaseConfirmed =>
        _releasedArtifactSha256 is not null &&
        StringComparer.Ordinal.Equals(_releasedArtifactSha256, PreviewedArtifactSha256);

    public bool IsObjectiveReadOnly => IsBusy || IsCancelling || RunId is not null;

    public string DiscardRecoveryText => IsDiscardRecoveryArmed
        ? "Confirm recovery discard"
        : "Discard blocked recovery...";

    public string CreditSummary => CreditPricingVersion is null
        ? "Credits not loaded"
        : $"{AvailableCredits:N0} available · {ReservedCredits:N0} reserved · {ConsumedCredits:N0} consumed";

    public string SpecificationSummary => _specification is null
        ? "Submit an objective to receive the immutable server specification and maximum charge."
        : $"{_specification.Spec.Provider.ModelId} - maximum {_specification.Spec.MaximumCreditCharge:N0} credits - " +
          $"spec {_specification.SpecSha256[..12]}";

    public string SpecificationDetails => _specification is null
        ? "No specification loaded."
        : FormatSpecification(_specification);

    public string RunCreditSummary => _specification is null
        ? "No run charge."
        : $"This run: {RunReservedCredits:N0} reserved, {RunChargedCredits:N0} charged; " +
          $"approved maximum {_specification.Spec.MaximumCreditCharge:N0}.";

    public string ArtifactSummary => _artifact is null || PreviewedArtifactSha256 is null
        ? "No source artifact has been previewed."
        : $"{_artifact.DisplayName} ({_artifact.StrategyId}) - {_artifact.Files.Count} file(s) - " +
          $"artifact {PreviewedArtifactSha256[..12]}";

    private bool CanInitialize() => !IsBusy && !IsCancelling;

    [RelayCommand(CanExecute = nameof(CanInitialize))]
    private async Task InitializeAsync() => await RunExclusiveAsync(async cancellationToken =>
    {
        RefreshAvailability();
        if (!IsConfigured) return;
        if (await ResumeBookmarkAsync(cancellationToken)) return;
        await RefreshCreditsCoreAsync(cancellationToken);
        Message = "Platform credits loaded. Submit creates a quote only; it does not start a run.";
    });

    private bool CanSubmit() =>
        IsConfigured && !IsBusy && !IsCancelling && !_hasRecoveryBarrier && RunId is null &&
        !string.IsNullOrWhiteSpace(Objective) && Objective.Length <= MaximumObjectiveCharacters;

    [RelayCommand(CanExecute = nameof(CanSubmit))]
    private async Task SubmitAsync() => await RunExclusiveAsync(async cancellationToken =>
    {
        var objective = Objective.Trim();
        if (objective.Length is < 1 or > MaximumObjectiveCharacters)
            throw new InvalidDataException($"Objective must contain 1 to {MaximumObjectiveCharacters:N0} characters.");

        RefreshAvailability();
        if (!IsConfigured) return;
        var client = GetClient();
        await RefreshCreditsCoreAsync(cancellationToken);
        Objective = objective;
        _idempotencyKey ??= $"terminal-strategy-{Guid.NewGuid():N}";
        CreateBookmarkRequired(new HostedStrategyRunBookmark(
            HostedStrategyRunBookmark.CurrentSchemaVersion,
            RequireConnectionBinding(),
            objective,
            _idempotencyKey,
            null,
            null,
            DateTimeOffset.UtcNow));

        var specification = await client.CreateRunAsync(
            new CreateVibeQuantRunRequest(objective, [], CoordinatorRunPurpose.StrategyAuthoring),
            _idempotencyKey,
            cancellationToken);

        LoadSpecification(specification, objective);
        SaveCurrentBookmarkRequired();
        RunStatus = CoordinatorRunStatus.AwaitingStartApproval;
        Message = AvailableCredits < specification.Spec.MaximumCreditCharge
            ? $"Quote created, but it can reserve up to {specification.Spec.MaximumCreditCharge:N0} credits and the current balance is lower."
            : $"Quote created. Review the server profile and explicitly approve up to {specification.Spec.MaximumCreditCharge:N0} credits.";
        RefreshComputed();
    });

    private bool CanStart() =>
        !IsBusy && !IsCancelling && _hasRecoveryBarrier && _specification is not null && RunId is not null &&
        RunStatus == CoordinatorRunStatus.AwaitingStartApproval;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private async Task StartAsync() => await RunExclusiveAsync(async cancellationToken =>
    {
        var specification = _specification ?? throw new InvalidOperationException("No hosted specification is loaded.");
        var runId = RunId ?? throw new InvalidOperationException("No hosted run is loaded.");
        SaveCurrentBookmarkRequired();
        var generation = ++_generation;
        _monitor?.Cancel();
        _monitor?.Dispose();
        _monitor = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);

        Message = $"Approving the exact specification and a maximum reservation of {specification.Spec.MaximumCreditCharge:N0} credits…";
        SetMonitoring(true);
        try
        {
            var status = await GetClient().StartAsync(
                runId,
                specification.SpecSha256,
                _monitor.Token);
            ApplyStatus(status);
            await TryRefreshCreditsAsync(_monitor.Token);
            await MonitorUntilReviewAsync(generation, _monitor.Token);
        }
        finally
        {
            SetMonitoring(false);
        }
    });

    private bool CanRefreshStatus() =>
        !IsBusy && !IsCancelling && RunId is not null && _specification is not null;

    [RelayCommand(CanExecute = nameof(CanRefreshStatus))]
    private async Task RefreshStatusAsync() => await RunExclusiveAsync(async cancellationToken =>
    {
        var runId = RunId ?? throw new InvalidOperationException("No hosted run is loaded.");
        var status = await GetClient().GetStatusAsync(runId, cancellationToken);
        ApplyStatus(status);
        if (status.Status is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed)
            await LoadPreviewAsync(status, cancellationToken);
        else
            Message = DescribeStatus(status);
        await TryRefreshCreditsAsync(cancellationToken);
        ClearBookmarkForTerminalStatus(status.Status);
    });

    private bool CanRelease() =>
        !IsBusy && !IsCancelling && RunId is not null &&
        RunStatus is (CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed) &&
        _artifact is not null && _riskReview is { Decision: CoordinatorDecision.Approve } &&
        PreviewedArtifactSha256 is not null && !ReleaseConfirmed;

    [RelayCommand(CanExecute = nameof(CanRelease))]
    private async Task ReleaseAsync() => await RunExclusiveAsync(async cancellationToken =>
    {
        var runId = RunId ?? throw new InvalidOperationException("No hosted run is loaded.");
        var previewHash = PreviewedArtifactSha256 ??
            throw new InvalidOperationException("Preview the exact source artifact before release.");
        var current = await GetClient().GetStatusAsync(runId, cancellationToken);
        ApplyStatus(current);
        if (current.Status is not (CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed) ||
            !StringComparer.Ordinal.Equals(current.FinalArtifactSha256, previewHash))
        {
            throw new InvalidDataException("The run no longer exposes the exact source artifact that was previewed.");
        }

        var completed = await GetClient().ReleaseAsync(runId, previewHash, cancellationToken);
        ApplyStatus(completed);
        if (completed.Status != CoordinatorRunStatus.Completed ||
            !StringComparer.Ordinal.Equals(completed.FinalArtifactSha256, previewHash))
        {
            throw new InvalidDataException("The release response did not complete the exact previewed artifact.");
        }

        SetReleasedArtifactSha256(previewHash);
        await TryRefreshCreditsAsync(cancellationToken);
        Message = "Exact source artifact released. Import copies inert source only; it does not compile or register it.";
    });

    private bool CanImport() =>
        !IsBusy && !IsCancelling && ReleaseConfirmed && RunStatus == CoordinatorRunStatus.Completed &&
        !_workspace.IsGenerating && _artifact is not null && PreviewedArtifactSha256 is not null &&
        StringComparer.Ordinal.Equals(_releasedArtifactSha256, PreviewedArtifactSha256);

    [RelayCommand(CanExecute = nameof(CanImport))]
    private void Import()
    {
        if (!CanImport()) return;
        var artifact = _artifact!;
        CoordinatorStrategyArtifactValidation.Validate(artifact);
        var hash = ContentHasher.HashJson(artifact);
        if (!StringComparer.Ordinal.Equals(hash, PreviewedArtifactSha256) ||
            !StringComparer.Ordinal.Equals(hash, _releasedArtifactSha256))
            throw new InvalidDataException("The source preview changed after release.");

        var script = new StrategyScript(
            artifact.StrategyId,
            artifact.DisplayName,
            [.. artifact.Files.Select(file => new StrategyFile(file.RelativePath, file.Content))]);
        var importedId = _workspace.ImportDraft(script);
        _workspace.Status =
            $"Imported released hosted source {hash[..12]} as '{importedId}'. Local edits are unbound; " +
            "Compile & Register still requires code review.";
        ClearRecoveryBookmark();
        Message = importedId == artifact.StrategyId
            ? "Released source imported into the local editor without compiling or registering it."
            : $"Released source imported as '{importedId}' without overwriting the existing '{artifact.StrategyId}' session.";
        CloseRequested?.Invoke(this, EventArgs.Empty);
    }

    private bool CanCancel() =>
        !IsCancelling && RunId is not null &&
        ((IsBusy && _isMonitoring && RunStatus is (CoordinatorRunStatus.AwaitingStartApproval or
             CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)) ||
         (!IsBusy && RunStatus is (CoordinatorRunStatus.AwaitingStartApproval or CoordinatorRunStatus.Ready or
             CoordinatorRunStatus.Running or CoordinatorRunStatus.AwaitingReleaseApproval)));

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private async Task CancelAsync()
    {
        if (!CanCancel()) return;
        var runId = RunId!.Value;
        ++_generation;
        _monitor?.Cancel();
        IsCancelling = true;
        try
        {
            var status = await GetClient().CancelAsync(runId, _lifetime.Token);
            ApplyStatus(status);
            await TryRefreshCreditsAsync(_lifetime.Token);
            ClearBookmarkForTerminalStatus(status.Status);
            Message = status.Status == CoordinatorRunStatus.Running
                ? "Cancellation requested. Refresh status until the worker acknowledges it."
                : DescribeStatus(status);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            ReportFailure("cancel", exception);
        }
        catch (OperationCanceledException) when (_disposed || _lifetime.IsCancellationRequested)
        {
        }
        finally
        {
            IsCancelling = false;
            RefreshCommands();
        }
    }

    [RelayCommand]
    private void Close() => CloseRequested?.Invoke(this, EventArgs.Empty);

    private bool CanDiscardRecovery() =>
        _hasRecoveryBarrier && !IsBusy && !IsCancelling &&
        (_bookmarkRead.State == HostedStrategyRunBookmarkReadState.InvalidOrUnreadable ||
         _bookmarkRead.Bookmark?.RunId is null ||
         (RunId is null && IsForeignConnectionRecovery())) &&
        (!IsDiscardRecoveryArmed || RecoveryDiscardConfirmation == "DISCARD");

    private bool IsForeignConnectionRecovery() =>
        IsConfigured && _connectionBinding is not null &&
        _bookmarkRead is
        {
            State: HostedStrategyRunBookmarkReadState.Valid,
            Bookmark: { } bookmark,
        } &&
        !StringComparer.Ordinal.Equals(bookmark.ConnectionBinding, _connectionBinding);

    [RelayCommand(CanExecute = nameof(CanDiscardRecovery))]
    private void DiscardRecovery()
    {
        if (!CanDiscardRecovery()) return;
        if (!IsDiscardRecoveryArmed)
        {
            IsDiscardRecoveryArmed = true;
            Message = IsForeignConnectionRecovery() && _bookmarkRead.Bookmark?.RunId is { } foreignRunId
                ? $"Warning: saved hosted run {foreignRunId:D} belongs to another loopback connection. " +
                  "Discarding this bookmark does not cancel that run or refund its credits. Restore the old " +
                  "connection and cancel first when possible; otherwise type DISCARD, then press Confirm."
                : "Warning: discarding recovery can orphan a server-side run and its settled or reserved credits. " +
                  "Type DISCARD, then press Confirm only if recovery is impossible.";
            return;
        }

        if (!_bookmarkStore.TryClear(_bookmarkRead))
        {
            _bookmarkRead = _bookmarkStore.Read();
            _hasRecoveryBarrier = _bookmarkRead.State != HostedStrategyRunBookmarkReadState.Missing;
            IsDiscardRecoveryArmed = false;
            RecoveryDiscardConfirmation = string.Empty;
            Message = "Recovery changed in another Terminal process; nothing was discarded. Refresh before retrying.";
            RefreshComputed();
            return;
        }
        _bookmarkRead = _bookmarkStore.Read();
        if (_bookmarkRead.State != HostedStrategyRunBookmarkReadState.Missing)
        {
            IsDiscardRecoveryArmed = false;
            RecoveryDiscardConfirmation = string.Empty;
            Message = "Terminal could not remove the recovery barrier; new hosted runs remain blocked.";
            return;
        }

        _hasRecoveryBarrier = false;
        _idempotencyKey = null;
        IsDiscardRecoveryArmed = false;
        RecoveryDiscardConfirmation = string.Empty;
        Message = "Recovery bookmark discarded. Any server-side run may still require operator cleanup.";
        RefreshComputed();
    }

    private async Task MonitorUntilReviewAsync(int generation, CancellationToken cancellationToken)
    {
        while (generation == _generation && RunStatus is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
        {
            Message = RunStatus == CoordinatorRunStatus.Ready
                ? "Credits reserved; waiting for a worker."
                : "Coordinator roles are running. No source is executable or installed.";
            await _pollDelay.WaitAsync(cancellationToken);
            var status = await GetClient().GetStatusAsync(RunId!.Value, cancellationToken);
            if (generation != _generation) return;
            ApplyStatus(status);
        }

        if (generation != _generation) return;
        if (RunStatus is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed)
        {
            var status = await GetClient().GetStatusAsync(RunId!.Value, cancellationToken);
            ApplyStatus(status);
            await LoadPreviewAsync(status, cancellationToken);
            await TryRefreshCreditsAsync(cancellationToken);
            return;
        }

        var terminal = _lastStatus ?? new VibeQuantRunStatusResponse(
            RunId!.Value,
            RunStatus ?? CoordinatorRunStatus.Failed,
            SpecificationSha256!,
            0,
            false,
            0,
            0,
            null,
            null,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);
        Message = DescribeStatus(terminal);
        ClearBookmarkForTerminalStatus(terminal.Status);
        await TryRefreshCreditsAsync(cancellationToken);
    }

    private async Task LoadPreviewAsync(
        VibeQuantRunStatusResponse status,
        CancellationToken cancellationToken)
    {
        var previouslyReleasedSha256 = _releasedArtifactSha256;
        ClearPreview();
        if (status.Status is not (CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed) ||
            status.CompletedRoleCount != 5 || status.FinalArtifactSha256 is null)
        {
            throw new InvalidDataException("The hosted run is not in a complete, previewable source state.");
        }

        var response = await GetClient().GetArtifactAsync(
            status.RunId,
            status.FinalArtifactSha256,
            cancellationToken);
        var artifact = response.StrategyArtifact ??
            throw new InvalidDataException("The final hosted artifact is not an inert strategy source artifact.");
        CoordinatorStrategyArtifactValidation.Validate(artifact);
        if (_specification is null || artifact.RunId != status.RunId ||
            !StringComparer.Ordinal.Equals(artifact.ObjectiveSha256, ContentHasher.HashUtf8(_specification.Spec.Objective)) ||
            !StringComparer.Ordinal.Equals(ContentHasher.HashJson(artifact), status.FinalArtifactSha256) ||
            artifact.EvidenceSourceIds.Any(sourceId =>
                !_specification.Spec.Sources.Any(source => source.Id == sourceId)))
        {
            throw new InvalidDataException("The source artifact is not bound to this run, objective, and exact preview hash.");
        }

        var riskResponse = await GetClient().GetArtifactAsync(
            status.RunId,
            artifact.RiskJudgeArtifactSha256,
            cancellationToken);
        var riskReview = riskResponse.Output;
        if (riskResponse.Role != CoordinatorRole.RiskJudge ||
            riskReview is null || riskReview.Role != CoordinatorRole.RiskJudge ||
            riskReview.Decision != CoordinatorDecision.Approve ||
            !StringComparer.Ordinal.Equals(
                ContentHasher.HashJson(riskReview),
                artifact.RiskJudgeArtifactSha256))
        {
            throw new InvalidDataException("The bound Risk Judge artifact is missing, changed, or did not approve release review.");
        }

        var riskItems = ValidateRiskReview(riskReview, _specification.Spec.Sources);
        var fileViews = artifact.Files
            .Select(file => new HostedStrategySourceFileView(
                file.RelativePath,
                file.Content,
                file.ContentSha256))
            .ToArray();

        _artifact = artifact;
        _riskReview = riskReview;
        PreviewedArtifactSha256 = status.FinalArtifactSha256;
        if (StringComparer.Ordinal.Equals(previouslyReleasedSha256, status.FinalArtifactSha256))
            SetReleasedArtifactSha256(previouslyReleasedSha256);
        foreach (var file in fileViews) Files.Add(file);
        SelectedFile = Files.FirstOrDefault();
        RiskReviewSummary = riskReview.Summary;
        foreach (var item in riskItems) RiskReviewItems.Add(item);
        Message = status.Status == CoordinatorRunStatus.AwaitingReleaseApproval
            ? "Read every source file. Release is a separate exact-hash approval and charges are already settled."
            : ReleaseConfirmed
                ? "Released source is complete and can be imported into the local editor."
                : "This run was already released outside this preview session; import remains locked.";
        RefreshComputed();
    }

    private void ApplyStatus(VibeQuantRunStatusResponse status)
    {
        if (_specification is null || status.RunId != _specification.Spec.RunId ||
            !StringComparer.Ordinal.Equals(status.SpecSha256, _specification.SpecSha256))
        {
            throw new InvalidDataException("The hosted status is not bound to the loaded run specification.");
        }
        if (status.Status is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed &&
            (status.CompletedRoleCount != 5 || status.FinalArtifactSha256 is null))
        {
            throw new InvalidDataException("The hosted status claims a final state without complete role and artifact evidence.");
        }
        if (status.ReservedCredits > _specification.Spec.MaximumCreditCharge ||
            status.ChargedCredits > _specification.Spec.MaximumCreditCharge ||
            status.ReservedCredits > _specification.Spec.MaximumCreditCharge - status.ChargedCredits ||
            status.ReservedCredits > 0 && status.ChargedCredits > 0 ||
            status.Status is (CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running) &&
                status.ReservedCredits != _specification.Spec.MaximumCreditCharge ||
            status.ReservedCredits > 0 &&
                status.Status is not (CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running) ||
            status.ChargedCredits > 0 &&
                status.Status is (CoordinatorRunStatus.AwaitingStartApproval or CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running) ||
            status.FinalArtifactSha256 is not null &&
                status.Status is not (CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed))
        {
            throw new InvalidDataException("The hosted status exceeds the approved charge or has inconsistent settlement state.");
        }
        if (status.ChargedCredits < RunChargedCredits ||
            RunStatus is { } previousStatus && !IsLegalStatusTransition(previousStatus, status.Status))
        {
            throw new InvalidDataException("The hosted status rolled back settled credits or run lifecycle state.");
        }

        if (_releasedArtifactSha256 is not null &&
            !StringComparer.Ordinal.Equals(_releasedArtifactSha256, status.FinalArtifactSha256))
        {
            SetReleasedArtifactSha256(null);
        }

        RunStatus = status.Status;
        RunReservedCredits = status.ReservedCredits;
        RunChargedCredits = status.ChargedCredits;
        _lastStatus = status;
        RefreshComputed();
    }

    private static bool IsLegalStatusTransition(
        CoordinatorRunStatus previous,
        CoordinatorRunStatus current)
    {
        if (previous == current) return true;
        return previous switch
        {
            CoordinatorRunStatus.AwaitingStartApproval => current is
                CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running or
                CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed or
                CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected or
                CoordinatorRunStatus.NeedsRevision or CoordinatorRunStatus.BudgetExhausted or
                CoordinatorRunStatus.Failed,
            CoordinatorRunStatus.Ready => current is
                CoordinatorRunStatus.Running or CoordinatorRunStatus.AwaitingReleaseApproval or
                CoordinatorRunStatus.Completed or CoordinatorRunStatus.Cancelled or
                CoordinatorRunStatus.Rejected or CoordinatorRunStatus.NeedsRevision or
                CoordinatorRunStatus.BudgetExhausted or CoordinatorRunStatus.Failed,
            CoordinatorRunStatus.Running => current is
                CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed or
                CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected or
                CoordinatorRunStatus.NeedsRevision or CoordinatorRunStatus.BudgetExhausted or
                CoordinatorRunStatus.Failed,
            CoordinatorRunStatus.AwaitingReleaseApproval => current is
                CoordinatorRunStatus.Completed or CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected,
            _ => false,
        };
    }

    private async Task RefreshCreditsCoreAsync(CancellationToken cancellationToken)
    {
        var credits = await GetClient().GetCreditsAsync(cancellationToken);
        AvailableCredits = credits.AvailableCredits;
        ReservedCredits = credits.ReservedCredits;
        ConsumedCredits = credits.ConsumedCredits;
        CreditPricingVersion = credits.CreditPricingVersion;
        RefreshComputed();
    }

    private async Task TryRefreshCreditsAsync(CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await RefreshCreditsCoreAsync(timeout.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Could not refresh Platform credits after hosted run state changed");
        }
    }

    private async Task<bool> ResumeBookmarkAsync(CancellationToken cancellationToken)
    {
        if (_bookmarkRead.State == HostedStrategyRunBookmarkReadState.Missing) return false;
        if (_bookmarkRead.State != HostedStrategyRunBookmarkReadState.Valid || _bookmarkRead.Bookmark is null)
        {
            throw new InvalidDataException(
                "The hosted-run recovery bookmark is unreadable. New runs remain blocked until explicit discard.");
        }
        var bookmark = _bookmarkRead.Bookmark;
        if (!StringComparer.Ordinal.Equals(bookmark.ConnectionBinding, RequireConnectionBinding()))
        {
            throw new InvalidDataException(
                bookmark.RunId is { } foreignRunId
                    ? $"Saved hosted run {foreignRunId:D} belongs to a different loopback connection and will not be replayed. " +
                      "Restore that connection to resume or cancel it; typed discard does not cancel or refund it."
                    : "The saved hosted quote belongs to a different loopback connection and will not be replayed.");
        }

        _restoringBookmark = true;
        try
        {
            _idempotencyKey = bookmark.IdempotencyKey;
            Objective = bookmark.Objective;
        }
        finally
        {
            _restoringBookmark = false;
        }

        Message = bookmark.RunId is null
            ? "Recovering the exact quote request from its idempotency key."
            : $"Restoring hosted run {bookmark.RunId:D}.";
        var specification = bookmark.RunId is { } bookmarkedRunId
            ? await GetClient().GetSpecificationAsync(bookmarkedRunId, cancellationToken)
            : await GetClient().CreateRunAsync(
                new CreateVibeQuantRunRequest(
                    bookmark.Objective,
                    [],
                    CoordinatorRunPurpose.StrategyAuthoring),
                bookmark.IdempotencyKey,
                cancellationToken);
        if (bookmark.SpecSha256 is not null &&
            !StringComparer.Ordinal.Equals(bookmark.SpecSha256, specification.SpecSha256))
        {
            throw new InvalidDataException("The restored run specification changed from the bookmarked exact hash.");
        }

        LoadSpecification(specification, bookmark.Objective);
        SaveCurrentBookmarkRequired();
        var status = await GetClient().GetStatusAsync(specification.Spec.RunId, cancellationToken);
        ApplyStatus(status);
        if (status.Status == CoordinatorRunStatus.AwaitingStartApproval)
        {
            await TryRefreshCreditsAsync(cancellationToken);
            Message = "Restored the uncharged quote. Review the exact specification before approving the charge.";
            return true;
        }
        if (status.Status is CoordinatorRunStatus.Ready or CoordinatorRunStatus.Running)
        {
            var generation = ++_generation;
            _monitor?.Cancel();
            _monitor?.Dispose();
            _monitor = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            Message = "Restored the active run. Monitoring resumes; closing the window will preserve this bookmark.";
            SetMonitoring(true);
            try
            {
                await TryRefreshCreditsAsync(_monitor.Token);
                await MonitorUntilReviewAsync(generation, _monitor.Token);
            }
            finally
            {
                SetMonitoring(false);
            }
            return true;
        }
        if (status.Status is CoordinatorRunStatus.AwaitingReleaseApproval or CoordinatorRunStatus.Completed)
        {
            await LoadPreviewAsync(status, cancellationToken);
            await TryRefreshCreditsAsync(cancellationToken);
            return true;
        }

        ClearBookmarkForTerminalStatus(status.Status);
        Message = $"Restored run ended safely. {DescribeStatus(status)}";
        await TryRefreshCreditsAsync(cancellationToken);
        return true;
    }

    private void LoadSpecification(VibeQuantRunSpecResponse specification, string expectedObjective)
    {
        var spec = specification.Spec;
        if (!StringComparer.Ordinal.Equals(ContentHasher.HashJson(spec), specification.SpecSha256) ||
            !StringComparer.Ordinal.Equals(spec.Objective, expectedObjective) ||
            spec.PolicyVersion != CoordinatorVersions.StrategyPolicy ||
            spec.WorkflowVersion != CoordinatorVersions.StrategyWorkflow ||
            spec.PromptCatalogSha256 != CoordinatorVersions.StrategyPromptCatalogSha256 ||
            spec.Provider.Protocol is not ("mock" or "openai-compatible") ||
            spec.Sources.Count != 0)
        {
            throw new InvalidDataException(
                "The hosted specification is not the exact inert strategy-authoring profile requested by Terminal.");
        }

        ClearPreview();
        _specification = specification;
        _lastStatus = null;
        RunId = spec.RunId;
        SpecificationSha256 = specification.SpecSha256;
        RunReservedCredits = 0;
        RunChargedCredits = 0;
        RefreshComputed();
    }

    private void SaveCurrentBookmarkRequired()
    {
        var specification = _specification ?? throw new InvalidOperationException("No hosted specification is loaded.");
        var idempotencyKey = _idempotencyKey ?? throw new InvalidOperationException("No hosted idempotency key is loaded.");
        UpdateBookmarkRequired(new HostedStrategyRunBookmark(
            HostedStrategyRunBookmark.CurrentSchemaVersion,
            RequireConnectionBinding(),
            specification.Spec.Objective,
            idempotencyKey,
            specification.Spec.RunId,
            specification.SpecSha256,
            DateTimeOffset.UtcNow));
    }

    private void CreateBookmarkRequired(HostedStrategyRunBookmark bookmark)
    {
        if (!_bookmarkStore.TryCreate(bookmark))
        {
            _bookmarkRead = _bookmarkStore.Read();
            _hasRecoveryBarrier = _bookmarkRead.State != HostedStrategyRunBookmarkReadState.Missing;
            throw new InvalidOperationException(
                "Another Terminal process or unreadable recovery state already owns hosted-run recovery; no request was sent.");
        }
        AcceptSavedBookmark(bookmark);
    }

    private void UpdateBookmarkRequired(HostedStrategyRunBookmark bookmark)
    {
        if (!_bookmarkStore.TryUpdate(bookmark))
        {
            throw new InvalidOperationException(
                "Terminal could not persist the hosted-run recovery bookmark, so no charge approval is allowed.");
        }
        AcceptSavedBookmark(bookmark);
    }

    private void AcceptSavedBookmark(HostedStrategyRunBookmark bookmark)
    {
        _bookmarkRead = new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.Valid,
            bookmark);
        _hasRecoveryBarrier = true;
        IsDiscardRecoveryArmed = false;
        RecoveryDiscardConfirmation = string.Empty;
        RefreshCommands();
    }

    private void ClearBookmarkForTerminalStatus(CoordinatorRunStatus status)
    {
        if (status is CoordinatorRunStatus.Cancelled or CoordinatorRunStatus.Rejected or
            CoordinatorRunStatus.NeedsRevision or CoordinatorRunStatus.BudgetExhausted or
            CoordinatorRunStatus.Failed)
        {
            ClearRecoveryBookmark();
        }
    }

    private void ClearRecoveryBookmark()
    {
        _ = _bookmarkStore.TryClear(_bookmarkRead);
        _bookmarkRead = _bookmarkStore.Read() ?? new HostedStrategyRunBookmarkReadResult(
            HostedStrategyRunBookmarkReadState.InvalidOrUnreadable);
        _hasRecoveryBarrier = _bookmarkRead.State != HostedStrategyRunBookmarkReadState.Missing;
        IsDiscardRecoveryArmed = false;
        RecoveryDiscardConfirmation = string.Empty;
        RefreshCommands();
    }

    private static string FormatSpecification(VibeQuantRunSpecResponse response)
    {
        var spec = response.Spec;
        var budget = spec.Budget;
        return string.Join(Environment.NewLine,
        [
            $"Run: {spec.RunId:D}",
            $"Provider: {spec.Provider.ProviderId} / {spec.Provider.ModelId} / {spec.Provider.Protocol}",
            $"Maximum charge: {spec.MaximumCreditCharge:N0} credits ({spec.CreditPricingVersion})",
            $"Budget: requests {budget.MaxRequests}; attempts/role {budget.MaxAttemptsPerRole}; " +
                $"prompt {budget.MaxPromptTokens:N0}; output {budget.MaxOutputTokens:N0}; per request {budget.MaxOutputTokensPerRequest:N0}",
            $"Limits: response {budget.MaxResponseBytes:N0} bytes; artifacts {budget.MaxArtifactBytes:N0} bytes; " +
                $"elapsed {budget.MaxElapsedSeconds}s; request {budget.RequestTimeoutSeconds}s",
            $"Policy: {spec.PolicyVersion}",
            $"Workflow: {spec.WorkflowVersion}",
            $"Prompt catalog SHA-256: {spec.PromptCatalogSha256}",
            $"Execution binding: {spec.ExecutionProfileBinding}",
            $"Specification SHA-256: {response.SpecSha256}",
        ]);
    }

    private static IReadOnlyList<string> ValidateRiskReview(
        CoordinatorRoleOutput output,
        IReadOnlyList<VibeQuantSourceView> sources)
    {
        if (output.SchemaVersion != CoordinatorVersions.ArtifactSchema ||
            output.Role != CoordinatorRole.RiskJudge ||
            output.Decision != CoordinatorDecision.Approve ||
            output.StrategyDraft is not null ||
            !IsBoundedText(output.Summary, 30_000) ||
            output.Claims is null || output.Claims.Count > 100 ||
            output.Risks is null || output.Risks.Count > 100 ||
            output.Recommendations is null || output.Recommendations.Count > 100 ||
            output.SourceIds is null || output.SourceIds.Count > 100)
        {
            throw new InvalidDataException("The bound Risk Judge output failed semantic validation.");
        }

        var allowedSourceIds = new HashSet<string>(
            sources.Select(source => source.Id),
            StringComparer.Ordinal);
        var outputSourceIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var sourceId in output.SourceIds)
        {
            if (!CoordinatorStrategyArtifactValidation.IsSafeIdentifier(sourceId, 100) ||
                !allowedSourceIds.Contains(sourceId) ||
                !outputSourceIds.Add(sourceId))
            {
                throw new InvalidDataException("The bound Risk Judge output contains invalid source identities.");
            }
        }

        foreach (var claim in output.Claims)
        {
            if (claim is null || !IsBoundedText(claim.Statement, 10_000) ||
                claim.Confidence is < 0m or > 1m || claim.EvidenceSourceIds is null ||
                claim.EvidenceSourceIds.Count > 100 ||
                claim.EvidenceSourceIds.Any(sourceId =>
                    !CoordinatorStrategyArtifactValidation.IsSafeIdentifier(sourceId, 100) ||
                    !allowedSourceIds.Contains(sourceId)) ||
                claim.EvidenceSourceIds.Distinct(StringComparer.Ordinal).Count() != claim.EvidenceSourceIds.Count)
            {
                throw new InvalidDataException("The bound Risk Judge output contains an invalid evidence claim.");
            }
        }

        var items = new List<string>(output.Risks.Count + output.Recommendations.Count);
        foreach (var risk in output.Risks)
        {
            if (!IsBoundedText(risk, 10_000))
                throw new InvalidDataException("The bound Risk Judge output contains invalid risk text.");
            items.Add($"Risk: {risk}");
        }
        foreach (var recommendation in output.Recommendations)
        {
            if (!IsBoundedText(recommendation, 10_000))
                throw new InvalidDataException("The bound Risk Judge output contains invalid recommendation text.");
            items.Add($"Recommendation: {recommendation}");
        }
        return items;
    }

    private static bool IsBoundedText(string? value, int maximumCharacters) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximumCharacters && value.IndexOf('\0') < 0;

    private void ClearPreview()
    {
        _artifact = null;
        _riskReview = null;
        PreviewedArtifactSha256 = null;
        Files.Clear();
        SelectedFile = null;
        RiskReviewSummary = "Risk review has not been loaded.";
        RiskReviewItems.Clear();
        SetReleasedArtifactSha256(null);
        RefreshComputed();
    }

    private void SetReleasedArtifactSha256(string? sha256)
    {
        if (StringComparer.Ordinal.Equals(_releasedArtifactSha256, sha256)) return;
        _releasedArtifactSha256 = sha256;
        OnPropertyChanged(nameof(ReleaseConfirmed));
        RefreshCommands();
    }

    private void SetMonitoring(bool value)
    {
        if (_isMonitoring == value) return;
        _isMonitoring = value;
        RefreshCommands();
    }

    private IVibeQuantApiClient GetClient() => _client ??= _clientFactory.Create();

    private string RequireConnectionBinding() => _connectionBinding ??
        throw new InvalidOperationException("The hosted connection identity is not available.");

    private void RefreshAvailability()
    {
        var availability = _clientFactory.GetAvailability();
        IsConfigured = availability.IsAvailable;
        ConfigurationMessage = availability.Message;
        _connectionBinding = availability.IsAvailable ? availability.ConnectionBinding : null;
        if (!availability.IsAvailable) Message = availability.Message;
        RefreshComputed();
    }

    private async Task RunExclusiveAsync(Func<CancellationToken, Task> action)
    {
        if (IsBusy || _disposed) return;
        IsBusy = true;
        RefreshCommands();
        try
        {
            await action(_lifetime.Token);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested || _monitor?.IsCancellationRequested == true)
        {
        }
        catch (Exception exception)
        {
            ReportFailure("hosted authoring", exception);
        }
        finally
        {
            IsBusy = false;
            RefreshCommands();
        }
    }

    private void ReportFailure(string operation, Exception exception)
    {
        _logger.LogWarning(exception, "Hyperion hosted {Operation} failed", operation);
        if (exception is VibeQuantApiException { StatusCode: HttpStatusCode.Unauthorized })
        {
            _client = null;
            Message = "The Platform session was rejected. Refresh the connection, then resume the bookmarked run.";
            return;
        }
        Message = exception switch
        {
            HttpRequestException => "The hosted Platform could not be reached.",
            VibeQuantApiException apiException => apiException.Message,
            InvalidDataException => exception.Message,
            InvalidOperationException => exception.Message,
            _ => "The hosted authoring request failed safely. Retry or inspect the Activity Log.",
        };
    }

    private static string DescribeStatus(VibeQuantRunStatusResponse status) => status.Status switch
    {
        CoordinatorRunStatus.Cancelled when status.ChargedCredits > 0 =>
            $"Run cancelled. {status.ChargedCredits:N0} settled credits remain charged; any unspent reservation was refunded.",
        CoordinatorRunStatus.Cancelled => "Run cancelled before settled usage; the server refunded its reservation.",
        CoordinatorRunStatus.Rejected => status.SafeMessage ?? "The risk review rejected this run.",
        CoordinatorRunStatus.NeedsRevision => status.SafeMessage ?? "The run needs revision and produced no releasable source.",
        CoordinatorRunStatus.BudgetExhausted => status.SafeMessage ?? "The server-owned budget was exhausted.",
        CoordinatorRunStatus.Failed => status.SafeMessage ?? "The hosted run failed safely.",
        CoordinatorRunStatus.Completed => "Run completed.",
        _ => status.SafeMessage ?? status.Status.ToString(),
    };

    partial void OnObjectiveChanged(string value)
    {
        if (RunId is null && !_restoringBookmark && !_hasRecoveryBarrier)
            _idempotencyKey = null;
        RefreshCommands();
    }

    partial void OnRunIdChanged(Guid? value) => RefreshComputed();
    partial void OnRunStatusChanged(CoordinatorRunStatus? value) => RefreshComputed();
    partial void OnIsConfiguredChanged(bool value) => RefreshCommands();
    partial void OnIsBusyChanged(bool value) => RefreshComputed();
    partial void OnIsCancellingChanged(bool value) => RefreshComputed();
    partial void OnIsDiscardRecoveryArmedChanged(bool value)
    {
        OnPropertyChanged(nameof(DiscardRecoveryText));
        RefreshCommands();
    }
    partial void OnRecoveryDiscardConfirmationChanged(string value) => RefreshCommands();
    partial void OnPreviewedArtifactSha256Changed(string? value)
    {
        OnPropertyChanged(nameof(ReleaseConfirmed));
        RefreshComputed();
    }
    partial void OnCreditPricingVersionChanged(string? value) => OnPropertyChanged(nameof(CreditSummary));
    partial void OnAvailableCreditsChanged(long value) => OnPropertyChanged(nameof(CreditSummary));
    partial void OnReservedCreditsChanged(long value) => OnPropertyChanged(nameof(CreditSummary));
    partial void OnConsumedCreditsChanged(long value) => OnPropertyChanged(nameof(CreditSummary));
    partial void OnRunReservedCreditsChanged(long value) => OnPropertyChanged(nameof(RunCreditSummary));
    partial void OnRunChargedCreditsChanged(long value) => OnPropertyChanged(nameof(RunCreditSummary));

    private void OnWorkspacePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName != nameof(StrategyAuthoringViewModel.IsGenerating)) return;
        if (_workspace.IsGenerating && ReleaseConfirmed)
            Message = "Stop the active local generation before importing the released hosted source.";
        RefreshCommands();
    }

    private void RefreshComputed()
    {
        OnPropertyChanged(nameof(RunStatusText));
        OnPropertyChanged(nameof(IsObjectiveReadOnly));
        OnPropertyChanged(nameof(CreditSummary));
        OnPropertyChanged(nameof(SpecificationSummary));
        OnPropertyChanged(nameof(SpecificationDetails));
        OnPropertyChanged(nameof(RunCreditSummary));
        OnPropertyChanged(nameof(ArtifactSummary));
        RefreshCommands();
    }

    private void RefreshCommands()
    {
        InitializeCommand.NotifyCanExecuteChanged();
        SubmitCommand.NotifyCanExecuteChanged();
        StartCommand.NotifyCanExecuteChanged();
        RefreshStatusCommand.NotifyCanExecuteChanged();
        ReleaseCommand.NotifyCanExecuteChanged();
        ImportCommand.NotifyCanExecuteChanged();
        CancelCommand.NotifyCanExecuteChanged();
        DiscardRecoveryCommand.NotifyCanExecuteChanged();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _workspace.PropertyChanged -= OnWorkspacePropertyChanged;
        ++_generation;
        _monitor?.Cancel();
        _monitor?.Dispose();
        _lifetime.Cancel();
        _lifetime.Dispose();
    }
}
