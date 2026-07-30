namespace TradingTerminal.Ai.Coordinator.Orchestration;

public sealed class CoordinatorInvocationStillActiveException(string message)
    : InvalidOperationException(message);
