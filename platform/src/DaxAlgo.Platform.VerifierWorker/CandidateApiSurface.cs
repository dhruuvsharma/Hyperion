namespace DaxAlgo.Platform.VerifierWorker;

internal static class CandidateApiSurface
{
    private const string CoreAssembly = "TradingTerminal.Core";
    private const string SdkAssembly = "DaxAlgo.Sdk";

    private static readonly HashSet<string> AllowedNamespaces =
    [
        "DaxAlgo.Sdk",
        "TradingTerminal.Core",
        "TradingTerminal.Core.Backtest",
        "TradingTerminal.Core.Domain",
        "TradingTerminal.Core.Time",
        "TradingTerminal.Core.Trading",
    ];

    private static readonly Dictionary<string, HashSet<string>> AllowedMembers = new(
        StringComparer.Ordinal)
    {
        ["DaxAlgo.Sdk.SdkInfo"] = ["Version"],
        ["TradingTerminal.Core.Backtest.IBacktestStrategy"] =
        [
            "OnStartAsync",
            "OnTickAsync",
            "OnOrderEventAsync",
            "OnEndAsync",
        ],
        ["TradingTerminal.Core.Domain.Contract"] =
        [
            ".ctor",
            "Symbol",
            "get_Symbol",
            "SecType",
            "get_SecType",
            "Exchange",
            "get_Exchange",
            "Currency",
            "get_Currency",
            "PrimaryExchange",
            "get_PrimaryExchange",
        ],
        ["TradingTerminal.Core.Domain.Tick"] =
        [
            "TimestampUtc",
            "get_TimestampUtc",
            "Bid",
            "get_Bid",
            "Ask",
            "get_Ask",
            "BidSize",
            "get_BidSize",
            "AskSize",
            "get_AskSize",
        ],
        ["TradingTerminal.Core.Time.IClock"] = ["UtcNow", "get_UtcNow"],
        ["TradingTerminal.Core.Trading.IOrderRouter"] =
        [
            "PlaceOrderAsync",
            "CancelOrderAsync",
        ],
        ["TradingTerminal.Core.Trading.OrderRequest"] =
        [
            ".ctor",
            "ClientOrderId",
            "get_ClientOrderId",
            "Contract",
            "get_Contract",
            "Side",
            "get_Side",
            "Type",
            "get_Type",
            "Quantity",
            "get_Quantity",
            "LimitPrice",
            "get_LimitPrice",
            "StopPrice",
            "get_StopPrice",
            "TimeInForce",
            "get_TimeInForce",
        ],
        ["TradingTerminal.Core.Trading.OrderResult"] =
        [
            "ClientOrderId",
            "get_ClientOrderId",
            "BrokerOrderId",
            "get_BrokerOrderId",
            "State",
            "get_State",
            "RejectReason",
            "get_RejectReason",
        ],
        ["TradingTerminal.Core.Trading.OrderEvent"] =
        [
            "TimestampUtc",
            "get_TimestampUtc",
            "ClientOrderId",
            "get_ClientOrderId",
            "BrokerOrderId",
            "get_BrokerOrderId",
            "Side",
            "get_Side",
            "State",
            "get_State",
            "FilledQuantity",
            "get_FilledQuantity",
            "AverageFillPrice",
            "get_AverageFillPrice",
            "LastFillQuantity",
            "get_LastFillQuantity",
            "LastFillPrice",
            "get_LastFillPrice",
            "RejectReason",
            "get_RejectReason",
            "Liquidity",
            "get_Liquidity",
        ],
        ["TradingTerminal.Core.Trading.OrderSide"] = ["Buy", "Sell"],
        ["TradingTerminal.Core.Trading.OrderType"] =
        [
            "Market",
            "Limit",
            "Stop",
            "StopLimit",
        ],
        ["TradingTerminal.Core.Trading.OrderState"] =
        [
            "PendingNew",
            "Working",
            "PartiallyFilled",
            "Filled",
            "Cancelled",
            "Rejected",
        ],
        ["TradingTerminal.Core.Trading.TimeInForce"] = ["Day", "Gtc", "Ioc", "Fok"],
        ["TradingTerminal.Core.Trading.LiquidityFlag"] = ["Taker", "Maker"],
    };

    public static bool IsProfileAssemblyName(string? name) =>
        name is CoreAssembly or SdkAssembly;

    public static bool IsProfileNamespaceName(string name) =>
        name.Equals("TradingTerminal.Core", StringComparison.Ordinal)
        || name.StartsWith("TradingTerminal.Core.", StringComparison.Ordinal)
        || name.Equals("DaxAlgo.Sdk", StringComparison.Ordinal)
        || name.StartsWith("DaxAlgo.Sdk.", StringComparison.Ordinal);

    public static bool IsAllowedNamespaceName(string name) =>
        AllowedNamespaces.Contains(name);

    public static bool IsProfileTypeName(string name) =>
        name.StartsWith("TradingTerminal.Core.", StringComparison.Ordinal)
        || name.StartsWith("DaxAlgo.Sdk.", StringComparison.Ordinal);

    public static bool IsAllowedTypeName(string name) =>
        AllowedMembers.ContainsKey(name);

    public static bool IsAllowedMember(string typeName, string memberName) =>
        AllowedMembers.TryGetValue(typeName, out var members)
        && members.Contains(memberName);
}
