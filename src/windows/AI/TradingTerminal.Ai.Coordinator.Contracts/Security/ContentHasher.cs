using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TradingTerminal.Ai.Coordinator.Serialization;

namespace TradingTerminal.Ai.Coordinator.Security;

public static class ContentHasher
{
    public static string HashUtf8(string value) => HashBytes(Encoding.UTF8.GetBytes(value));

    public static string HashBytes(ReadOnlySpan<byte> value) =>
        Convert.ToHexStringLower(SHA256.HashData(value));

    public static string HashJson<T>(T value) =>
        HashBytes(JsonSerializer.SerializeToUtf8Bytes(value, CoordinatorJson.Options));
}
