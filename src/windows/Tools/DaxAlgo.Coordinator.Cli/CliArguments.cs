namespace DaxAlgo.Coordinator.Cli;

internal sealed class CliArguments
{
    private readonly Dictionary<string, List<string>> _options;

    private CliArguments(IReadOnlyList<string> positionals, Dictionary<string, List<string>> options)
    {
        Positionals = positionals;
        _options = options;
    }

    public IReadOnlyList<string> Positionals { get; }

    public static CliArguments Parse(IReadOnlyList<string> args)
    {
        var positionals = new List<string>();
        var options = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        for (var index = 0; index < args.Count; index++)
        {
            var value = args[index];
            if (!value.StartsWith("--", StringComparison.Ordinal))
            {
                positionals.Add(value);
                continue;
            }

            var name = value[2..];
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Empty option name.");
            var optionValue = "true";
            if (index + 1 < args.Count && !args[index + 1].StartsWith("--", StringComparison.Ordinal))
                optionValue = args[++index];
            if (!options.TryGetValue(name, out var values))
                options[name] = values = [];
            values.Add(optionValue);
        }

        return new CliArguments(positionals, options);
    }

    public bool Has(string name) => _options.ContainsKey(name);

    public string? Optional(string name) =>
        _options.TryGetValue(name, out var values) ? values[^1] : null;

    public string Required(string name) =>
        Optional(name) is { } value && value != "true"
            ? value
            : throw new ArgumentException($"--{name} is required.");

    public IReadOnlyList<string> All(string name) =>
        _options.TryGetValue(name, out var values) ? values : [];
}
