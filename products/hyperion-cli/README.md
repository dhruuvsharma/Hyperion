# Hyperion CLI

The .NET `hyperion` executable is the single command-line entry point for:

- authenticated hosted Hyperion jobs and dataset operations; and
- the isolated local Free Strategy Workflow, using a different config schema and workspace.

The build project is at `src/windows/Tools/Hyperion.Cli/Hyperion.Cli.csproj`. Its legacy
`DaxAlgo.Coordinator.Cli` namespace is retained for compatibility, while the source path, produced
assembly, and command are now consistently branded as Hyperion.

The hosted client never receives provider credentials. The local workflow config stores only a
dedicated environment-variable name, never its value. Hosted config cannot be used for local
provider execution and local config cannot select hosted policy, credits, or deployment artifacts.

The local surface has pinned profiles for Ollama, OpenAI, OpenRouter, Groq, Mistral, DeepSeek,
Anthropic, and Gemini, plus an explicitly enabled custom OpenAI-compatible profile. Use
`workflow gauntlet` for a process-integrity report and `workflow revise` for one of at most two fresh,
lineage-bound repair runs. These commands do not compile, test, backtest, install, or trade.
The OpenAI profile is the Chat Completions compatibility route and rejects o-series models; a native
Responses profile remains deferred.

Run `hyperion --help` and `hyperion workflow --help` for the two surfaces.
