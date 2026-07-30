# Hyperion repository guide

Hyperion is the private expert-model coordinator, training-evidence, evaluation, verifier, and
serving system extracted from DaxAlgo Terminal Pro. Make Hyperion changes in this repository only.

## Boundaries

- Treat `public/` as a pinned, read-only shared-core submodule. Never copy private Hyperion code into
  it or commit changes through the submodule.
- Preserve legacy `DaxAlgo`, `TradingTerminal`, and `VibeQuant` wire identifiers where changing them
  would invalidate signed payloads, schema IDs, hashes, persisted data, or existing clients.
- Use **Hyperion** for the repository, product, solution, operator commands, and new documentation.
- Never commit model weights, checkpoints, secrets, private signing keys, review evidence, or
  production credentials.
- Existing dirty files are user work. Do not reset, reformat, stage, or overwrite them incidentally.

## Working discipline

- For material work, create and maintain `tasks/YYYY-MM-DD-HHMM-slug.md`.
- Prefer small, evidence-backed changes. Record implemented, proposed, and externally blocked work
  separately.
- Run focused checks before broad checks. Never describe synthetic fixtures as model-training or
  quality evidence.
- Do not commit, push, publish, create releases, or contact external systems unless the user asks.

## Main checks

```powershell
dotnet test Hyperion.slnx --no-restore
Push-Location tools/hyperion-model
python -m pytest tests
python -m ruff check .
python -m ruff format --check .
Pop-Location
```

The sealed trainer profile is Linux x86_64, CPython 3.11, CUDA 12.1. Local validation on another
host does not establish a conforming training run.
