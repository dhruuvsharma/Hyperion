@echo off
title Hyperion - Codex
rem One-click Codex session for the standalone private Hyperion repository.
rem Loads Hyperion guidance, architecture, research, and current task state only.
rem The public submodule is pinned read-only; DaxAlgo-Terminal-Pro is out of scope.
cd /d "%~dp0"
where codex >nul 2>nul
if errorlevel 1 (
    echo Codex CLI not found on PATH. Install it first: https://developers.openai.com/codex/cli/
    pause
    exit /b 1
)
codex --profile funkeh --dangerously-bypass-approvals-and-sandbox "Hyperion session start: this standalone repository is the only development target. Read AGENTS.md, README.md, tasks/README.md, docs/architecture/hyperion-frontier-architecture.md, docs/guides/hyperion-coordinator.md, and docs/research/kimi-k3-adoption-notes.md. Identify and read the newest task file whose Status is active or blocked, ignoring tasks/README.md. Inspect git status --short and git -C public status --short. Treat public/ as a pinned read-only shared-core submodule; never copy private Hyperion code into it. Do not read or modify D:\Github\DaxAlgo-Terminal-Pro. Use the engineering handbook and other Hyperion docs as routed references when the task needs them. Reply with one line confirming Hyperion context, task state, and both worktrees are loaded, then wait for my task."
