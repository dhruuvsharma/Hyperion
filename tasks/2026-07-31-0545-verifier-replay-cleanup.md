# Verifier replay cleanup race
Status: complete

## Goal
Close the Windows replay-workspace cleanup race exposed by hosted CI after an intentional candidate
process crash, without accepting residual candidate artifacts or weakening the verifier boundary.

## Evidence
- Hyperion CI run `30604602595` failed
  `CandidateProcessCrashBecomesACompletedNegativeResult` because recursive deletion of the exact
  replay temp directory encountered a transient Windows sharing violation.
- The preceding publication commit passed the same 43-test verifier suite, demonstrating that the
  failure is nondeterministic rather than a documentation-caused semantic regression.
- Process exit, redirected-pipe drainage, and `Process.Dispose` already precede cleanup. The likely
  remaining owner is transient Windows crash-reporting/postmortem handling of the crashed child's
  working directory.
- Independent review found two adjacent lifecycle gaps in the first repair: a cleanup exception
  could mask an earlier process/pipe failure, and an unexpected exception after `Start()` did not
  unconditionally terminate the child. The final implementation closes both and the re-audits found
  no remaining high- or medium-severity issue.

## Plan
1. Replace the one-shot deletion with a bounded, non-cancellable retry that still propagates a
   persistent cleanup failure.
2. Add deterministic transient-lock and persistent-lock regressions without wall-clock sleeps.
3. Run the focused verifier suite, repeat the original crash path, then run and publish full CI.

## Boundaries
- `D:\Github\Hyperion` only; `public/` remains clean and pinned read-only.
- Do not swallow persistent deletion failures, broaden deletion targets, or accept residual
  candidate/request/result artifacts.
- No model weights, corpus authority, production signer, or deployment evidence is created.

## Diff summary
- `CandidateReplayProcess` now retries exact replay-directory deletion for at most 21 attempts and
  20 non-cancellable 100 ms delays. Missing directories are success; exhausted sharing or access
  failures remain exceptions.
- Cleanup now checks and boundedly terminates every started child, disposes the process, and then
  deletes only the captured `Directory.CreateTempSubdirectory` path. When both replay and cleanup
  fail, an aggregate preserves the primary and cleanup exceptions.
- The verifier test assembly has internal test access. Four deterministic regressions cover a
  released sharing violation, a persistent lock, live-process termination before deletion, and
  preservation of both failures. The original intentional-crash test remains end-to-end coverage.

## Verification
- Focused cleanup/lifecycle coverage passed 5/5.
- The original crash plus live-process cleanup paths passed ten repeated iterations (20 test
  executions) after the final lifecycle repair; an earlier ten-run crash-only stress also passed.
- The complete VerifierWorker suite passed 47/47, up from 43 tests before this slice. Both verifier
  projects pass `dotnet format --verify-no-changes`.
- The full `Hyperion.slnx` Release build passed with only two pre-existing DAXQ nullable warnings;
  all 541 .NET tests passed: Contracts 44, VM 41, Compiler 41, VerifierWorker 47, Platform API 150,
  and coordinator headless 218. The solution formatting gate passed.
- `git diff --check` passes; the three edited C#/project files remain BOM-less UTF-8 CRLF. `public/`
  is clean and pinned unchanged at `ae19c5eb7ab7b3c6d6e1a5647fc127a838e6dd05`.
- Publication commit `93b77087f8522aaca1cfc9c8d0f9a3c1d36e3f2b` passed Hyperion CI run
  `30605721647`: Windows restore/build/all 541 tests/formatting and Linux Python tests/Ruff
  lint/Ruff formatting/compile/CLI discovery all completed successfully.

## Residual limits
- A same-user or privileged actor can still race path ownership within the previously documented
  host-custody limit; this slice neither widens nor claims to close that boundary.
- A lock that outlives the strict retry budget still fails the verifier as infrastructure cleanup
  failure. It is never converted into candidate success or silently abandoned residue.
