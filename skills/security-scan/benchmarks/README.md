# security-scan benchmark corpus

Ground-truth-labeled fixtures for regression testing the skill's precision and recall.

## Purpose

The skill is a probabilistic pipeline. Changes to prompts, tool configs, suppression rules, or the underlying Claude model can silently regress — a previously-caught issue becomes a false negative, or a previously-suppressed noise finding becomes a false positive. This corpus catches those regressions.

## Structure

```
benchmarks/
  README.md                 # this file
  fixtures/
    java/<case>/            # ~10–50 LOC minimal reproducer + case.yaml
    node/<case>/
    python/<case>/
  harness/
    metrics.schema.json     # output format for eval runs
    run.md                  # how to invoke the harness (scaffold — implementer TBD)
  results/                  # harness output — gitignored
    latest.json
    <timestamp>.json
```

## Current fixtures

| Fixture | Language | CWE | Expected | Tests |
|---|---|---|---|---|
| `sqli-reachable-requestparam` | Java | CWE-89 | must_fix | baseline TP: unsanitized `@RequestParam` → `Statement.executeQuery` |
| `race-single-threaded-scheduled` | Java | CWE-362 | info | FP suppression: `@Scheduled` single-threaded pool rules out race |
| `ssrf-reachable-express` | Node | CWE-918 | must_fix | baseline TP: `req.query.url` → `axios.get` |
| `ssrf-zod-validated` | Node | CWE-918 | info | FP suppression: Zod `.url().refine(isAllowedHost)` narrows taint |
| `sqli-django-raw` | Python | CWE-89 | must_fix | baseline TP: Django `Model.objects.raw("SELECT ... " + q)` |
| `pickle-authenticated` | Python | CWE-502 | should_fix | downgrade: `pickle.loads` behind `@login_required` — exploitable but auth-gated |

Fixtures grow over time. When a real scan produces a wrong verdict, minimize and add it here.

## case.yaml schema

See [`../workflows/07-benchmark-and-cache.md`](../workflows/07-benchmark-and-cache.md) for the full schema. Summary:
- `name`, `language`, `cwe`, `vulnerability`
- `expected.category` — `must_fix` / `should_fix` / `info`
- `expected.classification` — `reachable-exploitable` / `reachable-conditional` / `unreachable` / `insufficient-context`
- `expected.entry_point_type` — `http-public` / `http-authn` / `http-internal` / `kafka` / etc.
- `rationale` — why this fixture exists
- `must_mention_in_evidence` / `must_not_mention` — string assertions on the generated evidence chain

## Running the harness

Scaffolded only in MVP. The `harness/run.md` describes the intended flow:

1. For each `fixtures/*/*/case.yaml`:
   - Copy the fixture to a temp dir
   - Invoke the skill's pipeline (detectors → normalize → context bundle → validate → triage)
   - Parse `triage-report.json` and match against `case.yaml.expected`
2. Aggregate precision/recall per category, language, and CWE class
3. Write `results/<timestamp>.json` and update `results/latest.json`

Actual harness implementation is deferred — this MVP gives you the structure, schema, and labeled fixtures so a harness (Python script, GitHub Action, or a Claude Code loop) can be wired up without re-deciding the format.

## Targets

Baseline targets from `workflows/07-benchmark-and-cache.md`:

- Must Fix precision ≥ 90%
- Must Fix recall ≥ 80%
- FP rate on known-unreachable fixtures ≤ 10%
- Cache hit rate on unchanged re-run = 100%

## Adding a fixture

1. Pick a case that currently produces the wrong verdict (false positive or false negative in a real scan)
2. Minimize to the smallest reproducer — one entry point, one sink, the minimum intermediate code
3. Write `case.yaml` with the ground truth
4. Run the harness (once it exists) — confirm the case fails
5. Fix the skill — update prompts / detector config / suppression rules
6. Re-run — confirm it passes AND no other fixture regressed

Do not add fixtures for bugs that are already handled correctly unless they're genuinely new territory (new language, new framework, new CWE class).
