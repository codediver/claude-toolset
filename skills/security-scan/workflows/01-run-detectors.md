# 01 — Run Detectors

**Goal:** Run the language-appropriate SAST suite(s) and write raw outputs to `security-scan-report/raw-findings/`.

Dispatch rule: for each language in `inventory.json.languages`, run that language's detector suite. Common tools (osv-scanner, Gitleaks) run once across the whole repo.

Per-language invocation details: [`detectors/java.md`](../detectors/java.md) · [`detectors/node.md`](../detectors/node.md) · [`detectors/python.md`](../detectors/python.md). What follows is the universal tool set plus Java specifics; see the Node/Python detector files for those invocations.

## Universal tools (run once per repo regardless of language)

### osv-scanner (SCA — preferred default)
```bash
osv-scanner --lockfile=pom.xml --lockfile=package-lock.json --lockfile=requirements.txt \
  --lockfile=poetry.lock --lockfile=Pipfile.lock --lockfile=uv.lock \
  --format=sarif . > security-scan-report/raw-findings/osv-scanner.sarif
```
- Needs no API key, uses osv.dev, covers Maven/Gradle/npm/PyPI/Go/Rust/etc. from lockfiles
- **Prefer over OWASP Dependency-Check** — the latter requires an NVD API key or hits HTTP 429 on the public endpoint and aborts (verified 2026-04-15)
- Fall back to `dependency-check --nvdApiKey $NVD_API_KEY ...` only if the user has an NVD key configured and explicitly needs Dependency-Check's SARIF dialect

### Gitleaks (secret scan)
```bash
gitleaks detect --source . --report-format sarif \
  --report-path security-scan-report/raw-findings/gitleaks.sarif --no-banner
```
Scans working tree + git history. Always run.

## Java (run if `java` in inventory)

Tools and invocations follow. Run in parallel where practical. All emit SARIF where supported.

### Semgrep
```bash
semgrep scan \
  --config p/java --config p/owasp-top-ten --config p/jwt --config p/secrets \
  --sarif --output security-scan-report/raw-findings/semgrep.sarif \
  --metrics=off .
```
Fast, custom-rule friendly. Pin version in `versions.lock`.

### CodeQL
```bash
# 1. Create DB (cache in .codeql-db/)
codeql database create .codeql-db --language=java --overwrite \
  --command="mvn -B -DskipTests package"   # or Gradle equivalent

# 2. Analyze with the security-extended suite
codeql database analyze .codeql-db \
  codeql/java-queries:codeql-suites/java-security-extended.qls \
  --format=sarif-latest \
  --output=security-scan-report/raw-findings/codeql.sarif
```
Slowest but strongest interprocedural taint. Cache DB between runs; rebuild only when source changes.

### SpotBugs + FindSecBugs
```bash
# Via Maven plugin (preferred) or CLI
mvn -B com.github.spotbugs:spotbugs-maven-plugin:check \
  -Dspotbugs.plugins=com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0 \
  -Dspotbugs.sarifOutput=true \
  -Dspotbugs.sarifOutputPath=security-scan-report/raw-findings/spotbugs.sarif
```
Bytecode-level — catches deserialization, crypto misuse, XXE that AST tools miss.

### (Dependency-Check — only with NVD_API_KEY)

See the universal osv-scanner invocation above for the default SCA tool. Dependency-Check is kept as an option for teams with an NVD API key:
```bash
dependency-check --nvdApiKey "$NVD_API_KEY" --scan . --format SARIF \
  --out security-scan-report/raw-findings/dependency-check.sarif
```
Without `NVD_API_KEY`, the public NVD endpoint will rate-limit and the scan aborts.

## Node/TypeScript (run if `node` in inventory)

See [`detectors/node.md`](../detectors/node.md). Summary:
```bash
semgrep scan --config p/javascript --config p/typescript --config p/nodejs \
  --config p/owasp-top-ten --config p/secrets \
  --sarif --output security-scan-report/raw-findings/semgrep-node.sarif --metrics=off .

# eslint-plugin-security — if configured in repo
npx eslint --format json -o security-scan-report/raw-findings/eslint-security.json . || true

# npm audit (json mode) — osv-scanner usually supersedes this but keep for defense in depth
npm audit --json > security-scan-report/raw-findings/npm-audit.json || true
```

## Python (run if `python` in inventory)

See [`detectors/python.md`](../detectors/python.md). Summary:
```bash
semgrep scan --config p/python --config p/django --config p/flask \
  --config p/owasp-top-ten --config p/secrets \
  --sarif --output security-scan-report/raw-findings/semgrep-python.sarif --metrics=off .

bandit -r . -f sarif -o security-scan-report/raw-findings/bandit.sarif -q || true

pip-audit --format=sarif --output=security-scan-report/raw-findings/pip-audit.sarif || true
```

## IaC (run if `iac` in inventory)

See [`detectors/iac.md`](../detectors/iac.md). Summary:
```bash
trivy config . --format sarif --output security-scan-report/raw-findings/trivy-config.sarif
checkov -d . -o sarif --output-file security-scan-report/raw-findings/checkov.sarif --quiet || true
semgrep scan --config p/terraform --config p/dockerfile --config p/kubernetes \
  --sarif --output security-scan-report/raw-findings/semgrep-iac.sarif --metrics=off .

# Optional, per file type present:
find . -name "Dockerfile*" -not -path "*/node_modules/*" | xargs hadolint --format sarif \
  > security-scan-report/raw-findings/hadolint.sarif 2>/dev/null || true
kube-score score --output-format json $(find . -name "*.yaml" | xargs grep -l "^kind:" 2>/dev/null) \
  > security-scan-report/raw-findings/kube-score.json 2>/dev/null || true
```

## Container (run if `container` in inventory AND `--scan-image` supplied)

See [`detectors/container.md`](../detectors/container.md). Summary:
```bash
# Dockerfile-only (default — no build required)
trivy config Dockerfile --format sarif --output security-scan-report/raw-findings/trivy-dockerfile.sarif

# Image scan (only when user passes --scan-image <tag> or asks to build)
trivy image --format sarif --output security-scan-report/raw-findings/trivy-image.sarif \
  --scanners vuln,secret,misconfig --severity HIGH,CRITICAL "$IMAGE_TAG"
```

## Error handling

- If a tool is missing, log a warning in `security-scan-report/tool-status.json` and continue. Do NOT fail the whole scan.
- If a tool hangs (>30 min for CodeQL, >10 min for others), kill and record as `timeout`. The triage layer treats a missing detector as reduced coverage, not zero coverage.
- If a tool errors mid-run, preserve partial output and record `partial` status.

## Write versions.lock

Capture exact versions used so results reproduce. Only record the tools that actually ran.
```json
{
  "semgrep": "1.xx.x",
  "codeql": "2.xx.x (or omitted if not installed)",
  "osv_scanner": "2.x.x",
  "gitleaks": "8.x.x",
  "spotbugs": "4.x.x",
  "findsecbugs": "1.13.0",
  "bandit": "1.x.x",
  "pip_audit": "2.x.x",
  "eslint_security": "3.x.x",
  "claude_model": "claude-opus-4-6"
}
```
