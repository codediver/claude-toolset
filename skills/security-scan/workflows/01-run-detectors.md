# 01 — Run Detectors

**Goal:** Run the Java SAST suite and write raw outputs to `security-scan-report/raw-findings/`.

## Tools and invocations

Run in parallel where practical. All tools emit SARIF where supported.

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

### OWASP Dependency-Check
```bash
dependency-check --scan . --format SARIF --out security-scan-report/raw-findings/dependency-check.sarif
```
CVE lookup for declared dependencies.

### Gitleaks
```bash
gitleaks detect --source . --report-format sarif \
  --report-path security-scan-report/raw-findings/gitleaks.sarif --no-banner
```
Secret detection across the git history.

## Error handling

- If a tool is missing, log a warning in `security-scan-report/tool-status.json` and continue. Do NOT fail the whole scan.
- If a tool hangs (>30 min for CodeQL, >10 min for others), kill and record as `timeout`. The triage layer treats a missing detector as reduced coverage, not zero coverage.
- If a tool errors mid-run, preserve partial output and record `partial` status.

## Write versions.lock

Capture exact versions used so results reproduce:
```json
{
  "semgrep": "1.xx.x",
  "codeql": "2.xx.x",
  "codeql_queries_pack": "codeql/java-queries@x.y.z",
  "spotbugs": "4.x.x",
  "findsecbugs": "1.13.0",
  "dependency_check": "10.x.x",
  "gitleaks": "8.x.x",
  "claude_model": "claude-opus-4-6"
}
```
