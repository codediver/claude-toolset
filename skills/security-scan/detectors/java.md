# Java Detector Suite

## Suite composition and rationale

| Tool | Why it's in the suite |
|---|---|
| **Semgrep** (`p/java`, `p/owasp-top-ten`, `p/jwt`, `p/secrets`) | Fast, custom-rule friendly. Catches OWASP Top 10 patterns, JWT misuse, hardcoded secrets. Good for org-specific rules. |
| **CodeQL** (`java-security-extended.qls`) | Best-in-class interprocedural taint for Java. Emits SARIF `codeFlows` with full source→sink traces that the validator consumes directly. Slow but worth it. |
| **SpotBugs + FindSecBugs** | Bytecode-level analysis catches deserialization (CWE-502), insecure crypto (CWE-327), XXE (CWE-611), and JSP-specific issues that AST tools miss. |
| **OWASP Dependency-Check** | CVE lookup for declared dependencies. Complements SAST with SCA coverage. |
| **Gitleaks** | Secret scanning across working tree + git history. Catches API keys, private keys, tokens. |

## Install commands

```bash
# Semgrep
pipx install semgrep

# CodeQL — download bundle from github/codeql-cli-binaries releases
# Extract and add to PATH

# SpotBugs + FindSecBugs — use Maven/Gradle plugin (preferred), no separate install

# OWASP Dependency-Check
brew install dependency-check   # macOS
# or download from owasp.org/www-project-dependency-check/

# Gitleaks
brew install gitleaks
```

## Known gaps

- **Reflection / dynamic proxies / ServiceLoader** — none of these tools fully resolve runtime-dispatched calls. The context bundle marks these as `unresolved_edges` so the validator downgrades confidence.
- **Framework-specific patterns** — Spring `@ModelAttribute` binding, `@RequestPart` multipart, WebFlux reactive taint. CodeQL handles most; custom Semgrep rules may be needed for org-specific wrappers.
- **Kotlin interop modules** — not in MVP scope. Warn and skip.
- **Build-time code generation** — MapStruct, Lombok, Immutables. Scan generated code at your peril; default suppression rules exclude `target/generated-sources/**`.

## Entry point detection cheat sheet

| Framework | Annotation / pattern | Notes |
|---|---|---|
| Spring MVC | `@RestController`, `@Controller`, `@*Mapping` | Most common |
| Spring WebFlux | `@RestController` with `Mono`/`Flux` return types | Taint model differs slightly |
| Spring Kafka | `@KafkaListener(topics=..., concurrency=N)` | Concurrency=1 means single-threaded |
| JMS | `@JmsListener` | Container-managed |
| Scheduled | `@Scheduled` | Default pool is single-threaded |
| Servlet | `extends HttpServlet` | `doGet`/`doPost` |
| JAX-RS | `@Path`, `@GET`, `@POST` | Less common in Spring shops |
| gRPC | `extends *ImplBase` | Generated base classes |

## Running

See [workflows/01-run-detectors.md](../workflows/01-run-detectors.md) for exact invocations.
