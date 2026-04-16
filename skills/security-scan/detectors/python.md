# Python Detector Suite

## Suite composition and rationale

| Tool | Why it's in the suite |
|---|---|
| **Semgrep** (`p/python`, `p/django`, `p/flask`, `p/owasp-top-ten`, `p/secrets`) | Broad Python coverage: `subprocess.*` with shell=True, `pickle.loads`, `yaml.load` (unsafe), Jinja autoescape, SQLAlchemy `text(...)` concat, Django ORM `.raw(...)` injection, hardcoded secrets. |
| **Bandit** | Python-AST-native, well-tuned for Python idioms. Catches `assert` in production code (CWE-703), weak hashes (`hashlib.md5`), `exec`/`eval`, `tempfile.mktemp`, SSL verification disabled. Complements Semgrep. |
| **CodeQL** (`python-security-extended.qls`, optional) | Interprocedural taint — best for large Django/Flask apps where request data flows deep through services. Slower; skip for small projects. |
| **osv-scanner** (SCA, default) | Reads `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock` → CVE list via osv.dev. |
| **pip-audit** (defense-in-depth) | Official PyPA tool; queries osv.dev + PyPI advisories. Occasional diffs vs osv-scanner. |
| **Gitleaks** | Secret scanning (universal). |

## Install commands

```bash
# Semgrep
pipx install semgrep

# Bandit
pipx install bandit

# CodeQL — download bundle from github/codeql-cli-binaries releases

# osv-scanner
brew install osv-scanner

# pip-audit
pipx install pip-audit
```

## Running

```bash
# Semgrep
semgrep scan \
  --config p/python --config p/django --config p/flask \
  --config p/owasp-top-ten --config p/secrets \
  --sarif --output security-scan-report/raw-findings/semgrep-python.sarif \
  --metrics=off .

# Bandit
bandit -r . -f sarif -o security-scan-report/raw-findings/bandit.sarif -q || true

# CodeQL (optional)
codeql database create .codeql-db-py --language=python --overwrite
codeql database analyze .codeql-db-py \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest \
  --output=security-scan-report/raw-findings/codeql-python.sarif

# pip-audit
pip-audit --format=sarif --output=security-scan-report/raw-findings/pip-audit.sarif || true
```

## Entry-point detection cheat sheet

| Framework | Signal | Notes |
|---|---|---|
| Django | `urls.py` → `urlpatterns = [path("...", view, ...), ...]`; views are `def view(request)` or class-based (`View`, `TemplateView`, etc.) | Auth: `@login_required`, `@permission_required`, `LoginRequiredMixin`; DRF `permission_classes` |
| DRF | `ViewSet` / `APIView` classes with `@action` methods; routers via `DefaultRouter` | `permission_classes = [IsAuthenticated]` etc. |
| Flask | `@app.route(...)`, `@blueprint.route(...)` | Auth typically via `@login_required` or custom decorator — capture decorator chain |
| FastAPI | `@app.get/post/...`, path operation functions | `Depends(get_current_user)` = auth; Pydantic models = validated input |
| Starlette / Quart | `@app.route`, class-based endpoints | — |
| Celery | `@app.task`, `@shared_task` | Async worker entry; check `rate_limit`, `bind=True` |
| AWS Lambda | `def lambda_handler(event, context)` or name set in `serverless.yml` / `sam.yaml` | Public URL from API Gateway config |
| Click / Typer | `@click.command`, `@typer.command`, `@app.command` | CLI entry |

## Taint source extraction

- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.headers`, `request.COOKIES`, url kwargs — all taint sources
- DRF: `self.request.data`, `serializer.validated_data` (validated = taint narrowed if validators run), query/path kwargs
- Flask: `request.args`, `request.form`, `request.json`, `request.files`, `request.headers`, `request.cookies`
- FastAPI: function parameters bound via `Query`/`Body`/`Path`/`Header` — Pydantic-validated types = taint narrowed for schema-enforced fields but not for `Any`/`Dict[str, Any]`
- Celery: task args — usually from internal broker, trust level depends on deployment

## Callgraph extraction (for context bundles)

- **jedi** — reference resolution library used by IDE plugins; best for walking call edges by symbol
- **rope** — alternative with refactoring support
- **ast + manual symbol table** — cheapest fallback for small codebases; miss decorators and dynamic dispatch
- For Django: resolve `urls.py` → view callable using `django.urls.resolve` semantics (match `path()` strings to imports)

Walk reverse call edges from the sink. Mark as `unresolved_edges` when:
- `getattr(obj, varname)(...)` — dynamic attribute dispatch
- Duck-typed polymorphism — only one of several implementations is reachable, can't tell which
- Metaclass or decorator-based registration (plugin systems)
- `**kwargs` forwarding many hops deep — parameter identity lost

## Known gaps

- **Dynamic everything** — Python's `getattr`/`setattr`/`exec`/`eval` defeats static analysis. Bandit flags direct `eval`/`exec` calls; deeper dynamic dispatch is `unresolved`.
- **Duck typing** — without type annotations, `obj.method()` could resolve to any class with `method`. Prefer type-annotated code for clean callgraphs.
- **Lazy imports / conditional imports** — `if TYPE_CHECKING` blocks and runtime imports hide edges.
- **Framework magic** — Django signals, Flask `before_request`, FastAPI middleware — implicit callers the tools may miss. Record framework-implicit edges in the context bundle (e.g., "pre_save signal handler invoked on Model.save()").

## Ecosystem-specific notes

- **Virtual envs** — skip `.venv/`, `venv/`, `env/`, `site-packages/` (covered in `rules/suppression-rules.yaml`).
- **Monorepos / uv workspaces** — treat each `pyproject.toml` package as a module.
- **Poetry vs pip-tools vs uv vs PDM** — osv-scanner supports all lockfile formats; point it at whichever lockfile is committed.
- **Django settings leaks** — scan `settings.py` and `settings/*.py` specifically for `SECRET_KEY`, `DATABASES`, `DEBUG=True` in non-dev contexts.
