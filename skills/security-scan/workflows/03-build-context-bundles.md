# 03 — Build Context Bundles

**Goal:** For each non-suppressed finding, produce a deterministic `context_bundle` the validator can reason over without guessing. This is the most important phase for FP suppression.

Schema: [`schemas/context-bundle.schema.json`](../schemas/context-bundle.schema.json).

## What the bundle contains

```json
{
  "finding_id": "...",
  "sink": {
    "file": "...",
    "method_signature": "com.example.Repo#find(String)",
    "lines": [40, 60],
    "code": "...full method body..."
  },
  "callers": [
    {
      "depth": 1,
      "method_signature": "com.example.Service#search(String)",
      "file": "...",
      "lines": [12, 30],
      "code": "...",
      "call_site_line": 22
    }
    // ... up to depth N (default 5)
  ],
  "entry_points_reached": [
    {
      "type": "http-public",
      "file": "...",
      "method_signature": "com.example.Api#search(String)",
      "path": "/api/search",
      "http_method": "GET",
      "auth_required": false,
      "request_binding": [{ "name": "q", "type": "String", "source": "@RequestParam" }],
      "call_chain": ["Api#search", "Service#search", "Repo#find"]
    }
  ],
  "unresolved_edges": [
    { "at": "Service#search:18", "reason": "reflective invocation via Method.invoke" }
  ],
  "taint_from_tool": [ /* data_flow copied from finding if present */ ],
  "concurrency_signals": {
    "annotations": ["@Async on Service#search"],
    "executors_used": ["ForkJoinPool.commonPool in Service:L25"],
    "container_concurrency": "@KafkaListener concurrency=3 on entry point X"
  }
}
```

## How to build it

### Callgraph slice (depth N=5)

Walk **reverse** call edges from the sink up to N levels (default 5). For each edge that can't be resolved, push to `unresolved_edges` with a reason — do NOT silently drop.

**Per-language tooling:**

| Language | Callgraph tool | Unresolved-edge triggers |
|---|---|---|
| Java | JavaParser + `javaparser-symbol-solver-core` | reflection, `Method.invoke`, dynamic proxy, `ServiceLoader`, `@Autowired` by interface with multiple impls (include all, mark ambiguous) |
| Node / TS | `ts-morph` (TS projects), `@babel/parser` + `@babel/traverse` (plain JS) | dynamic `require(var)` / `import(var)`, `fn.apply`/`fn.call` with variable `fn`, `eval`, `new Function`, prototype-chain dispatch with unknown concrete type, monkey-patched library methods |
| Python | `jedi` (preferred) or `rope`; `ast` + manual symbol table as fallback | `getattr(obj, varname)(...)` dynamic dispatch, duck-typed polymorphism without type hints, metaclass/decorator plugin registries, `**kwargs` forwarding that loses parameter identity, lazy/conditional imports |

**Framework-implicit edges** (all languages) — the callgraph must include framework invocations that aren't explicit source code calls:
- Java: Spring `@KafkaListener`, `@Scheduled`, filters, interceptors
- Node: Express middleware chain (`app.use` calls before the route), Nest guards, Next.js `middleware.ts`
- Python: Django signals (`pre_save`, `post_save`), Flask `before_request`, FastAPI middleware, DRF `perform_create`

### Entry-point reachability

- For each terminal caller in the slice, check the inventory's entry_points list (from workflow 00). If a match, add to `entry_points_reached` with the full chain and request binding.
- If a terminal caller is not an entry point but is public API of the module (e.g., a library method), mark as `library-boundary` and include the public signature — the triage treats this as "depends on downstream usage".

### Concurrency signals

Specifically for concurrency/race CWEs:

**Java:** `@Async`, `CompletableFuture.supplyAsync`, `ExecutorService.submit`, `ForkJoinPool`, manual `new Thread`; container-managed — `@KafkaListener(concurrency=N)`, Tomcat (multi-threaded by default), `@Scheduled` (single-threaded default pool).

**Node/TS:** concurrency is cooperative per-event-loop by default (single threaded). But: `worker_threads`, `cluster`, multi-process PM2 / Docker replicas, and — critically — **async race on shared mutable state between awaits** (the most common Node race). Flag when module-level mutable state is read/written around `await` boundaries. Also: BullMQ / Kafka.js consumers with `concurrency > 1`.

**Python:** GIL makes CPython bytecode mostly single-threaded, but races still occur across yield points in asyncio and around IO in `threading`. Check for: `threading.Thread`, `concurrent.futures.ThreadPoolExecutor`/`ProcessPoolExecutor`, `asyncio.gather`/`asyncio.create_task`, Celery worker concurrency (`--concurrency=N`), gunicorn/uvicorn worker count. Module-level mutable state under asyncio is a common false-negative area.

Record explicit signals so the validator can rule out races when all callers are demonstrably single-threaded.

### Taint source details

Extract request binding + validation metadata at the entry point. The validator uses these to check whether the tainted path is actually validated before reaching the sink.

**Java (Spring):** `@RequestBody`, `@RequestParam`, `@PathVariable`, `@ModelAttribute`, `@RequestPart`. Validators: `@Valid`, `@Pattern`, `@Size`, `@NotNull`, custom `ConstraintValidator`.

**Node/TS:**
- Express/Koa/Fastify: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies` — each is a distinct source
- Nest: `@Body() dto: Dto`, `@Query(...)`, `@Param(...)` — class-validator decorators (`@IsEmail`, `@Length`) or custom pipes = validation evidence
- Next.js: `req.body`/`req.query` (pages) or `request.json()` / `request.nextUrl.searchParams` (app)
- Validation libs recognized: Zod `.parse()`, Yup `.validate()`, Valibot `parse()`, Joi `.validate()`, ajv, class-validator

**Python:**
- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.headers`, url kwargs
- DRF: `self.request.data`; `serializer.validated_data` = validated (taint narrowed for fields with validators)
- Flask: `request.args`, `request.form`, `request.json`, `request.files`
- FastAPI: function-parameter-bound with `Query`/`Body`/`Path`/`Header`; Pydantic-validated types narrow taint for typed fields (not `Any`/`Dict[str, Any]`)
- Validation libs: Pydantic, marshmallow, cerberus, django-rest-framework serializers

## Scale & caching

- Cache bundles by `sha256(finding_fingerprint + source_files_hashes_on_path)` in `.security-scan-cache/bundles/`
- Only rebuild when a file on the chain changes
- Bundles can get large — truncate method bodies at 400 lines with a marker; callgraph walking stops at depth N regardless

## Output

`security-scan-report/context-bundles/{finding_id}.json` — one file per finding.
