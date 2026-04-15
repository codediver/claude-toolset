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

- Use **JavaParser** (or `javaparser-symbol-solver-core`) to build a symbol table across source roots
- Start from the sink method, walk **reverse** call edges up to N levels
- For each edge that can't be resolved (reflection, `Method.invoke`, dynamic proxy, `ServiceLoader`, Spring `@Autowired` by interface with multiple impls), push an entry to `unresolved_edges` with a reason — do NOT silently drop
- For Spring DI by interface with a single impl, resolve it; with multiple impls, include all and mark ambiguous

### Entry-point reachability

- For each terminal caller in the slice, check the inventory's entry_points list (from workflow 00). If a match, add to `entry_points_reached` with the full chain and request binding.
- If a terminal caller is not an entry point but is public API of the module (e.g., a library method), mark as `library-boundary` and include the public signature — the triage treats this as "depends on downstream usage".

### Concurrency signals

Specifically for concurrency/race CWEs:
- Check the call chain for `@Async`, `CompletableFuture.supplyAsync`, `ExecutorService.submit`, `ForkJoinPool`, manual `new Thread`
- Check the outermost entry point for container-managed concurrency: `@KafkaListener(concurrency=N)`, Tomcat default (multi-threaded), `@Scheduled` (single-threaded per default pool)
- Record explicit signals so the validator can rule out races when all callers are single-threaded

### Taint source details

If the entry point binds user input (e.g., `@RequestBody CreateReq req`), extract the field types and any validation annotations (`@Valid`, `@Pattern`, `@Size`, custom validators). The validator uses these to check whether the tainted path is actually validated before reaching the sink.

## Scale & caching

- Cache bundles by `sha256(finding_fingerprint + source_files_hashes_on_path)` in `.security-scan-cache/bundles/`
- Only rebuild when a file on the chain changes
- Bundles can get large — truncate method bodies at 400 lines with a marker; callgraph walking stops at depth N regardless

## Output

`security-scan-report/context-bundles/{finding_id}.json` — one file per finding.
