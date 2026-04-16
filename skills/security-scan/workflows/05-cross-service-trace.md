# 05 — Cross-Service Flow Tracing

**Goal:** For findings whose local entry point is an **internal** consumer (private HTTP, Kafka, JMS, SQS), trace the flow upstream across service boundaries to determine whether the path ultimately originates from a public entry point.

A finding reachable only from an internal message consumer or private API is much less severe than the same finding reachable from a public unauthenticated endpoint — but most SAST tools cannot tell the difference. Phase 5 bridges that gap.

## When this workflow runs

Invoked by `workflows/04-validate-findings.md` **only** when all of:
- Finding's classification is `reachable-*` (not `unreachable` / `insufficient-context`)
- Entry point type is internal (`http-internal`, `kafka`, `jms`, `sqs`, `grpc-internal`)
- User supplied a scope wider than a single repo (see "Scope" below)

If scope is single-repo, skip this workflow and treat internal entry points per the triage rules in `workflows/06`.

## Scope

The user tells the skill which repos to consider together:

```bash
# Single scope file at the invoking project root
# .security-scan-scope.yaml
scope:
  - id: orders-api
    path: /abs/path/to/orders-api
  - id: billing-api
    path: /abs/path/to/billing-api
  - id: payments-api
    path: /abs/path/to/payments-api
  - id: notification-worker
    path: /abs/path/to/notification-worker
```

Or CLI: `/security-scan --scope orders-api:/path,billing-api:/path`.

Each scoped repo runs Phase 00–04 independently and writes its own `security-scan-report/`. Phase 5 reads every repo's inventory + findings and unifies them.

## Step 1 — Build the service graph

Output: `security-scan-report/service-graph.json` (global, at the invocation root or user-specified path).

Schema: [`schemas/service-graph.schema.json`](../schemas/service-graph.schema.json).

For each service in scope, read its `inventory.json` and extract:

### Public entry points (nodes)
Already captured during Phase 00. Tag each with `is_public = auth_required == false && type in {http-public, grpc}`.

### Outbound edges

**HTTP (per language):**

| Language | How to extract |
|---|---|
| Java | `RestTemplate`, `WebClient`, `FeignClient` (with `@FeignClient(name=...)` → direct service name hint), `HttpClient`, `OkHttp`. Pull URL literals, `@RequestMapping`-style constants, environment-variable references (`@Value("${billing.url}")`). |
| Node/TS | `axios`, `fetch`, `got`, `node-fetch`, tRPC client, OpenAPI-generated clients. Same URL-literal extraction. |
| Python | `requests`, `httpx`, `aiohttp`, service-specific SDKs. |

For each outbound call, record: caller file/line, URL pattern (may contain `${var}` placeholders), HTTP method. Try to resolve `${var}` via `application.properties` / `.env` / `values.yaml`.

**Async (per language):**
- Java: Kafka producers via `KafkaTemplate.send(topic, ...)`, JMS `JmsTemplate.convertAndSend`, SQS `SqsTemplate.send`
- Node: `kafkajs` producer, BullMQ `queue.add`, SQS SDK `SendMessageCommand`
- Python: `confluent-kafka` / `aiokafka` producer, `celery.send_task`, boto3 SQS

Record: topic/queue name, message schema (if known — Avro/Protobuf/JSON Schema file).

### Resolving edges (service A calls service B)

**By OpenAPI:** look for `openapi.yaml` / `swagger.yaml` / `openapi.json` in each service. If found, parse `paths` and `servers[].url`. Match outbound URL pattern to the servers URL prefix + paths.

**By Feign / client stubs:** `@FeignClient(name = "billing-api")` directly names the target service. Match to the service with that `spring.application.name` in its config.

**By URL hostname:** outbound `http://billing.internal/...` → find the service whose inventory lists a public HTTP entry with matching path. Hostname-to-service mapping can be:
- Explicit (user provides `services.yaml` with `hostname: orders.internal`)
- Inferred from Kubernetes `Service` definitions / Docker Compose service names / Helm values.yaml if available in the repo

**By Kafka topic:** producer of topic `X` in service A + `@KafkaListener(topics = "X")` in service B = edge.

**By schema registry:** Confluent / AWS Glue schema subject names can disambiguate topic flows when multiple producers/consumers share names.

### Unresolved edges

When an outbound URL can't be matched to any in-scope service, mark as `external-boundary`:
- Third-party API (Stripe, Twilio, etc.) — `external-third-party`
- Service outside scope — `external-unmapped` (user may have missed a repo)
- Dynamic URL construction — `external-dynamic`

The triage layer treats `external-unmapped` as Should Fix with a note to expand scope.

## Step 2 — Classify each internal finding

For each finding where Phase 4 produced a `reachable-*` verdict with an internal entry point:

1. Look up the finding's entry point in the service graph
2. Find incoming edges — who sends to this topic / calls this internal API?
3. Recurse: for each upstream service, is the upstream caller reached from a public entry point?

Prompt: [`prompts/cross-service-prompt.md`](../prompts/cross-service-prompt.md).

### Termination conditions (in order)

1. **Public entry point reached** → finding classification upgraded to match: if `reachable-exploitable` locally AND reached from public, stays `reachable-exploitable` with evidence chain extended across services. **Must Fix** in triage.
2. **Trusted internal source reached with validated input** → classification downgraded to `reachable-conditional` or `unreachable`, depending on validation strength. **Should Fix** or **Info**.
3. **External boundary hit** → `reachable-conditional` with `external-boundary` precondition. **Should Fix**.
4. **Hop limit (default 3) exceeded** → `insufficient-context` with note. **Should Fix**.
5. **Cycle detected** (service A → B → A) → don't loop; treat the cycle as reaching the already-classified entry point.

## Step 3 — Emit cross-service evidence chain

The triage report's evidence chain for cross-service findings spans multiple services. Example structure:

```json
"evidence_chain": [
  { "step": 1, "service": "public-api", "claim": "Public endpoint POST /submit (no auth)", "file": "...", "lines": [10,12], "quote": "..." },
  { "step": 2, "service": "public-api", "claim": "Payload forwarded to orders-api via RestTemplate.post", "file": "...", "lines": [42,43], "quote": "..." },
  { "step": 3, "service": "orders-api", "claim": "Internal endpoint POST /internal/orders receives payload unchanged", "file": "...", "lines": [18,22], "quote": "..." },
  { "step": 4, "service": "orders-api", "claim": "Payload flows to SQL concat in Repo.search", "file": "...", "lines": [78,79], "quote": "..." }
]
```

Each step names its service. The report renderer should group and visually separate service boundaries.

## Caching

Cross-service verdicts cache by:
```
sha256(finding_fingerprint + service_graph_subgraph_hash + prompt_hash + model_id)
```
where `service_graph_subgraph_hash` is the hash of the subgraph reachable from the finding's entry point within the hop limit. Any service in that subgraph changing its inventory invalidates the cache entry.

## Scale and cost

- Cost scales with: `(# findings with internal entry points) × (avg. upstream fanout) × (hop limit)`
- Default hop limit = **3**. Configurable via `--max-hops`.
- Large meshes (> 20 services in scope) — emit a warning and suggest narrowing scope to services connected to findings.
- Parallelize: each finding's cross-service trace is independent.

## What Phase 5 does NOT do

- **No runtime call inspection** — static contract mapping only. If service A calls service B at runtime but the URL is constructed from a database value, the edge is `external-dynamic`.
- **No spec-free inference of auth on internal edges** — if the caller attaches a JWT but the target service doesn't validate it (or vice versa), Phase 5 may miss the gap. Report authentication semantics as assumptions, not conclusions.
- **No mesh / service-mesh policy parsing** (Istio, Linkerd, Consul). Phase E material if ever needed.
