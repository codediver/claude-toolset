# Cross-Service Flow Classification Prompt

**System:** You are classifying whether a security finding in service **B** is reachable from an **untrusted public entry point** in some upstream service. You will be given:
- The finding + its context bundle in service B (already classified `reachable-*` locally)
- The service graph subgraph reachable from B's entry point, up to the hop limit
- Each upstream service's relevant entry points and the specific call-site that reaches B

Your job: decide if there is a complete, untrusted-source-to-sink path across service boundaries.

Temperature: 0. Output: JSON matching the schema below, nothing else.

## Your task

Walk the subgraph upstream from service B's entry point. For each hop:

1. Does the upstream caller send attacker-controlled data to service B? (Look at the call site — is the payload derived from `req.body`, a query string, or hardcoded/trusted?)
2. Is the upstream caller reachable from its own public entry point, or is it internal-only?
3. Is there validation or sanitization at the boundary (request-body schema, allow-list, etc.) that narrows taint before it reaches B?

Stop walking when you reach:
- A public entry point (terminate with `reachable-exploitable`)
- A trusted-input source with strong validation (terminate with `unreachable` or `reachable-conditional`)
- An external boundary (third-party API, unmapped service — terminate with `external-boundary`)
- The hop limit (terminate with `insufficient-context`)
- A cycle (use the already-computed classification for the repeated node)

## Hard rules

1. **Evidence chain must span service boundaries.** Each step quotes source lines from the service it names. Service boundary transitions are explicit steps (e.g., "service A calls http://b.internal/foo via RestTemplate").
2. **Every `unreachable` verdict requires quoted evidence of validation/sanitization at some upstream boundary.** Without it, downgrade to `insufficient-context`.
3. **External boundaries are never automatically safe.** A finding reached via a Stripe webhook handler is still Must Fix material if Stripe signatures aren't verified.
4. **Assumptions about auth semantics must be explicit.** Don't assume a JWT is validated just because it's attached; quote the validation code.
5. **Unmapped service edges downgrade confidence.** If a caller couldn't be identified in scope, the path is incomplete.

## Output schema

```json
{
  "finding_id": "string",
  "cross_service_classification": "reachable-exploitable | reachable-conditional | unreachable | insufficient-context | external-boundary",
  "confidence": "high | medium | low",
  "entry_point_ultimate": {
    "service": "string",
    "type": "http-public | http-authn | grpc | scheduled | cli | external-third-party | unmapped",
    "path": "string (if HTTP)",
    "auth_required": true | false
  },
  "hop_count": 2,
  "cycle_detected": false,
  "evidence_chain": [
    {
      "step": 1,
      "service": "string",
      "claim": "string",
      "file": "string",
      "lines": [start, end],
      "quote": "exact source text"
    }
  ],
  "assumptions": ["string"],
  "unmapped_edges_on_path": ["string"],
  "preconditions": ["string"]
}
```

## Example: cross-service exploitable

```json
{
  "finding_id": "xyz-123",
  "cross_service_classification": "reachable-exploitable",
  "confidence": "high",
  "entry_point_ultimate": {
    "service": "public-api",
    "type": "http-public",
    "path": "/submit",
    "auth_required": false
  },
  "hop_count": 2,
  "cycle_detected": false,
  "evidence_chain": [
    { "step": 1, "service": "public-api", "claim": "Public unauthenticated endpoint",
      "file": "public-api/src/main/java/Controller.java", "lines": [10, 12],
      "quote": "@PostMapping(\"/submit\") public Resp submit(@RequestBody Payload p) {" },
    { "step": 2, "service": "public-api", "claim": "Payload forwarded unchanged to orders-api",
      "file": "public-api/src/main/java/Controller.java", "lines": [14, 15],
      "quote": "restTemplate.postForObject(\"http://orders.internal/internal/order\", p, Resp.class);" },
    { "step": 3, "service": "orders-api", "claim": "Internal endpoint consumes payload",
      "file": "orders-api/src/main/java/OrderApi.java", "lines": [20, 23],
      "quote": "@PostMapping(\"/internal/order\") Order create(@RequestBody Payload p) { return repo.find(p.name()); }" },
    { "step": 4, "service": "orders-api", "claim": "Name concatenated into SQL",
      "file": "orders-api/src/main/java/Repo.java", "lines": [42, 43],
      "quote": "String sql = \"SELECT * FROM orders WHERE name = '\" + name + \"'\";" }
  ],
  "assumptions": ["No WAF in front of public-api"],
  "unmapped_edges_on_path": [],
  "preconditions": []
}
```
