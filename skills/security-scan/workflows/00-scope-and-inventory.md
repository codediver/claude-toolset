# 00 — Scope and Inventory

**Goal:** Produce `security-scan-report/inventory.json` describing the project: modules, languages, frameworks, entry points, external integrations. Everything downstream depends on this.

## Steps

### 1. Detect languages

Scan for language signals at the repo root and one level down:

| Layer | Build/manifest files | Source signal |
|---|---|---|
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle*` | `src/main/java/**/*.java` |
| Node/TS | `package.json`, `pnpm-lock.yaml`, `yarn.lock`, `tsconfig.json` | `**/*.{js,mjs,cjs,ts,tsx,jsx}` (excluding `node_modules`) |
| Python | `pyproject.toml`, `requirements*.txt`, `setup.py`, `Pipfile`, `poetry.lock`, `uv.lock` | `**/*.py` (excluding `.venv`, `venv`, `site-packages`) |
| IaC | `*.tf`, `*.tfvars`, `Chart.yaml`, `kustomization.yaml`, `docker-compose.yml`, `playbook.yml`, CFN templates | K8s manifests: YAML containing `apiVersion:` + `kind:` at root |
| Container | `Dockerfile`, `Dockerfile.*`, `.dockerfile` | — (image scanning is opt-in via `--scan-image`) |

A monorepo may have multiple layers — run each applicable adapter. IaC and container layers are **additive** to language layers: a Java + Terraform + Dockerfile repo gets all three suites.

If no supported layer is detected, stop and tell the user: "This skill supports Java, Node.js/TypeScript, Python, IaC (Terraform/K8s/CFN/Docker Compose/Helm), and containers (Dockerfile). Detected: {list}. For other languages, Rust/Go/Ruby/PHP adapters are deferred."

Per-layer detector guides:
- Code: [`detectors/java.md`](../detectors/java.md) · [`detectors/node.md`](../detectors/node.md) · [`detectors/python.md`](../detectors/python.md)
- Infra: [`detectors/iac.md`](../detectors/iac.md) · [`detectors/container.md`](../detectors/container.md)

### 2. Enumerate modules (per language)

- Maven: parse `<modules>` in root `pom.xml`, recurse
- Gradle: parse `settings.gradle*` for `include(...)` entries
- Record module name, path, Java version (from `<maven.compiler.source>` / `sourceCompatibility`), primary framework(s)

### 3. Detect frameworks

Grep/scan for the following to classify each module:

| Framework | Signal |
|---|---|
| Spring Boot | `spring-boot-starter*` in deps, `@SpringBootApplication` |
| Spring MVC/WebFlux | `spring-webmvc` / `spring-webflux`, `@RestController`, `@Controller` |
| Kafka | `spring-kafka` / `kafka-clients`, `@KafkaListener` |
| JMS | `spring-jms`, `@JmsListener` |
| Scheduling | `@Scheduled`, `@EnableScheduling` |
| JPA | `spring-data-jpa`, `@Entity`, `@Repository` |
| Servlets (plain) | `javax.servlet` / `jakarta.servlet`, `HttpServlet` |

### 4. Enumerate entry points

Entry points are where untrusted input enters the system. Language-specific patterns:

**Java (Spring / JAX-RS / servlets):**
- `@RestController` / `@Controller` classes → list handler methods (`@GetMapping`, `@PostMapping`, `@RequestMapping`, etc.) with paths, HTTP methods, Spring Security annotations (`@PreAuthorize`, `@Secured`, `@RolesAllowed`)
- `@KafkaListener` / `@JmsListener` / `@RabbitListener` → topic/queue, concurrency setting
- `@Scheduled` methods → cron/fixed-rate
- Plain servlets — classes extending `HttpServlet`
- `public static void main(String[] args)` — CLI
- gRPC — classes extending generated `*ImplBase`

**Node/TypeScript:**
- Express: `app.get/post/...`, `router.*`, `app.use` middleware chains — record route + auth middleware chain
- Fastify: `fastify.get/post/...`, `fastify.route({...})` — check `onRequest`/`preHandler` hooks for auth
- NestJS: `@Controller`, `@Get/Post/...`, `@UseGuards` for auth
- Koa: `router.get/post/...`, `app.use`
- Next.js: files under `pages/api/**` or `app/**/route.{js,ts}` — all exported HTTP methods
- Serverless: AWS Lambda `exports.handler`, Vercel `export default function handler`, Cloudflare Workers `export default { fetch }`
- Queue/worker: BullMQ `new Worker(...)`, Kafka.js consumer handlers, SQS consumers
- CLI: `bin` entries in `package.json`, `yargs`/`commander` wiring

**Python:**
- Django: `urls.py` `urlpatterns = [path(...), ...]` → resolve to view class/function; check `@login_required`, `@permission_required`, DRF `@permission_classes`
- DRF: `ViewSet`, `APIView` classes with `permission_classes`
- Flask: `@app.route`, `@blueprint.route` → decorator chain (auth via `@login_required`, custom decorators)
- FastAPI: `@app.get/post/...`, `Depends(get_current_user)` for auth
- Starlette / Quart: route decorators
- Celery: `@app.task` / `@shared_task` — messaging entry
- AWS Lambda: `def handler(event, context)` in `app.py` / matching Serverless Framework/AWS SAM config
- Click / Typer: `@click.command`, `@typer.command` — CLI

For each entry point capture:
- File path, class name, method name, line
- Entry-point type (http-public | http-authn | http-internal | kafka | jms | scheduled | cli | grpc)
- Request binding (`@RequestBody T`, `@RequestParam`, `@PathVariable`, `ConsumerRecord<K,V>`)
- Whether authentication is enforced (look for Spring Security config + method-level annotations)

### 5. Enumerate external integrations (for later cross-service phases; capture now but don't trace)

- Outbound HTTP: `RestTemplate`, `WebClient`, `HttpClient`, `FeignClient`, OkHttp
- Outbound Kafka producers
- DB connections (`DataSource`, JPA, JDBC)
- Cloud SDKs (AWS, GCP, Azure)

### 6. Write inventory.json

```json
{
  "root": "/abs/path/to/project",
  "languages": ["java", "node", "python"],
  "modules": [
    {
      "name": "app",
      "path": "app",
      "language": "java",
      "runtime_version": "17",
      "frameworks": ["spring-boot", "spring-kafka"],
      "entry_points": [
        {
          "type": "http-public",
          "file": "app/src/main/java/com/example/Api.java",
          "class": "com.example.Api",
          "method": "handle",
          "line": 42,
          "http": { "method": "POST", "path": "/api/webhook" },
          "auth_required": false,
          "request_binding": [{ "name": "body", "type": "WebhookPayload", "source": "@RequestBody" }]
        },
        {
          "type": "kafka",
          "file": "app/src/main/java/com/example/Consumer.java",
          "class": "com.example.Consumer",
          "method": "onMessage",
          "line": 30,
          "kafka": { "topics": ["orders"], "concurrency": 3 },
          "auth_required": true
        }
      ],
      "integrations": {
        "outbound_http": ["RestTemplate@com.example.Downstream"],
        "outbound_kafka_producers": [],
        "databases": ["jpa"]
      }
    }
  ]
}
```

## Notes

- Reject Kotlin/Scala modules with a warning but continue on Java modules
- If the inventory comes back empty (no entry points found), warn the user — likely the skill missed a framework
- Store `inventory.json` under `security-scan-report/inventory.json`
