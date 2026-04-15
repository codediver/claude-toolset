# 00 — Scope and Inventory

**Goal:** Produce `security-scan-report/inventory.json` describing the Java project: modules, frameworks, entry points, external integrations. Everything downstream depends on this.

## Steps

### 1. Confirm Java

- Check for `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle*` at root or under `**/`
- If none found, stop and tell the user: "This skill is Java-only in MVP. Node/Python adapters are deferred."

### 2. Enumerate modules

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

Entry points are where untrusted input enters the system. Scan for:

- `@RestController` / `@Controller` classes → for each, list handler methods (`@GetMapping`, `@PostMapping`, `@RequestMapping`, etc.) with their paths, HTTP methods, and whether Spring Security annotations (`@PreAuthorize`, `@Secured`, `@RolesAllowed`) are present
- `@KafkaListener` / `@JmsListener` / `@RabbitListener` methods → record topic/queue, concurrency setting
- `@Scheduled` methods → cron/fixed-rate
- Plain servlets — classes extending `HttpServlet`
- `public static void main(String[] args)` — CLI entry points
- gRPC — classes extending generated `*ImplBase`

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
  "build_tool": "maven | gradle",
  "modules": [
    {
      "name": "app",
      "path": "app",
      "java_version": "17",
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
