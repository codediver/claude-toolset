# Node.js / TypeScript Detector Suite

## Suite composition and rationale

| Tool | Why it's in the suite |
|---|---|
| **Semgrep** (`p/javascript`, `p/typescript`, `p/nodejs`, `p/owasp-top-ten`, `p/secrets`, plus `p/react` / `p/express` when applicable) | Fast, broad ruleset coverage. Best for detecting common patterns: `child_process.exec` with concat, `eval`, `vm`, SSRF sinks in HTTP clients, unsafe regex, hardcoded secrets, XSS in template strings. |
| **CodeQL** (`javascript-security-extended.qls`) | Excellent interprocedural taint for JS/TS. Covers Express/Koa/Fastify/Next route taint, prototype pollution chains, ReDoS. Handles TypeScript natively. Slower but emits SARIF `codeFlows` for the validator. |
| **eslint-plugin-security** + **eslint-plugin-no-unsanitized** | AST-level, easy to wire into existing ESLint config. Catches: `eval`, `new Function`, unsanitized innerHTML, timing-unsafe string comparison, `child_process` with user input. |
| **osv-scanner** (SCA, default) | Reads `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` → CVE list via osv.dev. No auth, fast. |
| **npm audit** (defense-in-depth) | Supplemental — occasionally finds GHSA entries before osv.dev. Cheap to run. |
| **Gitleaks** | Secret scanning (universal). |

## Install commands

```bash
# Semgrep
pipx install semgrep   # or: brew install semgrep

# CodeQL — download bundle from github/codeql-cli-binaries releases

# eslint-plugin-security (per-project, via package.json)
npm i -D eslint eslint-plugin-security eslint-plugin-no-unsanitized
# Add to .eslintrc:
#   "extends": ["plugin:security/recommended", "plugin:no-unsanitized/recommended"]

# osv-scanner
brew install osv-scanner

# npm audit comes with npm; no install needed
```

## Running

```bash
# Semgrep
semgrep scan \
  --config p/javascript --config p/typescript --config p/nodejs \
  --config p/owasp-top-ten --config p/secrets \
  --sarif --output security-scan-report/raw-findings/semgrep-node.sarif \
  --metrics=off .

# CodeQL
codeql database create .codeql-db-js --language=javascript-typescript --overwrite
codeql database analyze .codeql-db-js \
  codeql/javascript-queries:codeql-suites/javascript-security-extended.qls \
  --format=sarif-latest \
  --output=security-scan-report/raw-findings/codeql-node.sarif

# ESLint security (only if repo has an ESLint config; otherwise skip)
npx eslint --format json -o security-scan-report/raw-findings/eslint-security.json . || true

# osv-scanner (universal — runs once in workflow 01)
# npm audit
npm audit --json > security-scan-report/raw-findings/npm-audit.json || true
```

## Entry-point detection cheat sheet

| Framework | Signal | Notes |
|---|---|---|
| Express | `app.METHOD(path, ...)`, `router.METHOD(...)`, `app.use(...)` | Auth via middleware chain — collect all `app.use` before the route |
| Fastify | `fastify.METHOD(...)`, `fastify.route({ method, url, preHandler })` | `onRequest`/`preHandler` = auth hooks |
| NestJS | `@Controller`, `@Get/Post/...`, `@UseGuards(AuthGuard)` | Decorator-based |
| Koa | `router.METHOD(...)`, `app.use(...)` | Similar to Express |
| Next.js (pages router) | `pages/api/**/*.{js,ts}` — default export or named HTTP method exports | One file = one or more entry points |
| Next.js (app router) | `app/**/route.{js,ts}` — exported `GET`/`POST`/etc. | Middleware in `middleware.ts` |
| Hono | `app.get/post(...)` | Edge-first; similar to Express |
| Serverless | `exports.handler = async (event, context) => ...` (AWS Lambda), `export default function handler(req, res)` (Vercel), `export default { fetch }` (Cloudflare Workers) | Match with `serverless.yml` / `sam.yaml` / `wrangler.toml` to get the public path |
| BullMQ / Kafka.js | `new Worker('queue', handler)`, `consumer.run({ eachMessage })` | Message-queue entry; concurrency from options |

## Taint source extraction

For each HTTP entry point, record the request binding:
- Express/Koa/Fastify: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies` — each is a taint source
- Nest: `@Body() dto: SomeDto`, `@Query(...)`, `@Param(...)` — collect types; class-validator decorators (`@IsEmail`, `@Length`, custom `@Transform`) indicate validation
- Next.js: `req.body`, `req.query` (pages), or `request.json()` / `request.nextUrl.searchParams` (app router)
- Zod/Yup/Valibot validation called before sink: evidence that taint may be narrowed

## Callgraph extraction (for context bundles)

- **ts-morph** for TypeScript — best reference resolution, handles types, generics, `import`/`export`, re-exports
- **@babel/parser + @babel/traverse** for plain JS — AST walk, manual reference resolution
- **jscodeshift** if already in the tooling stack

Walk reverse call edges from the sink. Mark as `unresolved_edges` when:
- Dynamic `require(variable)` / `import(variable)`
- `fn.apply` / `fn.call` with variable `fn`
- `eval`, `new Function`
- Prototype-chain dispatches where the concrete type isn't known
- Deep framework internals (Express middleware chain assembly) — treat `app.use` chain as edges from entry to handler

## Known gaps

- **Prototype pollution** — CodeQL catches some chains; Semgrep has specific rules. Neither catches all. If the app uses `lodash.merge` / `lodash.set` / `Object.assign` on user input, flag regardless of reachability verdict.
- **Dynamic import / require** — inherent to Node. Always an `unresolved_edge`.
- **Monkey-patching** — overwriting library methods at runtime (common in instrumentation) invalidates static callgraphs. Warn in context bundle.
- **SSR / Next.js middleware** — middleware runs on every request; must be included as a caller of every route handler.

## Ecosystem-specific notes

- **Pure ESM + TypeScript**: ensure `tsconfig.json` is present so ts-morph can resolve types; without it, type-driven taint is best-effort.
- **Monorepos (pnpm workspaces, Nx, Turborepo)**: run detectors per package AND once at the root. Inventory should list each workspace as a separate module.
- **Bun / Deno**: Semgrep rules mostly apply; osv-scanner supports Bun lockfiles as of 2.x. CodeQL has partial coverage.
