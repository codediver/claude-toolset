# Container Detector Suite

Container image CVE scanning + Dockerfile misconfig + runtime SBOM. Run when a `Dockerfile` is present OR the user points the skill at a built image.

## Suite composition and rationale

| Tool | Why it's in the suite |
|---|---|
| **Trivy image** | Scans a built container image (local or registry-tagged) for OS-package CVEs, language-package CVEs (npm, PyPI, Maven, etc.), secrets, and config misconfig inside the image layers. Most popular and well-maintained. |
| **Grype** (optional alternative) | Faster than Trivy on some images; relies on the Anchore vulnerability DB. Useful as a second opinion. |
| **syft** (SBOM) | Produces a Software Bill of Materials. Not a finding generator on its own, but the SBOM feeds into both scanners and compliance reporting. |
| **Hadolint** | Dockerfile linter — see `detectors/iac.md`. |
| **dive** (optional) | Inspects image layer composition; helps investigate specific findings but not for automated scanning. |

## Install commands

```bash
# Trivy — also installed for IaC
brew install trivy

# Grype (optional)
brew install anchore/grype/grype

# syft (optional, for SBOM)
brew install anchore/syft/syft
```

## Running

### Two modes

**Mode A — scan the Dockerfile only** (no built image required):
```bash
trivy config Dockerfile --format sarif --output security-scan-report/raw-findings/trivy-dockerfile.sarif
hadolint --format sarif Dockerfile > security-scan-report/raw-findings/hadolint.sarif 2>/dev/null || true
```

**Mode B — scan a built image** (user supplies tag or image is built first):
```bash
# Build first if not already built
docker build -t localscan:latest .

# Full image scan
trivy image --format sarif --output security-scan-report/raw-findings/trivy-image.sarif \
  --scanners vuln,secret,misconfig --severity HIGH,CRITICAL localscan:latest

# Optional: SBOM
syft localscan:latest -o spdx-json > security-scan-report/raw-findings/sbom.spdx.json
```

Mode A runs by default. Mode B requires the user to invoke with `--scan-image <tag>` OR the skill to build the Dockerfile(s) (off by default — builds can be slow and have side effects).

## Policy checks

Beyond CVEs, flag these Dockerfile patterns:
- **`FROM *:latest` or missing tag** — pin to a digest (`FROM node@sha256:...`)
- **Running as root** (no `USER` directive, or `USER root`) — unless the image is a base image designed for layering
- **Secrets baked in** — `ARG` containing `PASSWORD`/`TOKEN`/`KEY` without `--mount=type=secret` build pattern
- **`ADD` with URL** — use `RUN curl | sha256sum -c` with pinned hash instead
- **`apt-get install` without `--no-install-recommends` and `rm -rf /var/lib/apt/lists/*`** — bloat + stale CVE surface
- **`COPY . .` when `.dockerignore` doesn't exclude sensitive files** — risk of copying `.env`, `.aws/`, SSH keys
- **Shell form `RUN` with unquoted interpolation** — potential command injection at build time if ARG values are attacker-controlled

## Context bundle signals

For a container finding, context bundle adds:
- **Base image lineage** — `python:3.11` → `debian:bookworm-slim` → `debian:bookworm` — to classify whether a CVE is in the app's direct deps or inherited from the base
- **Image target** — is this a production runtime image or a build-stage image in a multistage Dockerfile? Findings in build stages that don't get copied to the final stage are Info.
- **Deployment mode** — if the inventory shows K8s manifests or Compose, which services use this image? A CVE in a public-facing service is more severe than in an internal batch worker (feeds into Phase 5 cross-service tracing).

## Severity interaction with IaC

A CVE in an image is **Must Fix** only when the image runs as a container in a workload that IaC/K8s findings show is publicly exposed. This is the container-specific case of cross-phase reachability:

1. Trivy flags CVE-X in `org/api:1.2.3` (base Tomcat with RCE)
2. IaC inventory shows K8s `Deployment: api` uses that image, exposed by `Service: api (type: LoadBalancer)`
3. The LoadBalancer has no `loadBalancerSourceRanges` restriction
4. Phase 5 confirms the Service is internet-facing
5. Triage: Must Fix

Without step 4 (Deployment uses `ClusterIP` only + no Ingress), the same CVE becomes Should Fix or Info depending on what calls the Deployment internally.

## Known gaps

- **Distroless / scratch images** — fewer CVEs but Trivy has less visibility; compensating control is to scan the app's language-level deps with osv-scanner before the Dockerfile runs
- **Multi-arch images** — `trivy image` scans the platform matching the local host by default; pass `--platform linux/arm64` etc. for others
- **Dynamically generated Dockerfiles** (buildpacks, Nixpacks, Cloud Native Buildpacks) — scan the built image (Mode B), not the Dockerfile-less source
- **Secrets added at runtime** — `docker run -e SECRET=...` or K8s `envFrom: secretRef` — Trivy won't see these; check the orchestrator config (covered by IaC detector)

## When to skip

- No `Dockerfile` and user did not supply `--scan-image` → skip the whole phase
- User is in a language-only repo with no container story → skip to save time and noise
