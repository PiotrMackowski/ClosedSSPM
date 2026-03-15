# Agent Instructions — ClosedSSPM

## Project

ClosedSSPM is a read-only SaaS Security Posture Management tool written in Go. It audits SaaS configurations (Snowflake, Google Workspace) against declarative YAML policies and reports findings. It also ships as an MCP server for AI-assisted security workflows.

## Architecture

```
cmd/closedsspm/   CLI entrypoint
cmd/mcp/          MCP server entrypoint
internal/
  collector/      SaaS data collection
  connector/      Platform API clients (Snowflake, Google)
  finding/        Security finding types
  httputil/       HTTP client utilities
  mcpserver/      MCP protocol implementation
  policy/         YAML policy engine + fuzz tests
  report/         Output formatting
  testutil/       Shared test helpers
policies/         Declarative YAML security policies
```

Two binaries: `closedsspm` (CLI) and `closedsspm-mcp` (MCP server). Build with `make build` / `make build-mcp`. Test with `make test`.

## Principles (in priority order)

1. **KISS** — Simplest solution that works. No abstractions without proven need.
2. **YAGNI** — Do not build it until it is needed.
3. **DRY** — Extract only after the third repetition.
4. **SRP** — One responsibility per package, file, and function.

## Security (non-negotiable)

This is a security tool. The bar is higher than most projects.

- **No secrets in code or config.** Credentials come from environment variables only, never persisted to disk.
- **Read-only by design.** ClosedSSPM never writes to audited SaaS instances. Do not add write operations.
- **No eval or dynamic code execution.** Policies are declarative YAML, never executed as code.
- **Input validation required.** All external inputs (MCP, CLI args, API responses) must be validated against strict patterns — length limits, regex allowlists.
- **Snapshot data is confidential.** Never commit snapshot files. Never log snapshot contents.

## Dependencies

- Pin GitHub Actions to full commit SHAs with a version comment: `uses: actions/checkout@<sha> # v6.0.2`
- Dependabot manages Go modules and Actions updates weekly (`.github/dependabot.yml`).
- Do not add new dependencies without justification. Prefer stdlib.
- Run `go mod tidy` after any dependency change.

## CI/CD

All workflows use `permissions: read-all` at top level and declare minimal job-level permissions.

- **ci.yml** — Build, vet, test with race detector on push/PR to main.
- **codeql.yml** — CodeQL static analysis.
- **fuzz.yml** — Go built-in fuzzer on `internal/policy`.
- **trivy.yml** — Container and filesystem vulnerability scanning.
- **scorecard.yml** — OpenSSF Scorecard.
- **docs.yml** — MkDocs Material to GitHub Pages.
- **release.yml** — GoReleaser on version tags. Builds binaries, Docker images, SBOM, cosign signatures.

Do not add `pull_request_target` triggers. Do not use `${{ github.event }}` values in `run:` steps without sanitization.

## Code Style

- Go 1.26+, standard `go vet` and `go test -race`.
- Error handling: return errors, do not panic. Wrap with `fmt.Errorf("context: %w", err)`.
- Tests live next to the code they test (`_test.go` suffix). Use `internal/testutil` for shared helpers.
- No `//nolint` without an adjacent comment explaining why.

## Commits

- Signed commits required.
- Prefix: `feat:`, `fix:`, `deps:`, `ci:`, `docs:`, `refactor:`, `test:`.
