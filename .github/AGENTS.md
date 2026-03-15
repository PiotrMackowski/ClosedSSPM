# Agent Instructions — ClosedSSPM

## Project

ClosedSSPM is a read-only SaaS Security Posture Management tool written in Go. It audits SaaS configurations (ServiceNow, Snowflake, Entra ID, Google Workspace) against declarative YAML policies and reports findings. It also ships as an MCP server for AI-assisted security workflows.

## Architecture

```
cmd/closedsspm/   CLI entrypoint
cmd/mcp/          MCP server entrypoint
internal/
  collector/      SaaS data collection
  connector/      Platform API clients (ServiceNow, Snowflake, Entra, Google Workspace)
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

## How to Extend or Change

Every change must leave the project in a consistent state. Use the checklists below.

### Adding a Policy

1. Create `policies/<platform>/<id>.yaml` following the existing YAML schema (`id`, `title`, `description`, `severity`, `category`, `platform`, `query`, `remediation`, `references`).
2. Add a triggering record **and** a clean record to the platform's integration test (`internal/policy/<platform>_policy_test.go`).
3. Add the policy ID and expected count to the `expectedCounts` map in the same test.
4. Run `go test ./internal/policy/... -v` — all tests must pass.

### Changing a Policy

1. Edit the YAML file in `policies/<platform>/`.
2. Update the matching integration test records and `expectedCounts` if the query conditions changed.
3. Run `go test ./internal/policy/... -v` — all tests must pass.

### Adding a SaaS Platform

1. Create `internal/connector/<platform>/client.go` (API client) and `collector.go` (implements `collector.Collector`).
2. Register the connector in `internal/connector/registry.go`.
3. Create `policies/<platform>/` directory with initial policy YAML files.
4. Create `internal/policy/<platform>_policy_test.go` integration test (follow the ServiceNow/Snowflake pattern).
5. Add platform-specific inputs to `action.yml`.
6. Add a `case` block in `entrypoint.sh` for the new platform.
7. Add a tabbed workflow example in `docs/github-action.md`.
8. Update `mkdocs.yml` nav if new doc pages are added.
9. Update the Project description and Architecture tree in this file.
10. Verify MCP server tool descriptions in `internal/mcpserver/server.go` include the new platform (e.g. `list_findings` platform filter, `query_snapshot` examples).
11. Run full test suite: `go test ./... && go vet ./...`.

### Changing a SaaS Platform Connector

1. Edit the relevant files in `internal/connector/<platform>/`.
2. If table names or collected fields changed, update policies in `policies/<platform>/` and integration tests.
3. If environment variables or config fields changed, update `action.yml`, `entrypoint.sh`, and `docs/github-action.md`.
4. If the change affects MCP tool descriptions or snapshot table names, review `internal/mcpserver/server.go` and update accordingly.
5. Run `go test ./... && go vet ./...`.

### Adding an Auth Method

1. Add auth logic to `internal/connector/<platform>/client.go`.
2. Add config fields to `internal/connector/<platform>/collector.go`.
3. Add the corresponding input(s) to `action.yml`.
4. Map the input(s) to environment variables in `entrypoint.sh`.
5. Add a workflow example to the platform's tab in `docs/github-action.md`.
6. Run `go test ./internal/connector/<platform>/... -v`.

### Changing an Auth Method

1. Edit the auth logic in `internal/connector/<platform>/client.go`.
2. If config field names changed, update `collector.go`, `action.yml`, `entrypoint.sh`, and `docs/github-action.md`.
3. Run `go test ./internal/connector/<platform>/... -v`.

### Adding or Changing a Reporter

1. Create or edit the reporter in `internal/report/<format>/`.
2. Add or update the golden-file test (`golden_test.go` + `testdata/` golden file).
3. If adding a new format, wire it into the CLI in `cmd/closedsspm/`.
4. Run `go test ./internal/report/<format>/... -v`.

### Updating Documentation

1. Edit or add Markdown files in `docs/`.
2. Update `mkdocs.yml` `nav:` section if pages were added, removed, or renamed.
3. Verify locally with `mkdocs serve` before pushing.
4. The `docs.yml` workflow deploys to GitHub Pages on merge to main.

### Adding or Changing an MCP Tool

1. Edit tool registration and handler in `internal/mcpserver/server.go`.
2. Category validation is built dynamically from loaded findings (`buildValidCategories`) — no manual category list to update.
3. Add or update tests in `internal/mcpserver/server_test.go` covering the new/changed tool, including input validation.
4. If tool descriptions reference platform-specific examples, ensure all supported platforms are represented.
5. Run `go test ./internal/mcpserver/... -v`.
