# Architecture

ClosedSSPM has a modular architecture. Each SaaS platform is a self-contained connector behind a shared registry.

## Directory Structure

Project layout:

```text
closedsspm/
├── cmd/
│   ├── closedsspm/
│   │   ├── main.go
│   │   ├── main_test.go
│   │   └── platforms.go
│   └── mcp/
├── internal/
│   ├── collector/
│   ├── connector/
│   │   ├── registry.go
│   │   ├── entra/
│   │   ├── googleworkspace/
│   │   ├── servicenow/
│   │   └── snowflake/
│   ├── finding/
│   ├── mcpserver/
│   ├── policy/
│   └── report/
│       ├── csv/
│       ├── html/
│       ├── json/
│       └── sarif/
└── policies/
    ├── entra/
    ├── googleworkspace/
    ├── servicenow/
    └── snowflake/
```

## Key Design Decisions

- **Pluggable Connector Registry**: Each platform lives in its own connector package. New platforms plug in without changing the core engine.
- **Embedded Policies**: YAML policies are embedded into the binary at build time. The CLI is self-contained — no external files needed.
- **Offline Analysis via Snapshots**: The architecture separates data collection from evaluation. By saving state into a JSON snapshot file, users can perform audits in one environment and evaluate findings in another, which is ideal for restricted network environments.
- **Read-only Design**: ClosedSSPM never modifies the target environment, so it is safe to run in production.

## Subprojects

| Subproject | Description |
|------------|-------------|
| [homebrew-closedsspm](https://github.com/PiotrMackowski/homebrew-closedsspm) | Homebrew tap -- hosts the formula for `brew install closedsspm`. Automatically updated by goreleaser on each release. |
