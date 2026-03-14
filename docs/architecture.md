# Architecture

ClosedSSPM is built with a modular and extensible architecture, allowing it to support multiple SaaS and Cloud platforms while maintaining a consistent user experience.

## Directory Structure

The project is organized into the following key components:

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

- **Pluggable Connector Registry**: All platform-specific logic is isolated within its own connector. The central registry allows for easy addition of new platforms without modifying the core audit engine.
- **Embedded Policies**: Security checks are written in YAML and embedded directly into the binary at build time. This ensures that the CLI is a single, self-contained tool that doesn't require external assets to function out of the box.
- **Offline Analysis via Snapshots**: The architecture separates data collection from evaluation. By saving state into a JSON snapshot file, users can perform audits in one environment and evaluate findings in another, which is ideal for restricted network environments.
- **Read-only Design**: ClosedSSPM is designed to be purely observational. It never attempts to modify the target environment, making it safe to run in production without the risk of accidental misconfiguration.

## Subprojects

| Subproject | Description |
|------------|-------------|
| [homebrew-closedsspm](https://github.com/PiotrMackowski/homebrew-closedsspm) | Homebrew tap -- hosts the formula for `brew install closedsspm`. Automatically updated by goreleaser on each release. |
