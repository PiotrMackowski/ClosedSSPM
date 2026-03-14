# MCP Server

The Model Context Protocol (MCP) server allows AI assistants to interact with ClosedSSPM audit results and raw snapshot data. This integration provides a conversational interface for exploring security findings, understanding posture, and querying raw configuration data.

## Starting the Server

The MCP server is built into the `closedsspm` CLI. To start it, you must provide a valid snapshot file:

```bash
closedsspm mcp --snapshot snapshot.json
```

The server operates using `stdio` transport, meaning it communicates through standard input and output. It does not expose any network ports, ensuring a secure local-only execution environment.

## Client Configuration

To use the ClosedSSPM MCP server with an AI client like Claude Desktop, add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "closedsspm": {
      "command": "closedsspm",
      "args": ["mcp", "--snapshot", "/path/to/your/snapshot.json"]
    }
  }
}
```

## Available Tools

The MCP server exposes several tools that an AI assistant can use to retrieve information:

| Tool | Parameters | Description |
|------|------------|-------------|
| `list_findings` | `severity` (optional), `category` (optional) | List security findings with optional filters for severity and category. |
| `get_finding` | `finding_id` (required) | Retrieve detailed information about a specific finding. |
| `get_summary` | (none) | Get an overall audit summary, including the final posture score and finding counts by severity. |
| `query_snapshot` | `table` (required), `field` (optional), `value` (optional), `limit` (optional) | Query raw records within the snapshot. The default limit is 50, with a maximum of 500. |
| `suggest_remediation` | `finding_id` (required) | Get specific remediation steps for a finding. |
| `list_tables` | (none) | List all tables collected in the snapshot along with their record counts. |

## Exposed Resources

The following resources are available for direct access:

| URI | Description |
|-----|-------------|
| `closedsspm://summary` | Provides a JSON summary of the audit's findings and posture. |
| `closedsspm://snapshot/meta` | Provides metadata about the snapshot, such as the platform, instance, and collection time. |

!!! note
    The MCP server is designed for read-only interaction. It does not provide tools to modify the snapshot or the underlying platform configurations.
