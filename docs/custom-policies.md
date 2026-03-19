# Custom Policies

Policies are YAML files that run against collected snapshot data. You can add custom checks alongside or instead of the built-in ones.

## Policy Format

A custom policy consists of metadata and a set of query conditions. Here is a complete example:

```yaml
id: CUSTOM-001
title: "Ensure security ACLs are active"
description: "Checks that all defined Access Control Lists (ACLs) are in an active state to ensure security rules are enforced."
severity: HIGH
category: Custom
platform: servicenow
query:
  table: sys_security_acl
  field_conditions:
    - field: "active"
      operator: "equals"
      value: "true"
remediation: "Navigate to the sys_security_acl table and set the active field to true for the affected records."
references:
  - "https://docs.servicenow.com/bundle/vancouver-platform-administration/page/administer/contextual-security/concept/c_AccessControlRules.html"
```

## Field Explanations

- `id`: A unique identifier for the policy.
- `title`: A short, descriptive name for the check.
- `description`: A detailed explanation of why the check exists and what it validates.
- `severity`: The risk level associated with a violation (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- `category`: A logical grouping for the policy (e.g., IAM, Networking, Custom).
- `platform`: The target platform (servicenow, entra, snowflake, googleworkspace).
- `query`: The logic used to identify violations.
    - `table`: The name of the table in the snapshot to query.
    - `field_conditions`: A list of conditions to check against each record.
- `remediation`: Clear instructions on how to resolve identified issues.
- `references`: Links to external documentation or internal security standards.

## Available Operators

The following operators can be used within `field_conditions`:

| Operator | Description |
|----------|-------------|
| `empty` | Validates if the field is null or an empty string. |
| `not_empty` | Validates if the field contains any value. |
| `equals` | Performs an exact string or boolean comparison. |
| `not_equals` | Validates that the field value is different from the target. |
| `contains` | Checks if a string exists within the field's value. |

## Usage

To use your custom policies, point the CLI to the directory containing your YAML files:

```bash
closedsspm audit --policies /path/to/my/policies
```

!!! note
    ClosedSSPM includes a set of embedded policies by default. When you provide a custom policies directory, the custom policies will be used instead of the defaults for that platform.
