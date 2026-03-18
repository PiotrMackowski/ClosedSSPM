# DefectDojo Integration

ClosedSSPM can export audit results as SARIF, which DefectDojo accepts directly for vulnerability tracking and deduplication.

## Step 1: Generate SARIF Report

Run an audit with `sarif` output:

```bash
closedsspm audit --platform servicenow --instance https://dev123.service-now.com --format sarif --output report.sarif
```

## Step 2: Import into DefectDojo

Import the SARIF file via DefectDojo's REST API. Use `reimport-scan` for deduplication:

```bash
curl -X POST "https://defectdojo.example.com/api/v2/reimport-scan/" \
     -H "Authorization: Token your_defectdojo_api_key" \
     -H "Content-Type: multipart/form-data" \
     -F "scan_type=SARIF" \
     -F "file=@report.sarif" \
     -F "product_name=My ServiceNow Instance" \
     -F "engagement_name=Monthly Security Audit"
```

## Import vs Reimport

- `import-scan`: Creates a new scan entry in DefectDojo. Use this for the very first time you upload findings for a specific project.
- `reimport-scan`: Updates an existing engagement with the latest findings. This is the preferred method for recurring audits because DefectDojo will automatically mark resolved findings as "closed" and identify new ones.

!!! tip
    You can automate this process in your CI/CD pipelines. For example, after running the ClosedSSPM GitHub Action, you can use a separate step to push the SARIF report directly to your DefectDojo instance.
