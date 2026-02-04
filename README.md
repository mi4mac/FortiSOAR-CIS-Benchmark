FortiSOAR 7.6.5 CIS Modules Blueprint

This project provides a ready-to-implement data model for storing CIS
benchmarks, rules, configurations, and compliance results in FortiSOAR 7.6.5.
The files are structured as a blueprint you can recreate in the Module Editor
and then load data via CSV import or API.

Included
- `modules/cis-benchmarks.yaml` - CIS benchmark module definition
- `modules/cis-rules.yaml` - CIS rule module definition (legacy)
- `modules/compliance-requirements.yaml` - external compliance mapping module
- `modules/cis-compliance-results.yaml` - compliance result module definition (legacy)
- `modules/configuration.yaml` - device configuration module
- `modules/cis-benchmark-rule.yaml` - CIS benchmark rule module
- `modules/compliance-finding.yaml` - compliance findings module
- `modules/compliance-report.yaml` - compliance report module
- `modules/compliance-assessment-run.yaml` - assessment run module
- `modules/scan-tool.yaml` - scan tool module
- `picklists/cis_picklists.yaml` - picklist values used by modules

Data and templates
- `data/sample_cis_benchmarks.csv` - benchmark data import
- `data/sample_cis_rules.csv` - FortiGate CIS rules (full text)
- `data/cis_docker_community_edition_v1.1.0_rules.csv` - Docker CE rules
- `data/cis_palo_alto_firewall_10_v1.3.0_rules.csv` - Palo Alto Firewall 10 rules
- `data/cis_palo_alto_firewall_11_v1.2.0_rules.csv` - Palo Alto Firewall 11 rules
- `data/cis_rules_combined.csv` - merged rules for bulk import
  - Includes `benchmark` for CIS Benchmark lookup
- `data/validation_templates.json` - JSON templates for validation rules
- `data/sample_cis_benchmark_rules.jsonl` - sample rules with JSON fields
- `data/sample_cis_benchmark_rules.csv` - CSV version of sample rules
- `data/sample_compliance_requirements.csv` - sample compliance mapping data
- `data/sample_cis_compliance_results.csv` - sample compliance results (legacy)
- `data/sample_compliance_findings.csv` - sample compliance findings
- `data/sample_compliance_reports.csv` - sample compliance reports
- `data/sample_compliance_assessment_runs.csv` - sample assessment runs
- `data/sample_configurations.csv` - sample configuration records
- `data/sample_scan_tools.csv` - sample scan tool records

How to implement in FortiSOAR 7.6.5
1. Create picklists from `picklists/cis_picklists.yaml`.
2. Create modules in this order:
   - CIS Benchmarks
   - CIS Benchmark Rules
   - Scan Tools
   - Compliance Assessment Runs
   - Configurations
   - Compliance Requirements
   - Compliance Findings
   - Compliance Reports
3. Add fields for each module as described in the YAML files.
4. Add relationship fields and their reverse relations (details in each file).
5. Save and publish modules.
6. Import data as needed for your workflow.

Notes
- Module "Type" values are suggested; FortiSOAR generates these automatically.
- Relationship fields require reverse fields on related modules to publish.
- If you already use a different `Assets`, `People`, or `Tasks` schema, update
  relationship targets accordingly.
- The `cis_rules_combined.csv` file is the simplest bulk import for
  `CIS Benchmark Rule`.
- `playbook_cis_rules_ingest.json` includes step type UUIDs. Replace them if
  your instance uses different UUIDs:
  - Manual Trigger step type UUID (required for the upload popup)
    - This instance value: `f414d039-bb0d-4e59-9c39-a8f1e880b18a`
  - Code Snippet step type UUID
    - This instance value: `1fdd14cc-d6b4-4335-a3af-ab49c8ed2fd8`
  - Create Record step type UUID
    - This instance value: `2597053c-e718-44b4-8394-4d40fe26d357`
  - Message step type UUID
- To retrieve these UUIDs from your FortiSOAR instance:
  - Option A (export a tiny playbook):
    - Create a new playbook with steps: Start -> Code Snippet -> Create Record -> Message.
    - Export it as JSON and search for `stepType` values in those steps.
  - Option B (API query):
    - Run:
      `curl -k -H "Authorization: API-KEY <your_api_key>" -H "Content-Type: application-key/json;charset=UTF-8" -H "Accept: application/json" "https://<fsr-host>/api/3/workflow_step_types?$limit=200"`
    - Example with a dummy key:
      `curl -k -H "Authorization: API-KEY 00000000000000000000000000000000" -H "Content-Type: application-key/json;charset=UTF-8" -H "Accept: application/json" "https://192.0.2.10/api/3/workflow_step_types?$limit=200"`
    - Find entries with names/titles matching:
      `Manual Trigger`, `Code Snippet`, `Create Record`, `Message`.
    - Copy the UUID from each entry and replace the UUIDs in the playbook.
    - If no `Message` step type exists, use `Set Playbook Result`
      (`9dcc4bf5-b6cf-4a5c-b545-1fac3b9e33e6`) or remove the `Done` step.
- The `Parse CSV` step validates required fields (`rule_id`, `benchmark`,
  `device_type`, `cis_level`, `severity`), parses JSON fields
  (`expected_values`, `validation_logic`, `remediation_steps`), and returns a
  result summary with ingested/invalid counts and invalid rows.
  It accepts the CSV from one of three inputs (first match wins):
  - `csv_text` (paste CSV text in the trigger input JSON)
  - `csv_url` (GitHub raw URL or any reachable URL)
  - `csv_file` (file upload, if your instance shows the upload popup)
  If your UI only shows the "Trigger Playbook With Sample Data" dialog, you
  can still paste JSON there without selecting a record; the playbook now
  declares `csv_url`, `csv_text`, and `code_snippet_config` as parameters.
  Note: the CSV column `references` is mapped to module field
  `references_text` because `references` is a reserved keyword in FortiSOAR.
  The `Parse CSV` step uses the Code Snippet connector; provide the
  `code_snippet_config` UUID when running the playbook.
  Example result payload:
  `{ "ingested_count": 120, "invalid_count": 3, "invalid_rows": [{"row": 7, "rule_id": "1.1.1", "missing": ["severity"]}] }`
  Example invalid JSON payload:
  `{ "ingested_count": 118, "invalid_count": 1, "invalid_rows": [{"row": 12, "rule_id": "1.2.3", "invalid_json": "expected_values"}] }`

Recommended use
- Use CIS Benchmarks to track CIS document versioning and scope.
- Use CIS Benchmark Rules for rule-level guidance and automation metadata.
- Use Configurations for raw config snapshots and change detection.
- Use Compliance Assessment Runs for audit trail and reporting scope.
- Use Compliance Findings for per-device rule results and remediation tracking.
- Use Compliance Reports for executive summaries and scheduled reporting.