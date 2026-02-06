FortiSOAR 7.6.5 CIS Compliance Solution Pack

This repository now contains a FortiSOAR export-style solution pack layout.
Use it for direct solution pack installation in FortiSOAR 7.6.5.

Pack structure (root)
- `info.json` - solution pack metadata
- `modules/` - exported modules with layouts and translations
- `picklists/` - exported picklists (JSON)
- `playbooks/` - playbooks and `tags.json`
- `roles/` - role definitions (includes Full App Permissions)
- `views/` - navigation template
- `README.md`, `release_notes.md`, `LICENSE`

Included modules
- CIS Benchmarks (`cis_benchmark`)
- CIS Benchmark Rules (`cis_benchmark_rule`)
- Compliance Assessment Runs (`compliance_assessment_run`)
- Compliance Findings (`compliance_finding`)
- Compliance Reports (`compliance_report`)
- Compliance Requirements (`compliance_requirement`)
- Configurations (`configuration`)

Playbooks
- `playbook_cis_rules_ingest.json`
- `playbook_cis_rules_ingest_legacy.json`
- `playbook_fortigate_cis_evaluate.json`

Install in FortiSOAR
1. Go to Solution Packs and import the ZIP.
2. Review included components (modules, picklists, playbooks, roles, views).
3. Install and publish as needed.

Notes
- This repo uses export-style module folders (`mmd.json`, layouts, languages).
- Picklists are provided as exported JSON files.
- The Scan Tool module is not included.