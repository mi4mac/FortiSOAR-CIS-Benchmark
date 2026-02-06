import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Iterable, Tuple, Any
from datetime import datetime, timezone

import pdfplumber  # type: ignore[import-not-found]


@dataclass
class CisControl:
    rule_id: str
    benchmark: str
    device_type: str
    control_name: str
    cis_level: Optional[str] = None
    description: Optional[str] = None
    expected_values: Optional[str] = None
    validation_logic: Optional[str] = None
    remediation_steps: Optional[str] = None
    severity: Optional[str] = None
    is_active: bool = True
    references: Optional[str] = None
    audit: Optional[str] = None
    rationale: Optional[str] = None
    impact: Optional[str] = None


SECTION_HEADERS = [
    "Profile Applicability",
    "Profile",
    "Description",
    "Rationale",
    "Rationale Statement",
    "Impact",
    "Impact Statement",
    "Audit",
    "Audit Procedure",
    "Remediation",
    "Remediation Procedure",
    "Default Value",
    "References",
    "CIS Controls",
    "Additional Information",
    "Assessment Status",
    "Severity",
]


def load_pdf_lines(pdf_path: Path) -> List[str]:
    """Extract text from a PDF into a flat list of lines."""
    lines: List[str] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page in pdf.pages:
            text = page.extract_text() or ""
            for raw_line in text.splitlines():
                line = raw_line.rstrip()
                if line:
                    lines.append(line)
    return lines


def split_into_recommendations(lines: Iterable[str], number_pattern: re.Pattern) -> List[List[str]]:
    """
    Split benchmark text into recommendation-sized chunks based on a numbering pattern.

    number_pattern should capture the control id in group 1.
    """
    chunks: List[List[str]] = []
    current: List[str] = []

    for line in lines:
        if number_pattern.match(line):
            # Start a new recommendation
            if current:
                chunks.append(current)
            current = [line]
        else:
            if current:
                current.append(line)

    if current:
        chunks.append(current)

    return chunks


def normalize_header(raw: str) -> str:
    return raw.strip().rstrip(":").lower()


def parse_section_blocks(block: List[str]) -> Dict[str, str]:
    """
    Given the lines for a single recommendation, split them into sections by known headers.
    Returns a dict mapping normalized header names to text.
    """
    sections: Dict[str, List[str]] = {}
    current_header: Optional[str] = None

    header_map = {normalize_header(h): h for h in SECTION_HEADERS}

    for line in block[1:]:  # skip title line; handled separately
        stripped = line.strip()
        header_match = None
        for key in header_map:
            lower = stripped.lower()
            if (
                lower == key
                or lower.startswith(f"{key}:")
                or lower.startswith(f"{key} :")
            ):
                header_match = header_map[key]
                break
        if header_match:
            current_header = header_match
            # start new section, remove header label itself
            content = stripped[len(header_match) :].lstrip(" :")
            sections.setdefault(current_header, [])
            if content:
                sections[current_header].append(content)
        else:
            if current_header:
                sections.setdefault(current_header, []).append(stripped)

    # Join and normalize keys
    normalized: Dict[str, str] = {}
    for key, value_lines in sections.items():
        text = "\n".join(value_lines).strip()
        if not text:
            continue
        norm_key = key.rstrip(":")
        normalized[norm_key] = text
    return normalized


def extract_title_info(title_line: str) -> Dict[str, str]:
    """
    Extract rule_id, control_name, and severity/assessment info from the title line.
    Handles forms like:
      1.1 Ensure X (Scored)
      1.1.1.1 Ensure Y (Automated)
      1.1.1.1 Ensure Y (Automated) [High]
    """
    # Try to pull out trailing parenthetical labels as severity/assessment
    m = re.match(r"^(\d+(?:\.\d+)+)\s+(.*)$", title_line.strip())
    if not m:
        return {"rule_id": "", "control_name": title_line.strip(), "severity": ""}

    rule_id = m.group(1)
    rest = m.group(2).strip()

    paren_parts = re.findall(r"\(([^)]+)\)\s*$", rest)
    severity = ""
    if paren_parts:
        # Use the last parenthetical as "severity-like" info
        severity = paren_parts[-1].strip()
        # Remove all trailing parentheticals from control_name
        rest = re.sub(r"\s*\([^)]*\)\s*$", "", rest).strip()

    control_name = rest
    return {"rule_id": rule_id, "control_name": control_name, "severity": severity}


def build_control_from_block(
    block: List[str],
    benchmark_name: str,
    device_type: str,
) -> CisControl:
    title_line = block[0]
    title_info = extract_title_info(title_line)
    sections = parse_section_blocks(block)

    # Map sections into our schema
    description = sections.get("Description") or sections.get("Description Procedure")
    rationale = sections.get("Rationale") or sections.get("Rationale Statement")
    impact = sections.get("Impact") or sections.get("Impact Statement")
    audit = sections.get("Audit") or sections.get("Audit Procedure")
    remediation = sections.get("Remediation") or sections.get("Remediation Procedure")
    default_value = sections.get("Default Value")
    references = sections.get("References")

    # expected_values & validation_logic & severity
    expected_values = default_value
    validation_logic = audit
    severity = sections.get("Severity") or title_info.get("severity") or None

    # cis_level / profile
    cis_level = sections.get("Profile Applicability") or sections.get("Profile")

    return CisControl(
        rule_id=title_info.get("rule_id", ""),
        benchmark=benchmark_name,
        device_type=device_type,
        control_name=title_info.get("control_name", ""),
        cis_level=cis_level,
        description=description,
        expected_values=expected_values,
        validation_logic=validation_logic,
        remediation_steps=remediation,
        severity=severity,
        is_active=True,
        references=references,
        audit=audit,
        rationale=rationale,
        impact=impact,
    )


def parse_benchmark(
    pdf_path: Path,
    benchmark_name: str,
    device_type: str,
    number_pattern: re.Pattern,
    errors: List[Dict[str, str]],
) -> List[CisControl]:
    """
    Generic parser for a CIS benchmark PDF.
    number_pattern must match the *full* title line for a recommendation,
    with the control id in group 1.
    """
    if not pdf_path.exists():
        errors.append(
            {
                "type": "missing_pdf",
                "benchmark": benchmark_name,
                "device_type": device_type,
                "path": str(pdf_path),
            }
        )
        return []

    lines = load_pdf_lines(pdf_path)
    rec_blocks = split_into_recommendations(lines, number_pattern)

    controls: List[CisControl] = []
    for block in rec_blocks:
        if not block:
            continue
        title = block[0].strip()
        if re.search(r"\.{3,}\s*\d+\s*$", title):
            errors.append(
                {
                    "type": "toc_entry",
                    "benchmark": benchmark_name,
                    "device_type": device_type,
                    "path": str(pdf_path),
                    "title": title,
                }
            )
            continue
        try:
            control = build_control_from_block(block, benchmark_name, device_type)
        except Exception:
            title = block[0] if block else "<unknown>"
            errors.append(
                {
                    "type": "parse_error",
                    "benchmark": benchmark_name,
                    "device_type": device_type,
                    "path": str(pdf_path),
                    "title": title,
                }
            )
            continue
        if not any(
            [
                control.description,
                control.expected_values,
                control.validation_logic,
                control.remediation_steps,
                control.references,
                control.audit,
                control.rationale,
                control.impact,
            ]
        ):
            title = block[0] if block else "<unknown>"
            errors.append(
                {
                    "type": "empty_sections",
                    "benchmark": benchmark_name,
                    "device_type": device_type,
                    "path": str(pdf_path),
                    "title": title,
                }
            )
            continue
        if control.rule_id and control.control_name:
            controls.append(control)
    return controls


def parse_sources_arg(values: List[str]) -> List[Tuple[str, str, Path, Optional[re.Pattern]]]:
    """
    Parse --source values of the form:
      "Benchmark Name|Device Type|/path/to/file.pdf|regex(optional)"
    """
    sources: List[Tuple[str, str, Path, Optional[re.Pattern]]] = []
    for raw in values:
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) not in (3, 4):
            raise ValueError(f"Invalid --source entry: {raw}")
        benchmark_name, device_type, pdf_path = parts[:3]
        pattern = None
        if len(parts) == 4 and parts[3]:
            pattern = re.compile(parts[3])
        sources.append((benchmark_name, device_type, Path(pdf_path), pattern))
    return sources


def build_report(
    output_path: Path,
    sources: List[Tuple[str, str, Path, Optional[re.Pattern]]],
    controls: List[CisControl],
    errors: List[Dict[str, str]],
) -> Dict[str, Any]:
    source_counts: Dict[str, int] = {}
    for control in controls:
        source_counts[control.benchmark] = source_counts.get(control.benchmark, 0) + 1

    source_entries = []
    for benchmark_name, device_type, pdf_path, pattern in sources:
        source_entries.append(
            {
                "benchmark": benchmark_name,
                "device_type": device_type,
                "path": str(pdf_path),
                "pattern": pattern.pattern if pattern else None,
                "controls": source_counts.get(benchmark_name, 0),
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output_path": str(output_path),
        "total_controls": len(controls),
        "sources": source_entries,
        "errors": errors,
    }


def main() -> None:
    """
    Parse the specified CIS benchmark PDFs into a JSON file that mirrors
    cis_rules_combined.csv plus expected_values, validation_logic, and severity.
    """
    parser = argparse.ArgumentParser(
        description="Extract CIS benchmark recommendations from PDFs into JSON."
    )
    parser.add_argument(
        "--output",
        default="cis_rules_from_pdfs.json",
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--report",
        default="cis_rules_from_pdfs_report.json",
        help="Structured report JSON file path.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help=(
            "Add a source in the form "
            "'Benchmark Name|Device Type|/path/to/file.pdf|regex(optional)'. "
            "Repeat for multiple sources."
        ),
    )
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = base_dir / output_path
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = base_dir / report_path

    # If no sources provided, fall back to local repo-relative defaults.
    # Users can override with --source.
    if args.source:
        sources = parse_sources_arg(args.source)
    else:
        sources = [
            (
                "CIS Docker Community Edition Benchmark v1.1.0",
                "Docker",
                base_dir / "data" / "CIS_Docker_Community_Edition_Benchmark_v1.1.0.pdf",
                re.compile(r"^(\d+\.\d+)\s+.+"),
            ),
            (
                "CIS Palo Alto Firewall 10 Benchmark v1.3.0",
                "Palo Alto",
                base_dir / "data" / "CIS_Palo_Alto_Firewall_10_Benchmark_v1.3.0.pdf",
                re.compile(r"^(\d+\.\d+(?:\.\d+){1,2})\s+.+"),
            ),
            (
                "CIS Palo Alto Firewall 11 Benchmark v1.2.0",
                "Palo Alto",
                base_dir / "data" / "CIS_Palo_Alto_Firewall_11_Benchmark_v1.2.0.pdf",
                re.compile(r"^(\d+\.\d+(?:\.\d+){1,2})\s+.+"),
            ),
            (
                "CIS FortiGate 7.0.x Benchmark v1.4.0",
                "FortiGate",
                base_dir / "data" / "CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf",
                re.compile(r"^(\d+\.\d+)\s+.+"),
            ),
            (
                "CIS FortiGate 7.4.x Benchmark v1.0.1",
                "FortiGate",
                base_dir / "data" / "CIS_FortiGate_7.4.x_Benchmark_v1.0.1.pdf",
                re.compile(r"^(\d+\.\d+)\s+.+"),
            ),
        ]

    all_controls: List[CisControl] = []
    errors: List[Dict[str, str]] = []

    # Default: accept 2-4 digit segments: "1.1" or "1.1.1" or "1.1.1.1"
    generic_pattern = re.compile(r"^(\d+(?:\.\d+){1,3})\s+.+")
    for benchmark_name, device_type, pdf_path, pattern in sources:
        all_controls.extend(
            parse_benchmark(
                pdf_path,
                benchmark_name=benchmark_name,
                device_type=device_type,
                number_pattern=pattern or generic_pattern,
                errors=errors,
            )
        )

    # Serialize to JSON in the same column order as cis_rules_combined.csv
    result: List[Dict[str, object]] = []
    for c in all_controls:
        obj = {
            "rule_id": c.rule_id,
            "benchmark": c.benchmark,
            "device_type": c.device_type,
            "control_name": c.control_name,
            "cis_level": c.cis_level,
            "description": c.description,
            "expected_values": c.expected_values,
            "validation_logic": c.validation_logic,
            "remediation_steps": c.remediation_steps,
            "severity": c.severity,
            "is_active": c.is_active,
            "references_text": c.references,
            "audit": c.audit,
            "rationale": c.rationale,
            "impact": c.impact,
        }
        result.append(obj)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    report = build_report(output_path, sources, all_controls, errors)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Wrote {len(result)} controls to {output_path}")
    print(f"Wrote report to {report_path}")
    if errors:
        print(f"Warnings: {len(errors)} issue(s). See report for details.")


if __name__ == "__main__":
    main()

