import json
import os
from typing import List

# External library for SARIF, assumed to be installed via setup.py
import sarif_om as sarif

from aegiscan.analyzer import Finding
from aegiscan.rules import RuleSeverity

def convert_to_sarif(findings: List[Finding], tool_name: str = "Aegiscan") -> str:
    results = []
    rules = []
    rule_ids_seen = set()

    for finding in findings:
        if finding.rule_id not in rule_ids_seen:
            rules.append(sarif.ToolComponent(name=finding.rule_id, description=finding.message, id=finding.rule_id))
            rule_ids_seen.add(finding.rule_id)

        level = {
            RuleSeverity.HIGH: "error",
            RuleSeverity.MEDIUM: "warning",
            RuleSeverity.LOW: "note",
            RuleSeverity.INFO: "note",
        }.get(finding.severity, "note")

        results.append(sarif.Result(
            rule_id=finding.rule_id,
            message=sarif.Message(text=finding.message),
            locations=[
                sarif.Location(
                    physical_location=sarif.PhysicalLocation(
                        artifact_location=sarif.ArtifactLocation(uri=os.path.abspath(finding.file)),
                        region=sarif.Region(
                            start_line=finding.start_line,
                            end_line=finding.end_line,
                            # The SARIF spec defines 'snippet' as the full text of the region
                            # which can be a single line or multiple lines.
                            snippet=sarif.ArtifactContent(text=finding.code_snippet)
                        )
                    )
                )
            ],
            level=level,
            properties={
                "cwe": finding.cwe,
                "confidence": finding.confidence,
                "fix": finding.fix
            }
        ))

    tool = sarif.Tool(driver=sarif.ToolComponent(name=tool_name, rules=rules))
    run = sarif.Run(tool=tool, results=results)
    log = sarif.Sarif(runs=[run])

    return log.json(indent=2)

def convert_to_jsonl(findings: List[Finding]) -> str:
    jsonl_output = []
    for finding in findings:
        jsonl_output.append(json.dumps(finding.to_dict()))
    return "\n".join(jsonl_output)

def pretty_print_findings(findings: List[Finding]):
    if not findings:
        print("No findings found.")
        return

    for finding in findings:
        print(f"--------------------------------------------------")
        print(f"Rule ID: {finding.rule_id}")
        print(f"Severity: {finding.severity.value.upper()}")
        print(f"CWE: {finding.cwe}")
        print(f"File: {finding.file}")
        print(f"Line: {finding.start_line}-{finding.end_line}")
        print(f"Message: {finding.message}")
        print(f"Code Snippet:\n{finding.code_snippet}")
        if finding.fix:
            print(f"Suggested Fix: {finding.fix}")
        print(f"--------------------------------------------------\n")
