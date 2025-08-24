import json
import os
from typing import List, Optional
import sys

# External library for SARIF, assumed to be installed via setup.py
import sarif_om as sarif

# For colored output
from colorama import Fore, Style, init
init(autoreset=True) # Initialize colorama to reset colors after each print

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
                "fix": finding.fix,
                "taintTrace": finding.taint_trace # Add taint trace to SARIF properties
            }
        ))

    tool = sarif.Tool(driver=sarif.ToolComponent(name=tool_name, rules=rules))
    run = sarif.Run(tool=tool, results=results)
    log = sarif.Sarif(runs=[run])

    return log.json(indent=2)

def convert_to_jsonl(findings: List[Finding]) -> str:
    jsonl_output = []
    for finding in findings:
        jsonl_output.append(json.dumps(finding.to_dict())) # to_dict already includes taint_trace
    return "\n".join(jsonl_output)

def pretty_print_findings(findings: List[Finding]):
    if not findings:
        print(f"{Fore.GREEN}No findings found.{Style.RESET_ALL}")
        return

    for finding in findings:
        severity_color = {
            RuleSeverity.HIGH: Fore.RED,
            RuleSeverity.MEDIUM: Fore.YELLOW,
            RuleSeverity.LOW: Fore.CYAN,
            RuleSeverity.INFO: Fore.BLUE,
        }.get(finding.severity, Fore.WHITE)

        print(f"{Fore.LIGHTBLACK_EX}--------------------------------------------------{Style.RESET_ALL}")
        print(f"Rule ID: {Fore.WHITE}{finding.rule_id}{Style.RESET_ALL}")
        print(f"Severity: {severity_color}{finding.severity.value.upper()}{Style.RESET_ALL}")
        print(f"CWE: {Fore.MAGENTA}{finding.cwe}{Style.RESET_ALL}")
        print(f"File: {Fore.CYAN}{finding.file}{Style.RESET_ALL}")
        print(f"Line: {Fore.CYAN}{finding.start_line}-{finding.end_line}{Style.RESET_ALL}")
        print(f"Message: {Fore.WHITE}{finding.message}{Style.RESET_ALL}")
        print(f"Code Snippet:\n{Fore.LIGHTBLACK_EX}{finding.code_snippet}{Style.RESET_ALL}")
        if finding.taint_trace:
            print(f"\n{Fore.MAGENTA}Taint Trace:{Style.RESET_ALL}")
            for step in finding.taint_trace:
                print(f"{Fore.MAGENTA}- {step}{Style.RESET_ALL}")
        if finding.fix:
            print(f"Suggested Fix: {Fore.GREEN}{finding.fix}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLACK_EX}--------------------------------------------------\n{Style.RESET_ALL}")
