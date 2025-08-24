import argparse
import os
import fnmatch
import multiprocessing
import sys # Import sys module
from typing import List

# For colored output
from colorama import Fore, Style, init
init(autoreset=True) # Initialize colorama to reset colors after each print

from aegiscan.rules import load_rules_from_yaml, RuleSeverity
from aegiscan.analyzer import Analyzer, Finding
from aegiscan.output import convert_to_sarif, convert_to_jsonl, pretty_print_findings

AEGISCAN_LOGO = f"{Fore.GREEN}AEGISCAN{Style.RESET_ALL}{Fore.CYAN} - Python SAST Tool{Style.RESET_ALL}"

def _analyze_single_file(args_tuple) -> List[Finding]:
    filepath, file_content, rules_path, project_root = args_tuple
    rules = load_rules_from_yaml(rules_path)
    analyzer = Analyzer(rules, project_root)
    return analyzer.analyze_file(filepath, file_content)

def scan_path(path: str, rules_path: str, exclude_patterns: List[str], project_root: str, show_taint: bool) -> List[Finding]:
    all_findings: List[Finding] = []
    files_to_analyze = []

    # Initialize Analyzer once for all files
    rules = load_rules_from_yaml(rules_path)
    analyzer = Analyzer(rules, project_root, show_taint)

    python_files = []
    for root, dirnames, filenames in os.walk(path):
        # Exclude directories based on patterns
        dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, p) for p in exclude_patterns)]

        for filename in filenames:
            if filename.endswith(".py") and not any(fnmatch.fnmatch(filename, p) for p in exclude_patterns):
                filepath = os.path.join(root, filename)
                python_files.append(filepath)

    for filepath in sorted(python_files):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                file_content = f.read()
            findings_list = analyzer.analyze_file(filepath, file_content)
            all_findings.extend(findings_list)
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")

    return all_findings

def main():
    # Logo ve hoş geldiniz mesajı şimdi description içinde yönetilecek
    print(f"{Fore.GREEN}AEGISCAN{Style.RESET_ALL}{Fore.CYAN} - Python SAST Tool{Style.RESET_ALL}")
    print("\n")
    sys.stdout.flush()
    
    # ASCII art logo description içine eklendi
    app_description = f"{Fore.GREEN}AEGISCAN{Style.RESET_ALL}{Fore.CYAN} - Python SAST Tool{Style.RESET_ALL}\n\n{Fore.CYAN}Aegiscan: A rule-based SAST tool for Python code.{Style.RESET_ALL}"

    parser = argparse.ArgumentParser(
        description=app_description,
        formatter_class=argparse.RawTextHelpFormatter # Preserve formatting for descriptions
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan Python code for vulnerabilities.")
    scan_parser.add_argument("path", type=str, help="Path to the code to scan.")
    scan_parser.add_argument("--rules", dest="rules_path", type=str, default="./aegiscan/rules",
                             help="Path to the directory containing YAML rule files (default: ./aegiscan/rules).")
    scan_parser.add_argument("--format", dest="output_format", type=str, default="pretty",
                             choices=["sarif", "jsonl", "pretty"],
                             help="Output format (default: pretty).")
    scan_parser.add_argument("--output", dest="output_file", type=str, help="Output file path.")
    scan_parser.add_argument("--exclude", dest="exclude_patterns", type=str, default="venv,tests",
                             help="Comma-separated glob patterns to exclude files/directories (e.g., \"venv,tests,*.min.js\").")
    scan_parser.add_argument("--fail-on-severity", dest="fail_on_severity", type=str,
                             choices=["high", "medium", "low", "info"], default=None,
                             help="Exit with non-zero code if findings with this severity or higher are found.")
    scan_parser.add_argument("--baseline", dest="baseline_file", type=str, default=None,
                             help="Path to a baseline JSON file to suppress existing findings.")
    scan_parser.add_argument("--update-baseline", action="store_true",
                             help="Update the baseline file with current findings.")
    scan_parser.add_argument("--show-taint", action="store_true",
                             help="Show detailed taint propagation summary for findings.")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "scan":
        exclude_patterns = [p.strip() for p in args.exclude_patterns.split(',') if p.strip()]
        findings = scan_path(args.path, args.rules_path, exclude_patterns, args.path, args.show_taint)

        if args.output_format == "sarif":
            output_content = convert_to_sarif(findings)
        elif args.output_format == "jsonl":
            output_content = convert_to_jsonl(findings)
        else: # pretty
            pretty_print_findings(findings)
            output_content = None # Pretty print directly to stdout

        if output_content and args.output_file:
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(output_content)
        elif output_content:
            print(output_content)

        if args.fail_on_severity:
            severity_map = {
                "info": 0,
                "low": 1,
                "medium": 2,
                "high": 3
            }
            min_severity_level = severity_map[args.fail_on_severity.lower()]
            for finding in findings:
                if severity_map[finding.severity.value.lower()] >= min_severity_level:
                    exit(1) # Exit with error code

if __name__ == "__main__":
    # Logo artık main fonksiyonunun başında veya __main__ bloğunda ayrı olarak yazdırılmayacak,
    # description parametresi aracılığıyla argparse tarafından yönetilecek.
    main()
