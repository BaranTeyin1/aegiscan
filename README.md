# Aegiscan - Rule-Based SAST for Python

Aegiscan is a static application security testing (SAST) tool designed to identify vulnerabilities in Python code based on a set of predefined rules. It leverages Abstract Syntax Trees (AST) for code analysis, providing a robust and extensible framework for security auditing.

## Features

-   **AST-Based Analysis**: Uses Python's Abstract Syntax Trees for precise code pattern matching.
-   **Rule-Based Detection**: Configurable rules defined in YAML for various vulnerability types.
-   **Lightweight Taint Tracking**: Intra-file data flow analysis from sources to sinks.
-   **Alias Resolution**: Handles `import X as Y` and `from X import Y as Z` statements.
-   **Multiple Output Formats**: Generates findings in SARIF 2.1.0, JSONL, and human-readable "pretty" formats.
-   **CLI Interface**: Easy-to-use command-line interface for scanning projects.
-   **Finding Suppression**: Supports `# sast: ignore <RULE_ID>` annotations to suppress false positives.
-   **Performance**: Utilizes multiprocessing for efficient scanning of large codebases.
-   **Extensible**: Easily add new rules to detect custom vulnerability patterns.

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/yourusername/aegiscan.git
    cd aegiscan
    ```

2.  **Install dependencies:**

    ```bash
    pip install -e .
    ```

    This will install `aegiscan` as an editable package and its dependencies (`PyYAML`, `sarif_om`).

## Usage

To scan a directory, use the `scan` command:

```bash
aegiscan scan <path_to_code> [--rules <rules_directory>] [--format <output_format>] [--output <output_file>] [--exclude <patterns>] [--fail-on-severity <severity_level>] [--baseline <baseline_file>] [--update-baseline]
```

### Examples

-   **Scan a project and print pretty output (default):**

    ```bash
    aegiscan scan ./my_project
    ```

-   **Scan and output to SARIF format:**

    ```bash
    aegiscan scan ./my_project --format sarif --output results.sarif
    ```

-   **Scan with custom rules and exclude directories:**

    ```bash
    aegiscan scan ./my_project --rules ./custom_rules --exclude "tests,docs,vendor"
    ```

-   **Fail CI build if high-severity findings are found:**

    ```bash
    aegiscan scan ./my_project --fail-on-severity high
    ```

## Rule Definition

Rules are defined in YAML files. Each rule specifies:

-   `id`: Unique identifier for the rule (e.g., `AEGISCAN-001`)
-   `name`: Human-readable name (e.g., `Command Injection`)
-   `severity`: `HIGH`, `MEDIUM`, `LOW`, `INFO`
-   `cwe`: Common Weakness Enumeration ID (e.g., `CWE-77`)
-   `description`: Detailed explanation of the vulnerability.
-   `sources`: List of functions/variables considered as untrusted input sources.
-   `sinks`: List of functions/methods where tainted data should not reach.
-   `sanitizers`: List of functions that clean or neutralize tainted data.
-   `patterns`: (Advanced) AST patterns for more complex detection logic.
-   `message`: The finding message to display.
-   `examples.vuln`: Code snippets demonstrating vulnerable patterns.
-   `examples.safe`: Code snippets demonstrating safe patterns.
-   `fix`: Suggested fix for the vulnerability.

Example `command_injection.yaml`:

```yaml
id: AEGISCAN-001
name: Command Injection
severity: HIGH
cwe: CWE-77
description: Detects potential command injection vulnerabilities...
sources:
  - "input"
  - "request.args"
sinks:
  - "os.system"
  - "subprocess.run"
sanitizers:
  - "shlex.quote"
message: "User-controlled input flows into a command execution function..."
examples:
  vuln:
    - |
      import os
      user_input = input()
      os.system("echo " + user_input)
  safe:
    - |
      import os
      import shlex
      user_input = input()
      os.system("echo " + shlex.quote(user_input))
fix: "Use parameterized execution functions or `shlex.quote`..."
```

## Development

### Running Tests

To run the test suite, ensure you have `pytest` installed (`pip install pytest`) and then run:

```bash
pytest
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
