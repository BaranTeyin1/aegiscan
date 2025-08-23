import pytest
import os
from pathlib import Path

from aegiscan.rules import load_rules_from_yaml, RuleSeverity, Rule
from aegiscan.analyzer import Analyzer, Finding
from aegiscan.visitor import AegiscanVisitor
from aegiscan.taint import TaintTracker
from aegiscan.cli.cli import scan_path

# Helper function to get the absolute path to the rules directory
@pytest.fixture
def rules_dir():
    return Path(__file__).parent.parent / "aegiscan" / "rules"

# Helper to create a temporary file for testing
@pytest.fixture
def temp_file(tmp_path):
    def _create_temp_file(content, filename="test_file.py"):
        file_path = tmp_path / filename
        file_path.write_text(content)
        return file_path
    return _create_temp_file

# --- Unit Tests for Rules Module ---
def test_load_rules_from_yaml(rules_dir):
    rules = load_rules_from_yaml(str(rules_dir))
    assert len(rules) >= 6 # Should load at least the 6 example rules
    assert any(rule.id == "AEGISCAN-001" for rule in rules)
    assert any(rule.name == "Command Injection" for rule in rules)
    assert all(isinstance(rule, Rule) for rule in rules)

# --- Unit Tests for Visitor Module ---
def test_visitor_aliases():
    code = """import os as _os
from subprocess import run as _run
_os.system("ls")
_run("ls")
"""
    visitor = AegiscanVisitor(code)
    tree = ast.parse(code)
    visitor.visit(tree)
    assert visitor.get_fully_qualified_name("_os") == "os"
    assert visitor.get_fully_qualified_name("_run") == "subprocess.run"

def test_visitor_eval_finding():
    code = "eval(user_input)"
    visitor = AegiscanVisitor(code)
    tree = ast.parse(code)
    visitor.visit(tree)
    assert len(visitor.findings) == 1
    assert visitor.findings[0]["ruleId"] == "RCE-001"

# --- Unit Tests for Taint Module ---
def test_taint_propagation():
    aliases = {"input_data": "input"}
    tracker = TaintTracker(aliases)
    tracker.add_source("user_input")
    assert tracker.is_tainted("user_input")

    code = """a = user_input
b = a
c = 'safe'
d = some_func(b)
"""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        tracker.propagate_taint(node)

    assert tracker.is_tainted("a")
    assert tracker.is_tainted("b")
    assert not tracker.is_tainted("c")
    # Basic propagation doesn't trace function calls, so 'd' should not be tainted by this simple propagation
    assert not tracker.is_tainted("d")

# --- Unit Tests for Analyzer Module ---
def test_analyzer_command_injection(rules_dir, temp_file):
    rules = load_rules_from_yaml(str(rules_dir))
    analyzer = Analyzer(rules)

    vuln_code = """import os
user_input = input("cmd: ")
os.system("echo " + user_input)
"""
    vuln_file = temp_file(vuln_code, "vuln_cmd.py")
    findings = analyzer.analyze_file(str(vuln_file), vuln_code)
    assert len(findings) == 1
    assert findings[0].rule_id == "AEGISCAN-001"

    safe_code = """import os
import shlex
user_input = input("cmd: ")
os.system("echo safe_command")
"""
    safe_file = temp_file(safe_code, "safe_cmd.py")
    findings = analyzer.analyze_file(str(safe_file), safe_code)
    assert len(findings) == 0

def test_analyzer_rce_eval(rules_dir, temp_file):
    rules = load_rules_from_yaml(str(rules_dir))
    analyzer = Analyzer(rules)

    vuln_code = """user_input = input("Enter code: ")
eval(user_input)
"""
    vuln_file = temp_file(vuln_code, "vuln_rce.py")
    findings = analyzer.analyze_file(str(vuln_file), vuln_code)
    assert len(findings) >= 1 # Could be 1 from visitor, or more if taint also picks it up
    assert any(f.rule_id == "RCE-001" or f.rule_id == "AEGISCAN-002" for f in findings)

    safe_code = """import ast
user_input = input("Enter data: ")
safe_data = ast.literal_eval(user_input)
"""
    safe_file = temp_file(safe_code, "safe_rce.py")
    findings = analyzer.analyze_file(str(safe_file), safe_code)
    # The eval visitor finding is very basic, might still trigger if not fully integrated with taint+rules
    # For this test, we expect no RCE-002 from the rules if sanitization works.
    assert not any(f.rule_id == "AEGISCAN-002" for f in findings)

# --- E2E Test ---
def test_e2e_scan(rules_dir, tmp_path):
    # Create a dummy project structure with a vulnerable file
    dummy_project_path = tmp_path / "dummy_project"
    dummy_project_path.mkdir()
    (dummy_project_path / "app.py").write_text("""import os
user_input = input("cmd: ")
os.system(user_input)
""")

    # Run the scan via cli function
    findings = scan_path(str(dummy_project_path), str(rules_dir), exclude_patterns=["venv", "tests"])
    assert len(findings) >= 1
    assert any(f.rule_id == "AEGISCAN-001" for f in findings)
    assert findings[0].file == str(dummy_project_path / "app.py")
