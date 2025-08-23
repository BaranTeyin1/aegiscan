import ast
import os
import re
from typing import List, Dict, Any, Optional

from aegiscan.rules import Rule, RuleSeverity
from aegiscan.visitor import AegiscanVisitor
from aegiscan.taint import TaintTracker

class Finding:
    def __init__(self, file: str, start_line: int, end_line: int, rule_id: str, severity: RuleSeverity,
                 message: str, code_snippet: str, confidence: str, fingerprint: str, cwe: str, fix: Optional[str] = None):
        self.file = file
        self.start_line = start_line
        self.end_line = end_line
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.code_snippet = code_snippet
        self.confidence = confidence
        self.fingerprint = fingerprint
        self.cwe = cwe
        self.fix = fix

    def to_dict(self):
        return {
            "file": self.file,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "ruleId": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "codeSnippet": self.code_snippet,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "cwe": self.cwe,
            "fix": self.fix
        }

class Analyzer:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        self.findings: List[Finding] = []

    def _get_name_from_node(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Recursively get the base name, then append the attribute
            base_name = self._get_name_from_node(node.value)
            if base_name:
                return f"{base_name}.{node.attr}"
            return None
        elif isinstance(node, ast.Call):
            # Get the name of the function being called
            return self._get_name_from_node(node.func)
        return None

    def analyze_file(self, filepath: str, file_content: str) -> List[Finding]:
        self.findings = [] # Reset findings for each file
        
        # Parse ignore annotations
        ignored_lines: Dict[int, List[str]] = self._parse_ignore_annotations(file_content)

        try:
            tree = ast.parse(file_content, filename=filepath)
        except SyntaxError as e:
            print(f"Syntax error in {filepath}: {e}")
            return []

        visitor = AegiscanVisitor(file_content)
        visitor.visit(tree)

        taint_tracker = TaintTracker(visitor.aliases)

        # Collect initial sources from function calls (e.g., input(), request.args.get())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_full_name = visitor.get_fully_qualified_name(self._get_name_from_node(node.value.func))
                for rule in self.rules:
                    for source_pattern in rule.sources:
                        # Check if the called function's full name starts with a source pattern
                        if func_full_name and func_full_name.startswith(source_pattern):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    taint_tracker.add_source(target.id)
                                    taint_tracker.handle_call_return(func_full_name, target.id) # Mark return as tainted

        # First pass to propagate simple assignments and collected sources
        for node in ast.walk(tree):
            # Propagate taint through direct assignments
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Name) and taint_tracker.is_tainted(node.value.id):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            taint_tracker.add_source(target.id)
            # Mark function arguments that are considered sources by rules (this part needs more precise logic)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                for rule in self.rules:
                    for source_pattern in rule.sources:
                        # Simplified: If a rule defines a source that's a function name,
                        # we assume its arguments might become tainted if called by user input.
                        # This is an area for more advanced AST pattern matching.
                        pass
            
            taint_tracker.propagate_taint(node)

        # Second pass to identify sinks and report findings
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_full_name = visitor.get_fully_qualified_name(self._get_name_from_node(node.func))

                for rule in self.rules:
                    # Check for sinks
                    if func_full_name in rule.sinks:
                        is_tainted_sink = False
                        # Check if any argument to the sink function is tainted
                        for arg in node.args:
                            if isinstance(arg, ast.Name) and taint_tracker.is_tainted(arg.id):
                                is_tainted_sink = True
                                break
                            # Add basic handling for f-strings and joined strings for command injection
                            elif isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                                for sub_node in ast.walk(arg):
                                    if isinstance(sub_node, ast.Name) and taint_tracker.is_tainted(sub_node.id):
                                        is_tainted_sink = True
                                        break
                                if is_tainted_sink: break
                            elif isinstance(arg, ast.Call): # Handle cases like os.system(cmd_builder(user_input))
                                func_in_arg_full_name = visitor.get_fully_qualified_name(self._get_name_from_node(arg.func))
                                if taint_tracker.is_tainted(func_in_arg_full_name): # If the return of this call was marked tainted
                                    is_tainted_sink = True
                                    break
                                for sub_arg in arg.args:
                                    if isinstance(sub_arg, ast.Name) and taint_tracker.is_tainted(sub_arg.id):
                                        is_tainted_sink = True
                                        break
                                if is_tainted_sink: break

                        # Check for sanitizers (very basic for now)
                        is_sanitized = False
                        for sanitizer_pattern in rule.sanitizers:
                            # This part needs more sophisticated AST pattern matching
                            if sanitizer_pattern in func_full_name: # Placeholder: check if sanitizer name is in func name
                                is_sanitized = True
                                break

                        if is_tainted_sink and not is_sanitized:
                            # For a proof-of-concept, we're using the simple 'eval' example from visitor.py
                            # In a full implementation, we'd generate findings more dynamically based on rule matches.
                            code_snippet = ast.get_source_segment(file_content, node)
                            if code_snippet is None:
                                code_snippet = "Unable to retrieve code snippet."

                            # Check for suppression
                            if rule.id in ignored_lines.get(node.lineno, []):
                                continue

                            self.findings.append(Finding(
                                file=filepath,
                                start_line=node.lineno,
                                end_line=node.end_lineno,
                                rule_id=rule.id,
                                severity=rule.severity,
                                message=rule.message,
                                code_snippet=code_snippet,
                                confidence="HIGH", # Placeholder
                                fingerprint=f"{filepath}:{node.lineno}:{rule.id}", # Simple fingerprint
                                cwe=rule.cwe,
                                fix=rule.fix
                            ))

            # This is where we could integrate general AST pattern matching from rules.patterns
            # For now, it's focused on taint tracking for calls.

        # Include findings from visitor (like the eval example)
        for visitor_finding in visitor.findings:
            # Check for suppression for visitor findings
            if visitor_finding["ruleId"] in ignored_lines.get(visitor_finding["startLine"], []):
                continue

            # Ensure file and codeSnippet are correctly set
            visitor_finding["file"] = filepath
            # Use the codeSnippet directly from visitor_finding as it's already a string representation
            code_snippet = visitor_finding["codeSnippet"]
            
            self.findings.append(Finding(
                file=visitor_finding["file"],
                start_line=visitor_finding["startLine"],
                end_line=visitor_finding["endLine"], # Changed back to "endLine"
                rule_id=visitor_finding["ruleId"],
                severity=RuleSeverity(visitor_finding["severity"].lower()),
                message=visitor_finding["message"],
                code_snippet=code_snippet,
                confidence=visitor_finding["confidence"],
                fingerprint=f"{filepath}:{visitor_finding["startLine"]}:{visitor_finding["ruleId"]}",
                cwe=visitor_finding["cwe"],
                fix=visitor_finding["fix"]
            ))

        return self.findings

    def _parse_ignore_annotations(self, file_content: str) -> Dict[int, List[str]]:
        ignored_lines: Dict[int, List[str]] = {}
        lines = file_content.splitlines()
        for i, line in enumerate(lines):
            match = re.search(r"#\s*sast:\s*ignore\s+([A-Z0-9-,\s]+)", line, re.IGNORECASE)
            if match:
                rule_ids = [r.strip() for r in match.group(1).split(',') if r.strip()]
                ignored_lines[i + 1] = rule_ids # Line numbers are 1-based
        return ignored_lines
