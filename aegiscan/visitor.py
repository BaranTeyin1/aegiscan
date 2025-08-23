import ast
from typing import List, Dict, Any

class AegiscanVisitor(ast.NodeVisitor):
    def __init__(self, file_content: str):
        self.findings = []
        self.aliases: Dict[str, str] = {}
        self.imports: Dict[str, str] = {}
        self.file_content = file_content

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases[alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            full_name = f"{node.module}.{alias.name}" if node.module else alias.name
            if alias.asname:
                self.aliases[alias.asname] = full_name
            else:
                self.aliases[alias.name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # The eval finding is now handled by rule AEGISCAN-002, so removing this hardcoded finding.
        # if isinstance(node.func, ast.Name) and node.func.id == 'eval':
        #     self.findings.append({
        #         "file": "current_file.py", # This will be filled by the analyzer
        #         "startLine": node.lineno,
        #         "endLine": node.end_lineno,
        #         "ruleId": "RCE-001",
        #         "severity": "HIGH",
        #         "message": "Potential Remote Code Execution via eval()",
        #         "codeSnippet": ast.get_source_segment(self.file_content, node),
        #         "confidence": "HIGH",
        #         "fingerprint": "",
        #         "cwe": "CWE-94",
        #         "fix": "Use ast.literal_eval for safe evaluation."
        #     })
        self.generic_visit(node)

    def get_fully_qualified_name(self, name: str) -> str:
        return self.aliases.get(name, name)
