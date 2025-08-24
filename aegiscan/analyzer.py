import ast
import os
import re
from typing import List, Dict, Any, Optional

from aegiscan.rules import Rule, RuleSeverity
from aegiscan.visitor import AegiscanVisitor
from aegiscan.taint import TaintTracker
from aegiscan.symbols import SymbolResolver, SymbolType # Import SymbolResolver

class Finding:
    def __init__(self, file: str, start_line: int, end_line: int, rule_id: str, severity: RuleSeverity,
                 message: str, code_snippet: str, confidence: str, fingerprint: str, cwe: str, fix: Optional[str] = None, taint_trace: Optional[List[str]] = None):
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
        self.taint_trace = taint_trace

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
            "fix": self.fix,
            "taintTrace": self.taint_trace
        }

class Analyzer:
    def __init__(self, rules: List[Rule], project_root: str, show_taint: bool = False):
        self.rules = rules
        self.findings: List[Finding] = []
        self.project_root = project_root
        self.symbol_resolver = SymbolResolver(project_root)
        self.symbol_resolver.collect_symbols(project_root) # Collect all symbols at initialization
        
        # Initialize TaintTracker once, globally for the analyzer instance
        self.taint_tracker = TaintTracker(aliases={}, show_taint=show_taint) # Aliases will be updated per file

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

    def _is_node_tainted(self, node: ast.AST) -> bool:
        # Recursively check if any Name node within the given AST node is tainted.
        if isinstance(node, ast.Name):
            return self.taint_tracker.is_tainted(node.id)
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            for sub_node in ast.walk(node):
                if isinstance(sub_node, ast.Name) and self.taint_tracker.is_tainted(sub_node.id):
                    return True
        elif isinstance(node, ast.Call): # If a call itself returns a tainted value
            called_func_name = self._get_name_from_node(node.func)
            if called_func_name and self.taint_tracker.is_function_return_tainted(called_func_name):
                return True
        # Add other AST node types as needed for more comprehensive taint checking
        return False

    def analyze_file(self, filepath: str, file_content: str) -> List[Finding]:
        self.findings = [] # Reset findings for each file
        self.taint_tracker.tainted_vars.clear() # Clear local tainted variables for this file analysis
        
        # Parse ignore annotations
        ignored_lines: Dict[int, List[str]] = self._parse_ignore_annotations(file_content)

        try:
            tree = ast.parse(file_content, filename=filepath)
        except SyntaxError as e:
            print(f"Syntax error in {filepath}: {e}")
            return []
        
        # Determine module name for the current file
        relative_path = os.path.relpath(filepath, self.project_root)
        module_name = relative_path.replace(os.sep, ".")
        if module_name.endswith(".py"):
            module_name = module_name[:-3]
        if module_name.endswith(".__init__"):
            module_name = module_name[:-9]

        visitor = AegiscanVisitor(file_content, filepath, module_name) # Pass file_path and module_name
        visitor.visit(tree)

        # Update the taint_tracker's aliases for the current file's context
        self.taint_tracker.aliases = visitor.aliases

        # --- First Pass: Collect initial sources and mark inter-procedural call parameters/returns ---
        for node in ast.walk(tree):
            # Collect initial sources from function calls (e.g., input(), request.args.get())
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                # Resolve the called function's FQN using SymbolResolver
                called_func_name = self._get_name_from_node(node.value.func)
                resolved_symbol = self.symbol_resolver.resolve_call(module_name, called_func_name, visitor.imports)
                
                func_full_name = resolved_symbol.fully_qualified_name if resolved_symbol else called_func_name
                
                for rule in self.rules:
                    for source_pattern in rule.sources:
                        # Check if the called function's full name starts with a source pattern
                        if func_full_name and func_full_name.startswith(source_pattern):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    self.taint_tracker.add_source(target.id)
                                    # Mark the return of the call as tainted
                                    self.taint_tracker.handle_call_return(func_full_name, target.id)
                                    # If the resolved symbol is a function, consider its return tainted
                                    if resolved_symbol and resolved_symbol.symbol_type == SymbolType.FUNCTION:
                                        self.taint_tracker.mark_function_return_tainted(resolved_symbol.fully_qualified_name)

            # Inter-procedural taint propagation at call sites (caller to callee)
            # Propagate taint from tainted arguments to the callee's parameters
            if isinstance(node, ast.Call):
                called_func_name = self._get_name_from_node(node.func)
                resolved_symbol = self.symbol_resolver.resolve_call(module_name, called_func_name, visitor.imports)
                
                if resolved_symbol and resolved_symbol.symbol_type == SymbolType.FUNCTION:
                    # Map call arguments to function parameters
                    func_params_info = self.symbol_resolver.global_symbol_table.get(resolved_symbol.fully_qualified_name)
                    if func_params_info and func_params_info.parameters:
                        for i, arg_node in enumerate(node.args):
                            if i < len(func_params_info.parameters): # Positional arguments
                                param_name_in_callee = func_params_info.parameters[i]['name']
                                if self._is_node_tainted(arg_node):
                                    self.taint_tracker.mark_function_parameter_tainted(
                                        resolved_symbol.fully_qualified_name,
                                        param_name_in_callee
                                    )
                            # TODO: Handle keyword arguments for more robust propagation

        # --- Second Pass: Propagate taint from function parameters to local variables within their definitions ---
        for node in ast.walk(tree):
            # If this node is a function definition, check its parameters for taint
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_fqn = f"{module_name}.{node.name}" # Construct FQN for function defined in current file
                func_symbol_info = self.symbol_resolver.global_symbol_table.get(func_fqn)
                if func_symbol_info and func_symbol_info.parameters:
                    for param_info in func_symbol_info.parameters:
                        param_name = param_info['name']
                        # Check if this parameter was marked as tainted by a call in another file (or earlier in this file)
                        if self.taint_tracker.is_function_parameter_tainted(func_fqn, param_name):
                            # Mark the local variable corresponding to this parameter as tainted
                            self.taint_tracker.add_source(param_name)

        # --- Third Pass: Full intra-procedural taint propagation and sink detection ---
        for node in ast.walk(tree):
            # Propagate taint through direct assignments and calls within the file
            self.taint_tracker.propagate_taint(node)

            if isinstance(node, ast.Call):
                # Resolve the called function's FQN using SymbolResolver
                called_func_name = self._get_name_from_node(node.func)
                resolved_symbol = self.symbol_resolver.resolve_call(module_name, called_func_name, visitor.imports)
                
                func_full_name = resolved_symbol.fully_qualified_name if resolved_symbol else called_func_name

                for rule in self.rules:
                    # Check for sinks
                    if func_full_name in rule.sinks:
                        is_tainted_sink = False
                        # Check if any argument to the sink function is tainted
                        for arg in node.args:
                            if self._is_node_tainted(arg):
                                is_tainted_sink = True
                                break
                            elif isinstance(arg, ast.Call): # Handle cases like os.system(cmd_builder(user_input))
                                # Resolve the function called within the argument
                                func_in_arg_name = self._get_name_from_node(arg.func)
                                resolved_arg_func = self.symbol_resolver.resolve_call(module_name, func_in_arg_name, visitor.imports)
                                
                                func_in_arg_full_name = resolved_arg_func.fully_qualified_name if resolved_arg_func else func_in_arg_name

                                if self._is_node_tainted(arg) or self.taint_tracker.is_function_return_tainted(func_in_arg_full_name): # Check if the return of this call was marked tainted
                                    is_tainted_sink = True
                                    break
                                # For sub_args, _is_node_tainted handles the recursive check
                                # for sub_arg in arg.args:
                                #     if self._is_node_tainted(sub_arg):
                                #         is_tainted_sink = True
                                #         break
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

                            taint_trace = []
                            if self.taint_tracker.show_taint:
                                # Retrieve taint trace for the finding
                                taint_trace = self.taint_tracker.get_taint_trace() # Removed rule.id argument

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
                                fix=rule.fix,
                                taint_trace=taint_trace
                            ))

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
                fix=visitor_finding["fix"],
                taint_trace=[] # Visitor findings don't have taint trace for now
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
