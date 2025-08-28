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

        self.current_module_name: Optional[str] = None # To store module name of the currently analyzed file
        self.current_visitor: Optional[AegiscanVisitor] = None # To store visitor instance for current file

    def _get_name_from_node(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Recursively get the base name, then append the attribute
            # For class attributes (e.g., self.data), we need the fully qualified name
            # For module attributes (e.g., requests.get), we also need the FQN
            # This can be complex, so we will use the _get_fully_qualified_attribute_name for attributes.
            return self._get_fully_qualified_attribute_name(node, self.current_module_name, self.current_visitor)
        elif isinstance(node, ast.Call):
            # Get the name of the function being called
            return self._get_name_from_node(node.func)
        return None

    def _get_fully_qualified_attribute_name(self, node: ast.Attribute, module_name: str, visitor: AegiscanVisitor) -> Optional[str]:
        """
        Recursively gets the fully qualified name of an attribute.
        e.g., self.request.args.get -> my_module.MyClass.request.args.get
        """
        if isinstance(node.value, ast.Name):
            # Check if it's a 'self' attribute within a class context
            if node.value.id == "self" and visitor.current_class:
                return f"{module_name}.{visitor.current_class}.{node.attr}"
            # Check if it's a module or alias
            base_name = visitor.aliases.get(node.value.id, node.value.id)
            return f"{base_name}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            # Recursively get the FQN of the parent attribute
            parent_fqn = self._get_fully_qualified_attribute_name(node.value, module_name, visitor)
            if parent_fqn:
                return f"{parent_fqn}.{node.attr}"
        elif isinstance(node.value, ast.Call):
            # If the base is a function call (e.g., some_func().attribute)
            # This is complex and might require more advanced heap analysis.
            # For now, we'll just get the name of the function being called.
            func_name = self._get_name_from_node(node.value.func)
            if func_name:
                return f"{func_name}.{node.attr}"
        return None

    def _is_node_tainted(self, node: ast.AST) -> bool:
        # Recursively check if any Name node within the given AST node is tainted.
        if isinstance(node, ast.Name):
            return self.taint_tracker.is_tainted(node.id)
        elif isinstance(node, ast.Attribute):
            # Check if the attribute itself is tainted
            attribute_fqn = self._get_name_from_node(node) # Use the updated _get_name_from_node
            if attribute_fqn and self.taint_tracker.is_tainted(attribute_fqn, is_attribute=True):
                return True
            # Also check the base of the attribute (e.g., if 'request' is tainted in 'request.args')
            if self._is_node_tainted(node.value):
                return True
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            for sub_node in ast.walk(node):
                if isinstance(sub_node, ast.Name) and self.taint_tracker.is_tainted(sub_node.id):
                    return True
                # Also check for tainted attributes within JoinedStr/BinOp
                if isinstance(sub_node, ast.Attribute):
                    attribute_fqn = self._get_name_from_node(sub_node)
                    if attribute_fqn and self.taint_tracker.is_tainted(attribute_fqn, is_attribute=True):
                        return True
        elif isinstance(node, ast.Call): # If a call itself returns a tainted value
            called_func_name = self._get_name_from_node(node.func)
            if called_func_name and self.taint_tracker.is_function_return_tainted(called_func_name):
                return True
        # Add other AST node types as needed for more comprehensive taint checking
        return False

    def _analyze_function_body_for_taint(self, func_node: ast.AST, func_fqn: str, file_content: str, module_name: str, visitor: AegiscanVisitor):
        """
        Analyzes the body of a function for taint propagation and marks the function's
        return as tainted if a tainted value is returned.
        """
        local_taint_tracker = TaintTracker(aliases=visitor.aliases, show_taint=self.taint_tracker.show_taint)

        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg_node in func_node.args.args:
                if self.taint_tracker.is_function_parameter_tainted(func_fqn, arg_node.arg):
                    local_taint_tracker.add_source(arg_node.arg)

        for node in ast.walk(func_node):
            local_taint_tracker.propagate_taint(node)

            # Handle assignments to attributes within the function
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        attribute_fqn = self._get_fully_qualified_attribute_name(target, module_name, visitor)
                        if attribute_fqn and self._is_node_tainted_locally(node.value, local_taint_tracker):
                            local_taint_tracker.add_source(attribute_fqn, is_attribute=True)

            if isinstance(node, ast.Return) and node.value:
                if self._is_node_tainted_locally(node.value, local_taint_tracker):
                    self.taint_tracker.mark_function_return_tainted(func_fqn)

    def _is_node_tainted_locally(self, node: ast.AST, local_taint_tracker: TaintTracker) -> bool:
        """Helper to check if a node is tainted using a local taint tracker."""
        if isinstance(node, ast.Name):
            return local_taint_tracker.is_tainted(node.id)
        elif isinstance(node, ast.Attribute):
            attribute_fqn = self._get_name_from_node(node)
            if attribute_fqn and local_taint_tracker.is_tainted(attribute_fqn, is_attribute=True):
                return True
            if self._is_node_tainted_locally(node.value, local_taint_tracker):
                return True
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            for sub_node in ast.walk(node):
                if isinstance(sub_node, ast.Name) and local_taint_tracker.is_tainted(sub_node.id):
                    return True
                if isinstance(sub_node, ast.Attribute):
                    attribute_fqn = self._get_name_from_node(sub_node)
                    if attribute_fqn and local_taint_tracker.is_tainted(attribute_fqn, is_attribute=True):
                        return True
        elif isinstance(node, ast.Call):
            called_func_name = self._get_name_from_node(node.func)
            if called_func_name and local_taint_tracker.is_function_return_tainted(called_func_name):
                return True
            for arg in node.args: # Check if arguments passed to a call within the function are tainted
                if self._is_node_tainted_locally(arg, local_taint_tracker):
                    return True
        return False

    def analyze_file(self, filepath: str, file_content: str) -> List[Finding]:
        self.findings = [] # Reset findings for each file
        # Clear local tainted variables for this file analysis.
        # We don't clear tainted_function_returns or tainted_function_parameters here
        # because they are part of the global inter-procedural state across files.
        self.taint_tracker.tainted_vars.clear() 
        self.taint_tracker.logged_taint_events.clear() # Clear log for new file

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

        # Update current file's module name and visitor for use in helper methods
        self.current_module_name = module_name
        self.current_visitor = visitor

        # Update the taint_tracker's aliases for the current file's context
        self.taint_tracker.aliases = visitor.aliases

        # --- Pass 1: Collect initial sources and mark inter-procedural call parameters/returns ---
        for node in ast.walk(tree):
            # Collect initial sources from function calls (e.g., input(), request.args.get())
            if isinstance(node, ast.Assign):
                # Handle assignments to attributes (e.g., self.data = tainted_input)
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        attribute_fqn = self._get_fully_qualified_attribute_name(target, module_name, visitor)
                        if attribute_fqn and self._is_node_tainted(node.value):
                            self.taint_tracker.add_source(attribute_fqn, is_attribute=True)

                if isinstance(node.value, ast.Call):
                    # Resolve the called function's FQN using SymbolResolver
                    called_func_name = self._get_name_from_node(node.value.func)
                    resolved_symbol = self.symbol_resolver.resolve_call(module_name, called_func_name, visitor.imports)
                    
                    func_full_name = resolved_symbol.fully_qualified_name if resolved_symbol else called_func_name
                    
                    is_call_return_tainted = False
                    for rule in self.rules:
                        for source_pattern in rule.sources:
                            if func_full_name and func_full_name.startswith(source_pattern):
                                is_call_return_tainted = True
                                break
                        if is_call_return_tainted: break

                    # Also check if any argument to the call is tainted
                    for arg in node.value.args:
                        if self._is_node_tainted(arg):
                            is_call_return_tainted = True
                            break
                    
                    if is_call_return_tainted:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.taint_tracker.add_source(target.id)
                                self.taint_tracker.handle_call_return(func_full_name, target.id)
                                if resolved_symbol and resolved_symbol.symbol_type == SymbolType.FUNCTION:
                                    self.taint_tracker.mark_function_return_tainted(resolved_symbol.fully_qualified_name)
                            elif isinstance(target, ast.Attribute):
                                attribute_fqn = self._get_fully_qualified_attribute_name(target, module_name, visitor)
                                if attribute_fqn:
                                    self.taint_tracker.add_source(attribute_fqn, is_attribute=True)
                                    # self._log_taint_event(f"Taint propagates from call return to attribute: '{func_full_name}' -> '{attribute_fqn}'") # Original code had this line commented out
                                    # Also mark the function return tainted globally if it's assigned to a tainted attribute
                                    if resolved_symbol and resolved_symbol.symbol_type == SymbolType.FUNCTION:
                                        self.taint_tracker.mark_function_return_tainted(resolved_symbol.fully_qualified_name)
                                
            # Inter-procedural taint propagation at call sites (caller to callee)
            if isinstance(node, ast.Call):
                called_func_name = self._get_name_from_node(node.func)
                resolved_symbol = self.symbol_resolver.resolve_call(module_name, called_func_name, visitor.imports)
                
                if resolved_symbol and resolved_symbol.symbol_type == SymbolType.FUNCTION:
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

        # --- Pass 2: Intra-procedural taint propagation within functions and return value analysis ---
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_fqn = f"{module_name}.{node.name}" # FQN for function defined in current file
                self._analyze_function_body_for_taint(node, func_fqn, file_content, module_name, visitor)

        # --- Third Pass: Full intra-procedural taint propagation and sink detection ---
        for node in ast.walk(tree):
            # Propagate taint through direct assignments and calls within the file
            self.taint_tracker.propagate_taint(node)

            # Handle assignments to attributes during general taint propagation
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        attribute_fqn = self._get_fully_qualified_attribute_name(target, module_name, visitor)
                        if attribute_fqn and self._is_node_tainted(node.value):
                            self.taint_tracker.add_source(attribute_fqn, is_attribute=True)

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
                                if is_tainted_sink: break

                        # Check for sanitizers (very basic for now)
                        is_sanitized = False
                        for sanitizer_pattern in rule.sanitizers:
                            if sanitizer_pattern in func_full_name: # Placeholder: check if sanitizer name is in func name
                                is_sanitized = True
                                break

                        if is_tainted_sink and not is_sanitized:
                            code_snippet = ast.get_source_segment(file_content, node)
                            if code_snippet is None:
                                code_snippet = "Unable to retrieve code snippet."

                            if rule.id in ignored_lines.get(node.lineno, []):
                                continue

                            taint_trace = []
                            if self.taint_tracker.show_taint:
                                taint_trace = self.taint_tracker.get_taint_trace()

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

        for visitor_finding in visitor.findings:
            if visitor_finding["ruleId"] in ignored_lines.get(visitor_finding["startLine"], []):
                continue

            visitor_finding["file"] = filepath
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
                fingerprint=f"{filepath}:{visitor_finding['startLine']}:{visitor_finding['ruleId']}",
                cwe=visitor_finding["cwe"],
                fix=visitor_finding["fix"],
                taint_trace=[] # Visitor findings don't have taint trace for now
            ))

        self.current_module_name = None
        self.current_visitor = None

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
