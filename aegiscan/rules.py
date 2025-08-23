import yaml
import os
from enum import Enum
from typing import List, Dict, Any, Optional

class RuleSeverity(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Rule:
    def __init__(self, id: str, name: str, severity: RuleSeverity, cwe: str, description: str,
                 message: str, # Moved message here
                 sources: Optional[List[str]] = None, sinks: Optional[List[str]] = None,
                 sanitizers: Optional[List[str]] = None, patterns: Optional[List[str]] = None,
                 examples: Optional[Dict[str, List[str]]] = None, fix: Optional[str] = None):
        self.id = id
        self.name = name
        self.severity = severity
        self.cwe = cwe
        self.description = description
        self.message = message # Assigned message
        self.sources = sources if sources is not None else []
        self.sinks = sinks if sinks is not None else []
        self.sanitizers = sanitizers if sanitizers is not None else []
        self.patterns = patterns if patterns is not None else []
        self.examples = examples if examples is not None else {}
        self.fix = fix

    @classmethod
    def from_yaml(cls, rule_data: Dict[str, Any]) -> 'Rule':
        return cls(
            id=rule_data["id"],
            name=rule_data["name"],
            severity=RuleSeverity(rule_data["severity"].lower()),
            cwe=rule_data["cwe"],
            description=rule_data["description"],
            message=rule_data["message"], # Ensured message is passed correctly
            sources=rule_data.get("sources"),
            sinks=rule_data.get("sinks"),
            sanitizers=rule_data.get("sanitizers"),
            patterns=rule_data.get("patterns"),
            examples=rule_data.get("examples"),
            fix=rule_data.get("fix")
        )

def load_rules_from_yaml(rule_path: str) -> List[Rule]:
    rules = []
    for root, _, files in os.walk(rule_path):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                filepath = os.path.join(root, file)
                with open(filepath, 'r') as f:
                    try:
                        rule_data = yaml.safe_load(f)
                        if isinstance(rule_data, dict):
                            rules.append(Rule.from_yaml(rule_data))
                        elif isinstance(rule_data, list):
                            for r_data in rule_data:
                                rules.append(Rule.from_yaml(r_data))
                    except yaml.YAMLError as e:
                        print(f"Error parsing YAML file {filepath}: {e}")
    return rules
