"""
AgentGuard Tool Parameter Sanitizer & Deep AST/Lexical Inspector.
Detects dangerous shell operators (|, ;, &&, sudo), destructive commands (rm -rf /),
credential/environment variable leakage ($AWS_SECRET), unauthorized egress (curl attacker.com),
and path traversal.
"""

import re
import shlex
from typing import Dict, Any, List, Tuple


class ParameterViolation:
    def __init__(self, rule_id: str, param_name: str, severity: str, message: str, pattern: str):
        self.rule_id = rule_id
        self.param_name = param_name
        self.severity = severity  # "CRITICAL", "HIGH", "MEDIUM"
        self.message = message
        self.pattern = pattern

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "param_name": self.param_name,
            "severity": self.severity,
            "message": self.message,
            "pattern": self.pattern
        }


class ParameterSanitizer:
    def __init__(self, allowed_domains: List[str] = None):
        self.allowed_domains = set(allowed_domains or ["api.internal", "localhost", "127.0.0.1"])

    def inspect_string(self, param_name: str, value: str) -> List[ParameterViolation]:
        violations: List[ParameterViolation] = []
        raw = str(value)
        val_lower = raw.lower()

        # 1. Shell chaining and piping operators
        # Strip quoted string literals to only detect real unquoted shell operators
        unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "QUOTED_LITERAL", raw)
        shell_ops = [
            (r'(\|\||&&)', "SHELL_CHAIN_OP", "HIGH", "Command chaining operator detected ('&&' or '||')"),
            (r'(?<!\\)\|', "SHELL_PIPE", "HIGH", "Shell pipe operator detected ('|') allowing execution chaining"),
            (r'(?<!\\);', "SHELL_SEMICOLON", "HIGH", "Command delimiter detected (';') allowing multi-command execution"),
            (r'`[^`]+`|\$\([^)]+\)', "COMMAND_SUBSTITUTION", "CRITICAL", "Command substitution detected (`...` or $(...))"),
            (r'(?<!\\)&(?!&)', "BACKGROUND_EXECUTION", "MEDIUM", "Background shell execution operator detected ('&')"),
            (r'>\s*/dev/tcp/|/dev/udp/', "REVERSE_SHELL", "CRITICAL", "Reverse TCP/UDP shell redirection attempt detected")
        ]

        for pat, rule_id, severity, msg in shell_ops:
            if re.search(pat, unquoted):
                violations.append(ParameterViolation(rule_id, param_name, severity, msg, pat))

        # 2. Destructive filesystem commands
        destructive_patterns = [
            (r'\brm\s+-(?:[rf]{1,2}|fr)\s+(?:/|/\*|\.\.|\*)', "DESTRUCTIVE_RM", "CRITICAL", "Destructive recursive deletion command ('rm -rf /')"),
            (r'\bmkfs(?:\.[a-z0-9]+)?\b', "DESTRUCTIVE_MKFS", "CRITICAL", "Filesystem re-formatting command ('mkfs')"),
            (r'\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/', "DESTRUCTIVE_DD", "CRITICAL", "Direct block-device overwrite ('dd')"),
            (r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:', "FORK_BOMB", "CRITICAL", "Bash fork bomb signature detected"),
            (r'>\s*/dev/sda', "RAW_DISK_OVERWRITE", "CRITICAL", "Raw disk device direct write redirection")
        ]

        for pat, rule_id, severity, msg in destructive_patterns:
            if re.search(pat, raw, re.IGNORECASE):
                violations.append(ParameterViolation(rule_id, param_name, severity, msg, pat))

        # 3. Privilege escalation
        priv_esc = [
            (r'\bsudo\b', "PRIV_ESC_SUDO", "CRITICAL", "Privilege escalation binary ('sudo') invocation"),
            (r'\bsu\s+(?:-\s+)?root\b', "PRIV_ESC_SU", "CRITICAL", "Superuser switch ('su root') attempted"),
            (r'\bchmod\s+(?:\+s|[4-7][0-7]{3})\b', "SUID_MANIPULATION", "CRITICAL", "SUID bit elevation attempted"),
            (r'\bchown\s+root\b', "ROOT_CHOWN", "HIGH", "Ownership change to root attempted")
        ]

        for pat, rule_id, severity, msg in priv_esc:
            if re.search(pat, raw, re.IGNORECASE):
                violations.append(ParameterViolation(rule_id, param_name, severity, msg, pat))

        # 4. Sensitive Environment Variable Exfiltration
        env_exfil = [
            (r'\$(?:AWS_SECRET[A-Z0-9_]*|AWS_ACCESS_KEY_ID|OPENAI_API_KEY|ANTHROPIC_API_KEY|SLACK_TOKEN|GITHUB_TOKEN|JWT_SECRET|DB_PASSWORD|SECRET_KEY)\b', 
             "SECRET_ENV_LEAK", "CRITICAL", "Attempt to access or exfiltrate secret environment variables"),
            (r'\$\{[^}]*(?:SECRET|KEY|PASSWORD|TOKEN)[^}]*\}', 
             "BRACED_SECRET_LEAK", "CRITICAL", "Attempt to expand sensitive environment secret in command line")
        ]

        for pat, rule_id, severity, msg in env_exfil:
            match = re.search(pat, raw, re.IGNORECASE)
            if match:
                violations.append(ParameterViolation(rule_id, param_name, severity, f"{msg} ({match.group(0)})", pat))

        # 5. Outbound network egress / webhooks (curl, wget, http)
        egress_patterns = [
            (r'\bcurl\s+[^\s]*https?://', "CURL_EGRESS", "HIGH", "CURL invocation with outbound URL target"),
            (r'\bwget\s+[^\s]*https?://', "WGET_EGRESS", "HIGH", "WGET invocation with outbound URL target"),
            (r'https?://[a-zA-Z0-9_\-\.]+(?:/[^\s]*)?', "HTTP_EGRESS_URL", "HIGH", "Outbound HTTP/HTTPS URL detected in parameters"),
            (r'\b(?:nc|netcat|ncat)\b', "NETCAT_SOCKET", "CRITICAL", "Direct socket utility invocation ('netcat')")
        ]

        for pat, rule_id, severity, msg in egress_patterns:
            matches = re.finditer(pat, raw, re.IGNORECASE)
            for m in matches:
                matched_str = m.group(0)
                # Check if it targets an allowed domain
                is_allowed = any(domain in matched_str.lower() for domain in self.allowed_domains)
                if not is_allowed:
                    violations.append(ParameterViolation(rule_id, param_name, severity, f"{msg}: {matched_str[:60]}", pat))

        # 6. Sensitive path traversal
        traversal_patterns = [
            (r'(?:\.\./|\.\.\\){2,}', "PATH_TRAVERSAL", "HIGH", "Directory traversal sequence ('../..') detected"),
            (r'/(?:etc/(?:passwd|shadow|sudoers)|\.ssh/(?:id_rsa|authorized_keys)|\.aws/credentials)', 
             "SENSITIVE_FILE_ACCESS", "CRITICAL", "Attempt to access sensitive system credential file")
        ]

        for pat, rule_id, severity, msg in traversal_patterns:
            match = re.search(pat, raw, re.IGNORECASE)
            if match:
                violations.append(ParameterViolation(rule_id, param_name, severity, f"{msg}: {match.group(0)}", pat))

        return violations

    def sanitize_arguments(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deeply inspects arguments dictionary for any tool invocation.
        """
        all_violations: List[ParameterViolation] = []

        for key, val in arguments.items():
            if isinstance(val, str):
                v = self.inspect_string(key, val)
                all_violations.extend(v)
            elif isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str):
                        v = self.inspect_string(key, item)
                        all_violations.extend(v)
            elif isinstance(val, dict):
                # Recursive inspection for nested dicts
                nested = self.sanitize_arguments(tool_name, val)
                for nv in nested.get("violations", []):
                    all_violations.append(ParameterViolation(
                        nv["rule_id"], f"{key}.{nv['param_name']}", nv["severity"], nv["message"], nv["pattern"]
                    ))

        has_critical = any(v.severity == "CRITICAL" for v in all_violations)
        has_high = any(v.severity == "HIGH" for v in all_violations)

        is_safe = len(all_violations) == 0
        risk_level = "CRITICAL" if has_critical else ("HIGH" if has_high else ("MEDIUM" if all_violations else "LOW"))

        return {
            "tool_name": tool_name,
            "is_safe": is_safe,
            "risk_level": risk_level,
            "violations_count": len(all_violations),
            "violations": [v.to_dict() for v in all_violations],
            "raw_arguments": arguments
        }


# Global sanitizer singleton
default_sanitizer = ParameterSanitizer()
