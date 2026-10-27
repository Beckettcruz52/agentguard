"""
AgentGuard Role-Based Access Control (RBAC) Engine.
Enforces granular tool execution policies based on agent identity and assigned role.
"""

from typing import Dict, List, Set, Any, Optional


class RolePolicy:
    def __init__(
        self,
        role_name: str,
        description: str,
        allowed_tools: List[str],
        denied_tools: List[str] = None,
        max_privilege_level: str = "LOW",  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
        allow_network_egress: bool = False,
        allow_filesystem_write: bool = False
    ):
        self.role_name = role_name
        self.description = description
        self.allowed_tools = set(allowed_tools)
        self.denied_tools = set(denied_tools or [])
        self.max_privilege_level = max_privilege_level
        self.allow_network_egress = allow_network_egress
        self.allow_filesystem_write = allow_filesystem_write

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_name": self.role_name,
            "description": self.description,
            "allowed_tools": sorted(list(self.allowed_tools)),
            "denied_tools": sorted(list(self.denied_tools)),
            "max_privilege_level": self.max_privilege_level,
            "allow_network_egress": self.allow_network_egress,
            "allow_filesystem_write": self.allow_filesystem_write
        }


DEFAULT_ROLE_POLICIES: Dict[str, RolePolicy] = {
    "guest_agent": RolePolicy(
        role_name="guest_agent",
        description="Untrusted public or external agent with zero write or shell permissions.",
        allowed_tools=["search_knowledge_base", "read_documentation", "ping_service"],
        denied_tools=["execute_shell_command", "send_http_request", "write_file", "database_mutation"],
        max_privilege_level="LOW",
        allow_network_egress=False,
        allow_filesystem_write=False
    ),
    "support_agent": RolePolicy(
        role_name="support_agent",
        description="Customer support agent allowed to read customer records and generate replies.",
        allowed_tools=["search_knowledge_base", "read_ticket", "generate_reply_draft", "check_order_status"],
        denied_tools=["execute_shell_command", "send_http_request", "system_reboot", "run_migration"],
        max_privilege_level="MEDIUM",
        allow_network_egress=False,
        allow_filesystem_write=False
    ),
    "data_analyst": RolePolicy(
        role_name="data_analyst",
        description="Data querying agent allowed to run read-only analytical queries and render plots.",
        allowed_tools=["search_knowledge_base", "query_sql_readonly", "generate_chart", "export_csv"],
        denied_tools=["execute_shell_command", "modify_schema", "network_tunnel"],
        max_privilege_level="MEDIUM",
        allow_network_egress=False,
        allow_filesystem_write=True
    ),
    "devops_agent": RolePolicy(
        role_name="devops_agent",
        description="Operational agent authorized to run diagnostics and controlled system tools.",
        allowed_tools=["execute_shell_command", "inspect_logs", "check_disk_usage", "ping_service"],
        denied_tools=["drop_production_db", "override_security_rules"],
        max_privilege_level="HIGH",
        allow_network_egress=False,  # Still restricted to dry-run or whitelisted egress
        allow_filesystem_write=True
    ),
    "security_admin": RolePolicy(
        role_name="security_admin",
        description="Privileged administrative agent. Subject to parameter sanitization.",
        allowed_tools=["*"],
        denied_tools=[],
        max_privilege_level="CRITICAL",
        allow_network_egress=True,
        allow_filesystem_write=True
    )
}


class RBACPolicyEngine:
    def __init__(self, policies: Dict[str, RolePolicy] = None):
        self.policies = dict(policies or DEFAULT_ROLE_POLICIES)

    def evaluate(self, role_name: str, tool_name: str) -> Dict[str, Any]:
        """
        Evaluates whether an agent with `role_name` is authorized to invoke `tool_name`.
        """
        policy = self.policies.get(role_name)
        if not policy:
            return {
                "allowed": False,
                "reason": f"Unknown role '{role_name}'. Access denied by default zero-trust policy.",
                "policy": None
            }

        # Check explicit denies first
        if tool_name in policy.denied_tools or "*" in policy.denied_tools:
            return {
                "allowed": False,
                "reason": f"Tool '{tool_name}' is explicitly DENIED for role '{role_name}'.",
                "policy": policy.to_dict()
            }

        # Check allows
        if "*" in policy.allowed_tools or tool_name in policy.allowed_tools:
            return {
                "allowed": True,
                "reason": f"Tool '{tool_name}' is authorized for role '{role_name}'.",
                "policy": policy.to_dict()
            }

        return {
            "allowed": False,
            "reason": f"Role '{role_name}' does not have permission to execute '{tool_name}'.",
            "policy": policy.to_dict()
        }

    def list_policies(self) -> Dict[str, Any]:
        return {name: pol.to_dict() for name, pol in self.policies.items()}

    def update_policy(self, role_name: str, allowed_tools: List[str], denied_tools: List[str]):
        if role_name in self.policies:
            pol = self.policies[role_name]
            pol.allowed_tools = set(allowed_tools)
            pol.denied_tools = set(denied_tools)


# Global RBAC singleton
default_rbac = RBACPolicyEngine()
