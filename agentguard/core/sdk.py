"""
AgentGuard Developer SDK & Framework Integrations.
Provides plug-and-play middleware, wrappers, and callback hooks for
LangChain, AutoGen, CrewAI, and generic Python AI agents.
"""

from functools import wraps
from typing import Callable, Any, Dict, List, Optional
from .rag_scanner import default_scanner, VectorMemoryScanner
from .sandbox import default_sandbox, ToolSandboxEngine


class AgentSecurityException(PermissionError):
    """Raised when AgentGuard blocks a tool execution or vector memory write."""
    def __init__(self, message: str, interception_report: Dict[str, Any]):
        super().__init__(message)
        self.report = interception_report


def protect_tool(
    role: str = "guest_agent",
    tool_name: Optional[str] = None,
    dry_run: bool = True,
    sandbox: ToolSandboxEngine = default_sandbox
):
    """
    Decorator for AI agent tools to enforce RBAC and parameter sanitization.
    
    Example:
        @protect_tool(role="devops_agent")
        def execute_shell_command(command: str):
            ...
    """
    def decorator(func: Callable):
        actual_name = tool_name or func.__name__

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Convert positional args to dictionary format for inspection
            arguments = dict(kwargs)
            if args:
                arguments["_args"] = list(args)
            if "command" not in arguments and args and isinstance(args[0], str):
                arguments["command"] = args[0]

            interception = sandbox.intercept_and_execute(
                agent_role=role,
                tool_name=actual_name,
                arguments=arguments,
                dry_run=dry_run
            )

            if interception.verdict.startswith("BLOCKED"):
                raise AgentSecurityException(
                    f"AgentGuard blocked invocation of '{actual_name}': {interception.reason}",
                    interception.to_dict()
                )

            # If dry-run sandbox mode was executed
            if interception.verdict == "EXECUTED_DRY_RUN" and interception.sandbox_result:
                return interception.sandbox_result.get("stdout") or interception.sandbox_result

            return func(*args, **kwargs)

        wrapper.__agentguard_protected__ = True
        return wrapper
    return decorator


class AgentGuardMemoryStore:
    """
    Drop-in vector memory wrapper for ChromaDB, FAISS, or custom vector stores.
    Intercepts write operations and sanitizes/quarantines prompt injection attacks.
    """
    def __init__(self, scanner: VectorMemoryScanner = default_scanner):
        self.scanner = scanner

    def add_texts(self, texts: List[str], metadatas: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        results = []
        metadatas = metadatas or [{}] * len(texts)
        for text, meta in zip(texts, metadatas):
            record, report = self.scanner.intercept_upsert(
                memory_id=None,
                text=text,
                metadata=meta
            )
            results.append({
                "memory_id": record.memory_id,
                "status": record.status,
                "threat_detected": report["threat_detected"],
                "verdict": report["verdict"]
            })
        return results

    def similarity_search(self, query: str, k: int = 4) -> List[Dict[str, Any]]:
        return self.scanner.search_memory(query, top_k=k)


class AgentGuardLangChainCallback:
    """
    Callback handler for LangChain agents.
    Hooks into tool starts to sanitize parameters and vectorstore upserts.
    """
    def __init__(self, role: str = "devops_agent", sandbox: ToolSandboxEngine = default_sandbox):
        self.role = role
        self.sandbox = sandbox

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs) -> Any:
        tool_name = serialized.get("name", "unnamed_tool")
        interception = self.sandbox.intercept_and_execute(
            agent_role=self.role,
            tool_name=tool_name,
            arguments={"input": input_str},
            dry_run=True
        )
        if interception.verdict.startswith("BLOCKED"):
            raise AgentSecurityException(
                f"AgentGuard LangChain Hook Blocked '{tool_name}': {interception.reason}",
                interception.to_dict()
            )
