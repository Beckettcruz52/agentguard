"""
AgentGuard: Vector Memory Poisoning Scanner & Runtime Tool Sandbox for Autonomous AI Agents.
"""

__version__ = "1.0.0"

from .core import (
    SemanticEmbeddingEngine,
    default_engine,
    ThreatSignature,
    ThreatSignatureRegistry,
    default_registry,
    VectorMemoryScanner,
    RAGMemoryRecord,
    default_scanner,
    RolePolicy,
    RBACPolicyEngine,
    default_rbac,
    ParameterSanitizer,
    ParameterViolation,
    default_sanitizer,
    ToolSandboxEngine,
    ToolExecutionInterception,
    default_sandbox,
    protect_tool,
    AgentGuardMemoryStore,
    AgentGuardLangChainCallback,
    AgentSecurityException
)
