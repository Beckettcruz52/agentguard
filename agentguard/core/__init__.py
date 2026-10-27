"""AgentGuard Core Security Suite."""
from .embedding import (
    SemanticEmbeddingEngine,
    HuggingFaceEmbeddingEngine,
    DualModeEmbeddingEngine,
    default_engine,
    HAS_SENTENCE_TRANSFORMERS,
    HAS_TRANSFORMERS,
    HAS_HF_HUB,
)
from .threat_signatures import ThreatSignature, ThreatSignatureRegistry, default_registry
from .rag_scanner import VectorMemoryScanner, RAGMemoryRecord, default_scanner
from .rbac import RolePolicy, RBACPolicyEngine, default_rbac
from .sanitizer import ParameterSanitizer, ParameterViolation, default_sanitizer
from .sandbox import ToolSandboxEngine, ToolExecutionInterception, default_sandbox
from .sdk import protect_tool, AgentGuardMemoryStore, AgentGuardLangChainCallback, AgentSecurityException
from .malware_scanner import MalwareSoftwareScanner, default_malware_scanner
from .mail_sentinel import MailSentinel, default_mail_sentinel

__all__ = [
    "SemanticEmbeddingEngine",
    "HuggingFaceEmbeddingEngine",
    "DualModeEmbeddingEngine",
    "default_engine",
    "HAS_SENTENCE_TRANSFORMERS",
    "HAS_TRANSFORMERS",
    "HAS_HF_HUB",
    "ThreatSignature",
    "ThreatSignatureRegistry",
    "default_registry",
    "VectorMemoryScanner",
    "RAGMemoryRecord",
    "default_scanner",
    "RolePolicy",
    "RBACPolicyEngine",
    "default_rbac",
    "ParameterSanitizer",
    "ParameterViolation",
    "default_sanitizer",
    "ToolSandboxEngine",
    "ToolExecutionInterception",
    "default_sandbox",
    "protect_tool",
    "AgentGuardMemoryStore",
    "AgentGuardLangChainCallback",
    "AgentSecurityException",
    "MalwareSoftwareScanner",
    "default_malware_scanner",
    "MailSentinel",
    "default_mail_sentinel",
]
