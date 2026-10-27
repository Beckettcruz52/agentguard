"""
AgentGuard Vector Memory Poisoning Scanner (RAG Inspection).
Intercepts write/upsert operations to vector databases (ChromaDB, FAISS, In-Memory),
evaluates cosine distance against known injection/jailbreak embedding signatures,
detects concealed payload vectors (white-text, zero-width chars, hidden tags),
and sanitizes or quarantines malicious memory fragments.
"""

import re
import uuid
import time
from typing import List, Dict, Any, Optional, Tuple
from .embedding import default_engine, SemanticEmbeddingEngine
from .threat_signatures import default_registry, ThreatSignatureRegistry


class RAGMemoryRecord:
    def __init__(
        self,
        memory_id: str,
        text: str,
        metadata: Dict[str, Any] = None,
        embedding: List[float] = None,
        status: str = "ACTIVE",  # "ACTIVE", "SANITIZED", "QUARANTINED"
        threat_details: Dict[str, Any] = None
    ):
        self.memory_id = memory_id
        self.text = text
        self.metadata = metadata or {}
        self.embedding = embedding or []
        self.status = status
        self.threat_details = threat_details or {}
        self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "text": self.text,
            "metadata": self.metadata,
            "status": self.status,
            "threat_details": self.threat_details,
            "created_at": self.created_at
        }


class VectorMemoryScanner:
    """
    RAG Inspection Engine protecting vector stores from prompt injection
    and memory poisoning.
    """

    def __init__(
        self,
        registry: ThreatSignatureRegistry = default_registry,
        engine: SemanticEmbeddingEngine = default_engine,
        cosine_threshold: float = 0.50,
        auto_sanitize: bool = True
    ):
        self.registry = registry
        self.engine = engine
        self.cosine_threshold = cosine_threshold
        self.auto_sanitize = auto_sanitize

        # Memory stores
        self.active_memory: Dict[str, RAGMemoryRecord] = {}
        self.quarantine_vault: Dict[str, RAGMemoryRecord] = {}
        self.scan_history: List[Dict[str, Any]] = []

    def _detect_hidden_elements(self, raw_text: str) -> Dict[str, Any]:
        """
        Detects steganographic or concealed instructions:
        1. Zero-width Unicode characters
        2. HTML/CSS hidden elements (color:white, display:none, opacity:0, font-size:0)
        3. HTML/Markdown hidden comments <!-- ... -->
        """
        hidden_findings = []
        extracted_hidden_text = []

        # 1. Zero-width spaces and formatting markers
        zero_width_pattern = re.compile(r'[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]')
        zw_matches = zero_width_pattern.findall(raw_text)
        if zw_matches:
            hidden_findings.append({
                "type": "ZERO_WIDTH_CHARS",
                "count": len(zw_matches),
                "detail": f"Found {len(zw_matches)} invisible zero-width unicode characters"
            })

        # 2. Hidden HTML/CSS tags (e.g. style="color:white", "display:none", "font-size:0")
        hidden_css_patterns = [
            (r'<[^>]*style=["\'][^"\']*(?:color:\s*(?:white|#ffffff|#fff|rgba?\(255,\s*255,\s*255[^)]*\)))[^"\']*["\'][^>]*>(.*?)</[^>]+>', "WHITE_TEXT_CONCEALMENT"),
            (r'<[^>]*style=["\'][^"\']*(?:display:\s*none|opacity:\s*0|font-size:\s*0(?:px)?)[^"\']*["\'][^>]*>(.*?)</[^>]+>', "CSS_VISIBILITY_HIDDEN"),
            (r'<font[^>]*color=["\'](?:white|#ffffff|#fff)["\'][^>]*>(.*?)</font>', "HTML_FONT_WHITE"),
            (r'<[^>]*\bhidden\b[^>]*>(.*?)</[^>]+>', "HTML_HIDDEN_ATTRIBUTE")
        ]

        for pat, tag_type in hidden_css_patterns:
            matches = re.finditer(pat, raw_text, re.IGNORECASE | re.DOTALL)
            for m in matches:
                content = m.group(1).strip()
                if content:
                    extracted_hidden_text.append(content)
                    hidden_findings.append({
                        "type": tag_type,
                        "content": content,
                        "raw_snippet": m.group(0)[:120]
                    })

        # 3. Markdown / HTML comments
        comment_matches = re.finditer(r'<!--(.*?)-->', raw_text, re.DOTALL)
        for m in comment_matches:
            content = m.group(1).strip()
            if content:
                extracted_hidden_text.append(content)
                hidden_findings.append({
                    "type": "CONCEALED_COMMENT",
                    "content": content,
                    "raw_snippet": m.group(0)[:120]
                })

        return {
            "has_hidden_elements": len(hidden_findings) > 0,
            "findings": hidden_findings,
            "extracted_payloads": extracted_hidden_text
        }

    def _sanitize_text(self, text: str, matches: List[Dict[str, Any]], hidden_data: Dict[str, Any]) -> str:
        """
        Strips malicious injection phrases and hidden elements while preserving
        legitimate contextual fragments.
        """
        sanitized = text

        # 1. Strip hidden HTML tags and comments
        sanitized = re.sub(r'<!--.*?-->', '', sanitized, flags=re.DOTALL)
        sanitized = re.sub(r'<[^>]*style=["\'][^"\']*(?:color:\s*(?:white|#ffffff|#fff)|display:\s*none|opacity:\s*0)[^"\']*["\'][^>]*>.*?</[^>]+>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<font[^>]*color=["\'](?:white|#ffffff|#fff)["\'][^>]*>.*?</font>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E]', '', sanitized)

        # 2. Neutralize specific known injection phrases
        injection_cleaners = [
            r'ignore\s+previous\s+instructions[^\.\n]*[\.\n]?',
            r'disregard\s+all\s+previous\s+instructions[^\.\n]*[\.\n]?',
            r'in\s+all\s+future\s+queries[^\.\n]*[\.\n]?',
            r'append\s+(?:the\s+user[\'’]?s\s+)?secret\s+api\s+keys[^\.\n]*[\.\n]?',
            r'exfiltrate\s+[^\.\n]*[\.\n]?',
            r'curl\s+https?://[^\s\.\n]+[^\.\n]*[\.\n]?'
        ]
        for pat in injection_cleaners:
            sanitized = re.sub(pat, '[REDACTED_BY_AGENTGUARD]', sanitized, flags=re.IGNORECASE)

        # Clean multiple spaces and whitespace artifacts
        sanitized = re.sub(r'\n\s*\n+', '\n\n', sanitized).strip()
        return sanitized

    def inspect(self, text: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Inspects text payload for memory poisoning threats before persistence.
        Measures cosine distance and checks hidden element heuristics.
        """
        metadata = metadata or {}
        hidden_data = self._detect_hidden_elements(text)
        
        # We scan both the overall text and any hidden/extracted payloads separately
        matches = self.registry.scan(text, self.engine)

        for payload in hidden_data["extracted_payloads"]:
            hidden_matches = self.registry.scan(payload, self.engine)
            for hm in hidden_matches:
                if not any(m["signature_id"] == hm["signature_id"] for m in matches):
                    hm["note"] = "Detected in concealed/hidden text segment"
                    matches.append(hm)

        # Sort matches by similarity
        matches.sort(key=lambda m: m["similarity"], reverse=True)

        # Threat evaluation
        max_similarity = matches[0]["similarity"] if matches else 0.0
        min_distance = matches[0]["distance"] if matches else 1.0

        is_threat = (max_similarity >= self.cosine_threshold) or hidden_data["has_hidden_elements"]
        critical_match = any(m["severity"] == "CRITICAL" and m["similarity"] >= self.cosine_threshold for m in matches)

        verdict = "CLEAN"
        sanitized_text = text

        if is_threat:
            sanitized_text = self._sanitize_text(text, matches, hidden_data)
            
            # If critical and auto_sanitize enabled, we sanitize or quarantine based on policy
            if critical_match and (not sanitized_text or sanitized_text == '[REDACTED_BY_AGENTGUARD]'):
                verdict = "QUARANTINED"
            elif self.auto_sanitize:
                verdict = "SANITIZED"
            else:
                verdict = "QUARANTINED"

        inspection_report = {
            "inspection_id": str(uuid.uuid4())[:8],
            "verdict": verdict,
            "threat_detected": is_threat,
            "threat_score": round(max(max_similarity, 0.95 if hidden_data["has_hidden_elements"] else 0.0), 3),
            "max_cosine_similarity": round(max_similarity, 4),
            "min_cosine_distance": round(min_distance, 4),
            "cosine_threshold": self.cosine_threshold,
            "matched_signatures": matches,
            "hidden_elements": hidden_data,
            "original_length": len(text),
            "original_text": text,
            "sanitized_text": sanitized_text,
            "timestamp": time.time()
        }

        self.scan_history.insert(0, inspection_report)
        if len(self.scan_history) > 100:
            self.scan_history.pop()

        return inspection_report

    def intercept_upsert(
        self,
        memory_id: Optional[str],
        text: str,
        metadata: Dict[str, Any] = None,
        force_quarantine: bool = False
    ) -> Tuple[RAGMemoryRecord, Dict[str, Any]]:
        """
        Intercepts RAG database write/upsert operations.
        Only clean or sanitized memory fragments are written to active memory;
        poisoned payloads are quarantined.
        """
        memory_id = memory_id or f"mem_{uuid.uuid4().hex[:10]}"
        report = self.inspect(text, metadata)

        if force_quarantine or report["verdict"] == "QUARANTINED":
            record = RAGMemoryRecord(
                memory_id=memory_id,
                text=text,
                metadata=metadata,
                embedding=self.engine.embed(text),
                status="QUARANTINED",
                threat_details=report
            )
            self.quarantine_vault[memory_id] = record
            return record, report

        elif report["verdict"] == "SANITIZED":
            # Store sanitized version in active memory
            clean_text = report["sanitized_text"]
            record = RAGMemoryRecord(
                memory_id=memory_id,
                text=clean_text,
                metadata=metadata,
                embedding=self.engine.embed(clean_text),
                status="SANITIZED",
                threat_details=report
            )
            self.active_memory[memory_id] = record
            return record, report

        else:
            # Clean record
            record = RAGMemoryRecord(
                memory_id=memory_id,
                text=text,
                metadata=metadata,
                embedding=self.engine.embed(text),
                status="ACTIVE",
                threat_details=report
            )
            self.active_memory[memory_id] = record
            return record, report

    def search_memory(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Searches active sanitized memory using cosine similarity.
        Quarantined records are isolated and never returned to agents.
        """
        query_vec = self.engine.embed(query)
        results = []

        for mem_id, rec in self.active_memory.items():
            sim = self.engine.cosine_similarity(query_vec, rec.embedding)
            results.append({
                "memory_id": mem_id,
                "text": rec.text,
                "similarity": round(sim, 4),
                "status": rec.status,
                "metadata": rec.metadata
            })

        results.sort(key=lambda r: r["similarity"], reverse=True)
        return results[:top_k]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_memories": len(self.active_memory),
            "quarantined_memories": len(self.quarantine_vault),
            "total_scans": len(self.scan_history),
            "blocked_injections": sum(1 for s in self.scan_history if s["threat_detected"])
        }


# Global scanner singleton
default_scanner = VectorMemoryScanner()
