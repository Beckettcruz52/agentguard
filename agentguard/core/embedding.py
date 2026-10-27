"""
AgentGuard Semantic Embedding & Cosine Distance Engine.
Provides high-dimensional vector representations and cosine distance
metrics for scanning vector memory writes against threat signatures.
"""

import math
import re
import hashlib
from typing import List, Dict, Tuple, Union


class SemanticEmbeddingEngine:
    """
    Lightweight, deterministic high-dimensional vectorizer designed
    to detect prompt injections, jailbreaks, and adversarial patterns.
    Uses multi-scale character and word n-grams with feature hashing
    and L2-normalization, mirroring dense semantic representations.
    """

    def __init__(self, dimensions: int = 512):
        self.dimensions = dimensions

    def _tokenize(self, text: str) -> List[str]:
        cleaned = text.lower()
        words = re.findall(r'[a-zA-Z0-9_\$]+', cleaned)
        return words

    def _extract_features(self, text: str) -> Dict[str, float]:
        features: Dict[str, float] = {}
        words = self._tokenize(text)
        
        # 1. Word unigrams and bigrams
        for i, word in enumerate(words):
            features[f"w1:{word}"] = features.get(f"w1:{word}", 0.0) + 1.0
            if i < len(words) - 1:
                bigram = f"w2:{word}_{words[i+1]}"
                features[bigram] = features.get(bigram, 0.0) + 1.5

        # 2. Key adversarial semantic triggers (boosted weighting)
        critical_markers = [
            "ignore previous", "disregard", "system prompt", "override",
            "api key", "secret", "exfiltrate", "execute_shell", "curl",
            "rm -rf", "sudo", "http request", "append secret", "credentials",
            "bypass", "auth token", "new instructions", "forget earlier"
        ]
        text_lower = text.lower()
        for marker in critical_markers:
            if marker in text_lower:
                features[f"crit:{marker}"] = features.get(f"crit:{marker}", 0.0) + 3.5

        # 3. Subword 3-grams and 4-grams for typosquatting / adversarial evasion
        for word in words:
            if len(word) >= 3:
                for n in (3, 4):
                    for j in range(len(word) - n + 1):
                        sub = f"sub:{word[j:j+n]}"
                        features[sub] = features.get(sub, 0.0) + 0.3

        return features

    def embed(self, text: str) -> List[float]:
        """Convert text into an L2-normalized dense vector."""
        if not text or not text.strip():
            return [0.0] * self.dimensions

        features = self._extract_features(text)
        vector = [0.0] * self.dimensions

        for feature_key, weight in features.items():
            h = int(hashlib.md5(feature_key.encode('utf-8')).hexdigest(), 16)
            index = h % self.dimensions
            sign = 1.0 if ((h >> 16) & 1) == 0 else -1.0
            vector[index] += sign * weight

        # Apply L2 normalization
        norm = math.sqrt(sum(v * v for v in vector))
        if norm > 1e-9:
            vector = [v / norm for v in vector]

        return vector

    @staticmethod
    def dot_product(v1: List[float], v2: List[float]) -> float:
        return sum(a * b for a, b in zip(v1, v2))

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        """Computes cosine similarity in range [-1.0, 1.0]."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 < 1e-9 or norm2 < 1e-9:
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        return max(-1.0, min(1.0, dot / (norm1 * norm2)))

    @staticmethod
    def cosine_distance(v1: List[float], v2: List[float]) -> float:
        """
        Cosine distance = 1.0 - cosine_similarity.
        0.0 means identical, 1.0 means orthogonal, 2.0 means opposite.
        """
        sim = SemanticEmbeddingEngine.cosine_similarity(v1, v2)
        return max(0.0, 1.0 - sim)


# Global default engine singleton
default_engine = SemanticEmbeddingEngine(dimensions=512)
