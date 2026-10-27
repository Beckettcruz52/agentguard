"""
AgentGuard Semantic Embedding & Cosine Distance Engine.
Provides dual-mode vector representations:
1. Hugging Face Transformers / Sentence-Transformers (Dense Neural Embeddings)
2. Fast Built-in Multi-Scale Semantic N-Gram Vectorizer (Zero External Dependencies)
"""

import os
import math
import re
import hashlib
import logging
from typing import List, Dict, Any, Optional, Tuple, Union

logger = logging.getLogger("agentguard.embedding")

# ---------------------------------------------------------------------------
# Hugging Face Ecosystem Detection & Imports
# ---------------------------------------------------------------------------
try:
    import sentence_transformers
    from sentence_transformers import SentenceTransformer
    HAS_SENTENCE_TRANSFORMERS = True
except (ImportError, Exception):
    HAS_SENTENCE_TRANSFORMERS = False
    SentenceTransformer = None

try:
    import transformers
    from transformers import AutoTokenizer, AutoModel
    HAS_TRANSFORMERS = True
except (ImportError, Exception):
    HAS_TRANSFORMERS = False
    AutoTokenizer = None
    AutoModel = None

try:
    import huggingface_hub
    from huggingface_hub import InferenceClient
    HAS_HF_HUB = True
except (ImportError, Exception):
    HAS_HF_HUB = False
    InferenceClient = None


class SemanticEmbeddingEngine:
    """
    Lightweight, deterministic high-dimensional vectorizer designed
    to detect prompt injections, jailbreaks, and adversarial patterns.
    Uses multi-scale character and word n-grams with feature hashing
    and L2-normalization, mirroring dense semantic representations.
    Zero external dependencies (pure Python Standard Library).
    """

    def __init__(self, dimensions: int = 512):
        self._dimensions = dimensions
        self._active_backend = "builtin"
        self._model_name = "builtin-ngram-hasher"

    @property
    def dimensions(self) -> int:
        return self._dimensions

    @dimensions.setter
    def dimensions(self, val: int):
        self._dimensions = val

    @property
    def active_backend(self) -> str:
        return self._active_backend

    @active_backend.setter
    def active_backend(self, val: str):
        self._active_backend = val

    @property
    def model_name(self) -> str:
        return self._model_name

    @model_name.setter
    def model_name(self, val: str):
        self._model_name = val

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
        if not text or not str(text).strip():
            return [0.0] * self.dimensions

        features = self._extract_features(str(text))
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

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embedding of texts."""
        return [self.embed(t) for t in texts]

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


class HuggingFaceEmbeddingEngine:
    """
    Hugging Face-powered dense neural embedding engine.
    
    Supports:
    1. sentence-transformers (e.g. 'sentence-transformers/all-MiniLM-L6-v2', 'BAAI/bge-small-en-v1.5')
    2. transformers (AutoTokenizer + AutoModel with mean-pooling and L2-normalization)
    3. huggingface_hub.InferenceClient (remote HF Inference API endpoints)
    """

    def __init__(
        self,
        model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        hf_token: Optional[str] = None,
        use_inference_api: bool = False,
        device: Optional[str] = None
    ):
        self.model_name = model_name
        self.hf_token = hf_token or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACEHUB_API_TOKEN")
        self.use_inference_api = use_inference_api
        self.device = device
        self._model = None
        self._tokenizer = None
        self._hf_client = None
        self._dimensions = None
        self.active_backend = "huggingface"

    @property
    def is_available(self) -> bool:
        """Checks if any Hugging Face execution method is available."""
        if self.use_inference_api and HAS_HF_HUB:
            return True
        return HAS_SENTENCE_TRANSFORMERS or HAS_TRANSFORMERS or (HAS_HF_HUB and bool(self.hf_token))

    def _init_model(self):
        """Lazy initialization of the Hugging Face model or client."""
        if self._model is not None or self._hf_client is not None:
            return

        # 1. Hugging Face Inference API via huggingface_hub
        if self.use_inference_api or (not HAS_SENTENCE_TRANSFORMERS and not HAS_TRANSFORMERS and HAS_HF_HUB):
            if not HAS_HF_HUB:
                raise ImportError("huggingface_hub is required for Hugging Face Inference API. Install with: pip install huggingface_hub")
            self._hf_client = InferenceClient(token=self.hf_token)
            return

        # 2. sentence-transformers
        if HAS_SENTENCE_TRANSFORMERS:
            try:
                self._model = SentenceTransformer(self.model_name, device=self.device)
                dim = getattr(self._model, "get_sentence_embedding_dimension", None)
                if callable(dim):
                    self._dimensions = dim()
                return
            except Exception as e:
                logger.warning(f"Could not load SentenceTransformer({self.model_name}): {e}")

        # 3. transformers (AutoTokenizer + AutoModel fallback)
        if HAS_TRANSFORMERS:
            try:
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self._model = AutoModel.from_pretrained(self.model_name)
                if self.device:
                    self._model = self._model.to(self.device)
                self._model.eval()
                hidden_size = getattr(self._model.config, "hidden_size", None)
                if hidden_size:
                    self._dimensions = hidden_size
                return
            except Exception as e:
                logger.warning(f"Could not load transformers AutoModel({self.model_name}): {e}")

        raise RuntimeError(
            f"No usable Hugging Face backend available for '{self.model_name}'. "
            "Install sentence-transformers via: pip install sentence-transformers"
        )

    @property
    def dimensions(self) -> int:
        if self._dimensions is not None:
            return self._dimensions
        sample = self.embed("AgentGuard probe")
        self._dimensions = len(sample)
        return self._dimensions

    def embed(self, text: str) -> List[float]:
        """Convert text into an L2-normalized Hugging Face dense embedding vector."""
        if not text or not str(text).strip():
            dim = self._dimensions or 384
            return [0.0] * dim

        self._init_model()

        # 1. Using SentenceTransformer or model with encode method
        if self._model is not None and hasattr(self._model, "encode"):
            vec = self._model.encode(text, normalize_embeddings=True)
            if hasattr(vec, "tolist"):
                return vec.tolist()
            return list(vec)

        # 2. Using transformers AutoTokenizer + AutoModel
        if HAS_TRANSFORMERS and self._tokenizer is not None and self._model is not None:
            import torch
            inputs = self._tokenizer(text, return_tensors="pt", padding=True, truncation=True)
            if self.device:
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
            with torch.no_grad():
                outputs = self._model(**inputs)
                mask = inputs['attention_mask'].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
                sum_embeddings = torch.sum(outputs.last_hidden_state * mask, 1)
                sum_mask = torch.clamp(mask.sum(1), min=1e-9)
                mean_pooled = sum_embeddings / sum_mask
                normalized = torch.nn.functional.normalize(mean_pooled, p=2, dim=1)
                return normalized[0].cpu().tolist()

        # 3. Using huggingface_hub InferenceClient
        if self._hf_client is not None:
            res = self._hf_client.feature_extraction(text, model=self.model_name)
            if hasattr(res, "tolist"):
                res = res.tolist()
            if isinstance(res, list) and res and isinstance(res[0], list):
                res = res[0]
            # Normalize vector
            norm = math.sqrt(sum(x * x for x in res))
            if norm > 1e-9:
                res = [x / norm for x in res]
            return res

        raise RuntimeError("Hugging Face model failed to produce embeddings.")

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embedding with SentenceTransformer or Transformers."""
        if not texts:
            return []
        self._init_model()

        if self._model is not None and hasattr(self._model, "encode"):
            vectors = self._model.encode(texts, normalize_embeddings=True)
            if hasattr(vectors, "tolist"):
                vectors = vectors.tolist()
            if isinstance(vectors, list) and vectors and not isinstance(vectors[0], (list, tuple)):
                return [list(vectors)]
            return [list(v) for v in vectors]

        return [self.embed(t) for t in texts]

    @staticmethod
    def dot_product(v1: List[float], v2: List[float]) -> float:
        return SemanticEmbeddingEngine.dot_product(v1, v2)

    @staticmethod
    def cosine_similarity(v1: List[float], v2: List[float]) -> float:
        return SemanticEmbeddingEngine.cosine_similarity(v1, v2)

    @staticmethod
    def cosine_distance(v1: List[float], v2: List[float]) -> float:
        return SemanticEmbeddingEngine.cosine_distance(v1, v2)


class DualModeEmbeddingEngine(SemanticEmbeddingEngine):
    """
    Dual-Mode Semantic Embedding Engine for AgentGuard.
    
    Modes:
    - 'auto' (Default): Attempts Hugging Face dense embeddings if installed/configured;
      transparently falls back to the high-speed built-in n-gram semantic vectorizer.
    - 'huggingface' (or 'hf'): Enforces Hugging Face model execution.
    - 'fast' (or 'builtin', 'local'): Uses the zero-dependency deterministic
      character/word n-gram feature hashing engine for sub-millisecond scanning.
    """

    def __init__(
        self,
        mode: str = "auto",
        hf_model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
        hf_token: Optional[str] = None,
        fast_dimensions: int = 512,
        use_inference_api: bool = False
    ):
        self.fast_engine = SemanticEmbeddingEngine(dimensions=fast_dimensions)
        super().__init__(dimensions=fast_dimensions)
        self.mode = mode.lower()
        self.hf_model_name = hf_model_name
        self.hf_token = hf_token
        self.use_inference_api = use_inference_api
        self._hf_engine: Optional[HuggingFaceEmbeddingEngine] = None
        self._last_error: Optional[str] = None

    @property
    def hf_engine(self) -> HuggingFaceEmbeddingEngine:
        if self._hf_engine is None:
            self._hf_engine = HuggingFaceEmbeddingEngine(
                model_name=self.hf_model_name,
                hf_token=self.hf_token,
                use_inference_api=self.use_inference_api
            )
        return self._hf_engine

    @property
    def model_name(self) -> str:
        if self.active_backend == "huggingface":
            return self.hf_model_name
        return self.fast_engine.model_name

    @model_name.setter
    def model_name(self, val: str):
        self._model_name = val

    @property
    def active_backend(self) -> str:
        """Indicates whether Hugging Face or the Builtin engine is active."""
        if self.mode in ("fast", "local", "builtin"):
            return "builtin"
        if self.mode in ("huggingface", "hf"):
            return "huggingface"
        # mode == 'auto'
        if self.hf_engine.is_available:
            return "huggingface"
        return "builtin"

    @active_backend.setter
    def active_backend(self, val: str):
        self._active_backend = val

    @property
    def dimensions(self) -> int:
        """Returns the dimensions of the active embedding engine."""
        if self.active_backend == "huggingface":
            try:
                return self.hf_engine.dimensions
            except Exception:
                return self.fast_engine.dimensions
        return self.fast_engine.dimensions

    @dimensions.setter
    def dimensions(self, val: int):
        self.fast_engine.dimensions = val

    def set_mode(self, mode: str, hf_model_name: Optional[str] = None):
        """Dynamically switch between 'auto', 'huggingface', and 'fast' modes."""
        valid_modes = ("auto", "huggingface", "hf", "fast", "local", "builtin")
        mode_clean = mode.lower()
        if mode_clean not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Expected one of {valid_modes}")
        self.mode = mode_clean
        if hf_model_name:
            self.hf_model_name = hf_model_name
            self._hf_engine = None  # Re-init on next use

    def embed(self, text: str) -> List[float]:
        """Generates embeddings using the active or auto-fallback engine."""
        if self.mode in ("fast", "local", "builtin"):
            return self.fast_engine.embed(text)

        if self.mode in ("huggingface", "hf"):
            return self.hf_engine.embed(text)

        # mode == 'auto'
        if self.hf_engine.is_available:
            try:
                return self.hf_engine.embed(text)
            except Exception as e:
                self._last_error = str(e)
                logger.info(f"Hugging Face embedding unavailable in auto mode ({e}); falling back to fast built-in engine.")
                return self.fast_engine.embed(text)

        return self.fast_engine.embed(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Batch embedding with the active engine."""
        if self.mode in ("fast", "local", "builtin"):
            return self.fast_engine.embed_batch(texts)

        if self.mode in ("huggingface", "hf"):
            return self.hf_engine.embed_batch(texts)

        # mode == 'auto'
        if self.hf_engine.is_available:
            try:
                return self.hf_engine.embed_batch(texts)
            except Exception as e:
                self._last_error = str(e)
                return self.fast_engine.embed_batch(texts)

        return self.fast_engine.embed_batch(texts)

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive diagnostic and telemetry status of the embedding engine."""
        return {
            "mode": self.mode,
            "active_backend": self.active_backend,
            "model_name": self.model_name,
            "dimensions": self.dimensions,
            "huggingface_available": self.hf_engine.is_available,
            "backends_detected": {
                "sentence_transformers": HAS_SENTENCE_TRANSFORMERS,
                "transformers": HAS_TRANSFORMERS,
                "huggingface_hub": HAS_HF_HUB
            },
            "last_error": self._last_error
        }


# ---------------------------------------------------------------------------
# Global default engine singleton (Dual-Mode with Auto-Fallback)
# ---------------------------------------------------------------------------
default_engine = DualModeEmbeddingEngine(mode="auto")
