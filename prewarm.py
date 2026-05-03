"""Pre-warm all ML models at Docker build time.

Triggers HuggingFace Hub model downloads + Presidio engine init so all
binaries are baked into the Docker image; no internet access is needed
at runtime. The spaCy ``en_core_web_lg`` model used by Presidio is
already pulled by ``uv sync`` (declared as a direct dep in pyproject.toml),
so this script doesn't need to download it.
"""

import logging

from presidio_analyzer import AnalyzerEngine
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("prewarm")

logger.info("Pre-warming Tidewall ML models...")

# Vijil DOME (prompt injection) — needs ModernBERT tokenizer separately.
logger.info("Vijil DOME prompt-injection model + ModernBERT tokenizer...")
_ = AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
_ = AutoModelForSequenceClassification.from_pretrained("vijil/vijil_dome_prompt_injection_detection")

# Toxicity classifier
logger.info("Toxicity model (unitary/unbiased-toxic-roberta)...")
_ = pipeline("text-classification", model="unitary/unbiased-toxic-roberta", top_k=None, device="cpu")

# Zero-shot topic classifier
logger.info("Zero-shot topic model (MoritzLaurer/roberta-base-zeroshot-v2.0-c)...")
_ = pipeline("zero-shot-classification", model="MoritzLaurer/roberta-base-zeroshot-v2.0-c", device="cpu")

# Language detection
logger.info("Language detector (papluca/xlm-roberta-base-language-detection)...")
_ = pipeline("text-classification", model="papluca/xlm-roberta-base-language-detection", device="cpu")

# Code-language identification
logger.info("Code-language classifier (philomath-1209/programming-language-identification)...")
_ = pipeline("text-classification", model="philomath-1209/programming-language-identification", device="cpu")

# Malicious URL classifier
logger.info("Malicious-URL classifier (DunnBC22/codebert-base-Malicious_URLs)...")
_ = pipeline("text-classification", model="DunnBC22/codebert-base-Malicious_URLs", device="cpu")

# Sentence-transformer for intent conformance
logger.info("Sentence-transformer (all-MiniLM-L6-v2)...")
_ = SentenceTransformer("all-MiniLM-L6-v2")

# Presidio AnalyzerEngine — warms NER models. en_core_web_lg is already
# installed via uv sync (direct dep in pyproject.toml), so this just
# loads it into memory.
logger.info("Presidio AnalyzerEngine (warms NER models)...")
_ = AnalyzerEngine()

logger.info("All models pre-warmed successfully!")
