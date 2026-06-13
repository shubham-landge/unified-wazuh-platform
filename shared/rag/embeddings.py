import json
import logging
from shared.config import settings

logger = logging.getLogger(__name__)


async def embed_text(text: str) -> list[float] | None:
    import httpx
    url = f"{settings.ollama_base_url}/api/embeddings"
    model = getattr(settings, "embedding_model", "nomic-embed-text")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json={"model": model, "prompt": text})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("embedding")
            logger.warning("Embedding API returned %d: %s", resp.status_code, resp.text)
            return None
    except Exception as e:
        logger.error("Embedding request failed: %s", e)
        return None


async def embed_batch(texts: list[str]) -> list[list[float]]:
    results = []
    for t in texts:
        emb = await embed_text(t)
        if emb:
            results.append(emb)
    return results


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)
