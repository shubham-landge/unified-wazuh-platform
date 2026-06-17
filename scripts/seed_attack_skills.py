#!/usr/bin/env python3
"""Seed the RAG knowledge base with MITRE ATT&CK skill files.

Reads markdown skill files (one technique per file, e.g. ``T1059.001.md``) from
one or more directories and ingests them into the ``knowledge_chunks`` table via
the existing RAG pipeline (chunk -> embed -> store). Idempotent per source: a
technique already present (matched by ``source``) is skipped unless ``--force``.

Sources, in order of preference:
  1. ``--skills-dir`` argument (repeatable)
  2. ``prompts/skills/`` in the repo (the 5 curated techniques shipped today)
  3. An external clone (e.g. mukul975/awesome-attck-skill-db) pointed at via
     ``ATTACK_SKILLS_DIR`` env var or ``--skills-dir``.

Run on-demand (needs the embedding model reachable via OLLAMA_BASE_URL):
    python scripts/seed_attack_skills.py
    python scripts/seed_attack_skills.py --skills-dir /opt/attck-skill-db --force

This is intentionally a standalone script, not a startup hook, so seeding 700+
embeddings never blocks service boot on the CPU-only box.
"""
import argparse
import asyncio
import glob
import logging
import os
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

# Allow running from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import settings  # noqa: E402
from shared.models.knowledge_base import KnowledgeChunk  # noqa: E402
from shared.rag.vector_store import chunk_and_ingest  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("seed_attack_skills")


def _default_dirs() -> list[str]:
    dirs = []
    env_dir = os.environ.get("ATTACK_SKILLS_DIR")
    if env_dir:
        dirs.append(env_dir)
    repo_skills = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts", "skills")
    dirs.append(repo_skills)
    return dirs


async def _already_seeded(session, source: str) -> bool:
    res = await session.execute(
        select(KnowledgeChunk.id).where(KnowledgeChunk.source == source).limit(1)
    )
    return res.scalar_one_or_none() is not None


async def seed(dirs: list[str], force: bool) -> dict:
    engine = create_async_engine(settings.database_sync_url.replace("postgresql://", "postgresql+asyncpg://"))
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    files: list[str] = []
    for d in dirs:
        if os.path.isdir(d):
            files.extend(sorted(glob.glob(os.path.join(d, "T*.md"))))
    files = list(dict.fromkeys(files))  # dedupe, preserve order

    if not files:
        logger.warning("No ATT&CK skill files (T*.md) found in: %s", dirs)
        return {"ingested": 0, "skipped": 0, "files": 0}

    ingested = skipped = 0
    async with session_factory() as session:
        for path in files:
            technique = os.path.splitext(os.path.basename(path))[0]
            source = f"attack-skill:{technique}"
            if not force and await _already_seeded(session, source):
                skipped += 1
                continue
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            await chunk_and_ingest(
                source,
                text,
                session,
                chunk_size=settings.rag_chunk_size,
                overlap=settings.rag_chunk_overlap,
                metadata={"type": "attack_skill", "technique": technique},
            )
            ingested += 1
            logger.info("Seeded %s", technique)

    await engine.dispose()
    return {"ingested": ingested, "skipped": skipped, "files": len(files)}


def main():
    ap = argparse.ArgumentParser(description="Seed RAG KB with MITRE ATT&CK skills")
    ap.add_argument("--skills-dir", action="append", default=[], help="Directory of T*.md skill files (repeatable)")
    ap.add_argument("--force", action="store_true", help="Re-ingest even if already seeded")
    args = ap.parse_args()

    dirs = args.skills_dir or _default_dirs()
    result = asyncio.run(seed(dirs, args.force))
    logger.info("Done: %s", result)


if __name__ == "__main__":
    main()
