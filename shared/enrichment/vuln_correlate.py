"""Vulnerability correlation enricher.

When an alert has rule_group tags suggesting exploitation (e.g. web attack,
buffer overflow, CVE mention), check if the target host has an open vulnerability
with a matching CVE in the database.

Fail-open: if DB unavailable or no match, returns (False, 0.0, False).
"""
from __future__ import annotations
import logging
import re
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
logger = logging.getLogger(__name__)

# CVE pattern
_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)

# Rule group keywords that suggest exploitation attempts
_EXPLOIT_KEYWORDS = frozenset([
    "web", "exploit", "buffer", "overflow", "rce", "sqli", "injection",
    "shellshock", "heartbleed", "log4j", "proxyshell", "printnightmare",
    "eternalblue", "bluekeep", "cve",
])

async def correlate(
    session: AsyncSession,
    agent_id: Optional[str],
    rule_description: str,
    rule_groups: str,
    rule_cve: Optional[str] = None,
) -> tuple[bool, float, bool]:
    """Check if this alert corresponds to an open CVE on the target host.

    Returns:
        (matched, epss_score, is_kev)
    """
    try:
        # Extract CVE from rule description or explicit field
        cves = _CVE_RE.findall(f"{rule_description} {rule_cve or ''}".upper())
        if not cves:
            # No CVE in alert — check if it looks like exploitation
            groups_lower = rule_groups.lower() if rule_groups else ""
            if not any(kw in groups_lower for kw in _EXPLOIT_KEYWORDS):
                return False, 0.0, False

        if not agent_id:
            return False, 0.0, False

        # Look up vulnerabilities table for this agent
        try:
            q = text("""
                SELECT v.cve_id, v.epss_score, v.is_kev
                FROM vulnerabilities v
                WHERE v.agent_id = :agent_id
                  AND v.status IN ('open', 'active')
                  AND (:cve IS NULL OR v.cve_id = :cve)
                LIMIT 1
            """)
            result = await session.execute(q, {
                "agent_id": agent_id,
                "cve": cves[0] if cves else None,
            })
            row = result.fetchone()
            if row:
                return True, float(row.epss_score or 0.0), bool(row.is_kev)
        except Exception:
            # Table might not exist yet
            pass

        return False, 0.0, False
    except Exception as exc:
        logger.debug("vuln_correlate error: %s", exc)
        return False, 0.0, False
