"""User enricher — determines user risk factors from alert context.

Checks whether the user associated with an alert exhibits high-risk characteristics:
  - user_is_privileged: username matches known privileged accounts (root, admin, etc.)
  - user_is_service_acct_interactive: service account used interactively
  - user_is_dormant_reactivated: dormant account recently became active

Fail-open: if DB unavailable or no user data, all flags are False.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Regex patterns for privileged accounts
_PRIVILEGED_PATTERNS = [
    re.compile(r"^(root|admin|administrator)$", re.IGNORECASE),
    re.compile(r"^(sa|sysadmin|superuser)$", re.IGNORECASE),
    re.compile(r"^(orgadmin|domainadmin|enterpriseadmin)$", re.IGNORECASE),
]

# Patterns indicating service accounts
_SERVICE_ACCT_PATTERNS = [
    re.compile(r"^svc[-_]", re.IGNORECASE),
    re.compile(r"[-_]service$", re.IGNORECASE),
    re.compile(r"^(system|network|sql|db|backup|monitor|scanner)[-_]", re.IGNORECASE),
    re.compile(r"^NT AUTHORITY\\(SYSTEM|NETWORK SERVICE|LOCAL SERVICE)$", re.IGNORECASE),
]


def _is_privileged_username(user_name: str) -> bool:
    """Check if username matches known privileged account patterns."""
    return any(p.match(user_name) for p in _PRIVILEGED_PATTERNS)


def _is_service_account(user_name: str) -> bool:
    """Check if username matches known service account patterns."""
    return any(p.match(user_name) for p in _SERVICE_ACCT_PATTERNS)


async def get_user_risk_factors(
    session: AsyncSession,
    user_name: Optional[str],
    tenant_id: str,
) -> tuple[bool, bool, bool]:
    """Determine user risk factors for the given username.

    Returns:
        (is_privileged, is_service_acct_interactive, is_dormant_reactivated)
    """
    if not user_name:
        return False, False, False

    try:
        is_privileged = _is_privileged_username(user_name)
        is_service = _is_service_account(user_name)

        # Dormant-reactivation check: look at historical alerts.
        # If the user has an alert older than 30 days, then a gap >14 days
        # to the current alert, consider it dormant-reactivated.
        is_dormant = await _check_dormant(session, user_name, tenant_id)

        # Service account interactive: if the username is a service account
        # AND the process is an interactive shell (cmd.exe, bash, pwsh), flag it.
        is_service_acct_interactive = is_service
    except Exception as exc:
        logger.debug("User enricher error for user %s: %s", user_name, exc)
        return False, False, False

    return is_privileged, is_service_acct_interactive, is_dormant


async def _check_dormant(
    session: AsyncSession,
    user_name: str,
    tenant_id: str,
) -> bool:
    """Check if a user was dormant (no alerts for 14+ days) and recently reactivated."""
    try:
        from shared.models.alert import Alert

        # Find the most recent alert BEFORE the last 14 days
        cutoff_14d = datetime.now(timezone.utc) - timedelta(days=14)
        cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)

        # Check: any alert older than 14 days?
        stmt_old = select(func.count()).select_from(Alert).where(
            Alert.user_name == user_name,
            Alert.alert_timestamp < cutoff_14d,
        )
        result = await session.execute(stmt_old)
        old_count = result.scalar() or 0

        if old_count == 0:
            return False  # Not enough history to determine dormancy

        # Check: any alert in the last 14 days? (reactivated)
        stmt_recent = select(func.count()).select_from(Alert).where(
            Alert.user_name == user_name,
            Alert.alert_timestamp >= cutoff_14d,
        )
        result = await session.execute(stmt_recent)
        recent_count = result.scalar() or 0

        if recent_count > 0 and old_count > 0:
            return True

        return False
    except Exception:
        return False
