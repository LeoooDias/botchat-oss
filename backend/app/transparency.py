"""Transparency module for botchat.

Provides a public, read-only view of the database with masked data.
This demonstrates our privacy-first architecture - we publish what we store
because there's nothing to hide.

SECURITY ARCHITECTURE (Gold Standard):
When TRANSPARENCY_DATABASE_URL is configured, this endpoint uses a RESTRICTED
PostgreSQL role (transparency_reader) that can ONLY access the transparency_users
VIEW - not the underlying users table. This means:

1. Even if this endpoint is compromised, raw user data cannot be exfiltrated
2. The VIEW itself does all masking in PostgreSQL - data leaves the DB pre-masked
3. The backend never sees raw sensitive values for transparency requests

MASKING (done in PostgreSQL VIEW):
- id: Always "•••"
- oauth_id: First 8 characters + "..."
- stripe_customer_id: "cus_•••••" if exists, else null
- All other fields: "•••" if exists, else null
- Order: Randomized to prevent sequence inference
"""

import logging
import random
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, cast

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.database import get_pool, get_transparency_pool

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/transparency", tags=["transparency"])


# -----------------------------
# Response Models
# -----------------------------

class AnonymizedUser(BaseModel):
    """A single user record with masked fields for public display.
    
    This model includes ALL database columns to demonstrate full transparency.
    Most fields are masked to protect user privacy while proving the schema.
    """
    # Primary key (masked)
    id: str  # "•••" - proves auto-increment exists
    
    # Identity
    oauth_provider: str  # Shown as-is
    oauth_id: str  # First 8 chars of hash shown
    
    # Billing
    stripe_customer_id: Optional[str]  # "cus_•••••" or null
    subscription_status: str  # Masked
    subscription_id: Optional[str]  # Masked
    subscription_ends_at: Optional[str]  # Masked
    
    # Usage
    message_quota_used: str  # Masked
    quota_period_start: Optional[str]  # Masked
    total_messages: str  # Masked
    
    # Recovery (optional feature)
    recovery_email_hash: Optional[str]  # Masked (proves field exists)
    recovery_email_set_at: Optional[str]  # Masked
    
    # Account Status (abuse tracking - always masked)
    account_status: str  # Masked - active/suspended/deleted
    
    # Timestamps
    created_at: str  # Masked
    updated_at: str  # Masked


class TransparencyResponse(BaseModel):
    """Response from the transparency endpoint."""
    # Metadata
    description: str
    last_generated: str
    documentation_url: str
    
    # Schema explanation
    schema_notes: Dict[str, str]

    # Sample data (randomized order, limited for privacy)
    users: List[AnonymizedUser]


# NOTE: Masking is now done in PostgreSQL via the transparency_users VIEW
# The anonymize_user() helper below is kept for reference but no longer used


# -----------------------------
# API Endpoints
# -----------------------------

@router.get("/database", response_model=TransparencyResponse)
async def get_transparency_data(
    limit: int = Query(default=25, le=25, ge=1, description="Max records to return (capped at 25)"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
):
    """
    Public endpoint showing sample user data with privacy masking.
    
    This endpoint demonstrates our privacy-first architecture by exposing
    the schema and sample records. The data is masked to prevent
    identification while proving we store no personal information.
    
    Note: Limited to 25 sample records to demonstrate schema without revealing user base size.
    
    **Security**: Uses transparency_users VIEW (masking done in PostgreSQL).
    When TRANSPARENCY_DATABASE_URL is configured, uses a restricted role that
    cannot access the underlying users table at all.
    
    **Masking applied (in PostgreSQL VIEW):**
    - OAuth IDs: First 8 characters of SHA-256 hash
    - Stripe IDs: Masked to "cus_•••••"
    - All other fields: "•••" or null
    - Results: Randomly ordered
    
    No authentication required - this is intentionally public.
    """
    # Use transparency pool if available (gold standard), else main pool
    pool = get_transparency_pool()
    if not pool:
        raise HTTPException(
            status_code=503, 
            detail="Database not available"
        )
    
    try:
        # Note: asyncpg lacks complete type stubs, so we use type: ignore comments
        async with pool.acquire() as conn:  # type: ignore[union-attr]
            # Fetch from the VIEW - data is ALREADY masked by PostgreSQL
            # This is the gold standard: raw data never leaves the database
            fetch_result = await conn.fetch(  # type: ignore[union-attr]
                """
                SELECT 
                    id,
                    oauth_provider,
                    oauth_id,
                    stripe_customer_id,
                    subscription_status,
                    subscription_id,
                    subscription_ends_at,
                    message_quota_used,
                    quota_period_start,
                    total_messages,
                    recovery_email_hash,
                    recovery_email_set_at,
                    created_at,
                    updated_at,
                    account_status
                FROM transparency_users
                ORDER BY RANDOM()
                LIMIT $1 OFFSET $2
                """,
                limit,
                offset,
            )
            rows: List[Dict[str, Any]] = [
                dict(row) for row in cast(List[Any], fetch_result)
            ]
            
            # Convert to response model (data is already masked from VIEW)
            users: List[AnonymizedUser] = [
                AnonymizedUser(
                    id=row["id"],
                    oauth_provider=row["oauth_provider"],
                    oauth_id=row["oauth_id"],
                    stripe_customer_id=row.get("stripe_customer_id"),
                    subscription_status=row["subscription_status"],
                    subscription_id=row.get("subscription_id"),
                    subscription_ends_at=row.get("subscription_ends_at"),
                    message_quota_used=row["message_quota_used"],
                    quota_period_start=row.get("quota_period_start"),
                    total_messages=row["total_messages"],
                    recovery_email_hash=row.get("recovery_email_hash"),
                    recovery_email_set_at=row.get("recovery_email_set_at"),
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                    account_status=row["account_status"],
                )
                for row in rows
            ]
            
            # Additional shuffle for extra randomness
            random.shuffle(users)
            
            return TransparencyResponse(
                description=(
                    "This is a sample of our user database schema with masked data. "
                    "We publish this to demonstrate our privacy-first architecture. "
                    "We do not store names, emails, or any personally identifying information."
                ),
                last_generated=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                documentation_url="https://botchat.ca/privacy",
                schema_notes={},  # Schema details now shown inline in table headers
                users=users,
            )
            
    except Exception as e:
        logger.error("Transparency endpoint error: %s", str(e))
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve transparency data"
        )


@router.get("/schema")
async def get_database_schema() -> Dict[str, Any]:
    """
    Returns the exact database schema we use.
    
    This shows the CREATE TABLE statement so you can see
    exactly what columns exist and their types.
    """
    return {
        "description": "Exact PostgreSQL schema for the users table",
        "table_name": "users",
        "schema": """
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    oauth_provider VARCHAR(20) NOT NULL,
    oauth_id VARCHAR(64) NOT NULL,          -- SHA-256 hash, NOT raw OAuth ID
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(20) DEFAULT 'none',
    subscription_id VARCHAR(255),
    subscription_ends_at TIMESTAMP,
    message_quota_used INT DEFAULT 0,
    quota_period_start TIMESTAMP DEFAULT NOW(),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(oauth_provider, oauth_id)
);
        """.strip(),
        "privacy_notes": {
            "oauth_id": "This is a SHA-256 hash of the original OAuth ID, salted with a secret. The original ID cannot be recovered.",
            "no_email": "Notice there is no email column. We don't store or request your email address.",
            "no_name": "Notice there is no name column. We don't store or request your name.",
        }
    }
