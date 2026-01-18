# ============================================================================
# ⚠️  PUBLIC FILE - Part of botchat-oss transparency repo
# ============================================================================
# This file is publicly visible at: https://github.com/LeoooDias/botchat-oss
#
# Purpose: Demonstrate privacy-first data schema (what we store/don't store)
#
# ⚠️  DO NOT add proprietary business logic here
# ⚠️  Only data schema transparency code belongs in this file
# ============================================================================

"""Database module for botchat.

Handles PostgreSQL connection and user/subscription storage.

PRIVACY-FIRST DATA MODEL:
- NO personally identifying information (PII) is stored
- oauth_id is a SHA-256 hash (cannot be reversed to original OAuth ID)
- recovery_email_hash is SHA-256 (user's optional recovery email, hashed)
- total_messages tracks lifetime usage for recovery email prompt (at 500)

Tables:
- users: Hashed OAuth identity + Stripe customer ID + subscription status + quota tracking
"""

import os
import hashlib
import logging
from typing import Optional
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

import asyncpg
from asyncpg import Pool

logger = logging.getLogger(__name__)


# Custom exceptions
class AccountDeletedException(Exception):
    """Raised when a user tries to re-register during tombstone period."""
    pass


# GCP project for Secrets Manager (optional)
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")


def _get_secret_from_gcp(secret_name: str) -> Optional[str]:
    """Fetch a secret from GCP Secret Manager.
    
    Returns None if GCP is not configured or secret doesn't exist.
    """
    if not GCP_PROJECT_ID:
        return None
    
    try:
        from google.cloud import secretmanager
        
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{GCP_PROJECT_ID}/secrets/{secret_name}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except ImportError:
        logger.debug("google-cloud-secret-manager not installed, using env vars")
        return None
    except Exception as e:
        logger.warning("Failed to fetch secret %s from GCP: %s", secret_name, str(e))
        return None


def _get_pepper(secret_name: str, env_var: str) -> str:
    """Get pepper/salt from GCP Secrets Manager with env var fallback."""
    gcp_value = _get_secret_from_gcp(secret_name)
    if gcp_value:
        logger.info("Loaded %s from GCP Secret Manager", secret_name)
        return gcp_value
    
    env_value = os.environ.get(env_var, "")
    if env_value:
        logger.info("Loaded %s from environment variable", env_var)
        return env_value
    
    return ""


# Recovery email hashing salt (separate from OAuth salt for defense in depth)
# Loaded from GCP Secret Manager (recovery-email-salt) or RECOVERY_EMAIL_SALT env var
RECOVERY_EMAIL_SALT = _get_pepper("recovery-email-salt", "RECOVERY_EMAIL_SALT")


def hash_recovery_email(email: str) -> str:
    """Hash a recovery email address.
    
    Uses SHA-256 with salt. The email is normalized (lowercase, trimmed)
    before hashing to ensure consistent lookups.
    """
    if not RECOVERY_EMAIL_SALT:
        logger.warning("RECOVERY_EMAIL_SALT not set - using unsalted hash (insecure)")
        salt = "default-salt-insecure"
    else:
        salt = RECOVERY_EMAIL_SALT
    
    normalized = email.strip().lower()
    data = f"{salt}:{normalized}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()

# Database URL from environment
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Transparency-specific database URL (read-only user with only VIEW access)
# Falls back to main DATABASE_URL if not set
TRANSPARENCY_DATABASE_URL = os.environ.get("TRANSPARENCY_DATABASE_URL", "")

# Connection pool (initialized on startup)
_pool: Optional[Pool] = None

# Separate pool for transparency endpoint (uses restricted role)
_transparency_pool: Optional[Pool] = None


# -----------------------------
# Connection Management
# -----------------------------

async def init_db():
    """Initialize database connection pool and create tables."""
    global _pool, _transparency_pool
    
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set - billing features disabled")
        return
    
    try:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=2,
            max_size=10,
            command_timeout=60,
        )
        logger.info("Database connection pool created")
        
        # Create transparency pool if URL provided (optional gold-standard setup)
        if TRANSPARENCY_DATABASE_URL:
            try:
                _transparency_pool = await asyncpg.create_pool(
                    TRANSPARENCY_DATABASE_URL,
                    min_size=1,
                    max_size=3,
                    command_timeout=30,
                )
                logger.info("Transparency database pool created (restricted role)")
            except Exception as e:
                logger.warning("Failed to create transparency pool: %s - using main pool", str(e))
                _transparency_pool = None
        
        # Create tables if they don't exist
        await _create_tables()
        
    except Exception as e:
        logger.error("Failed to initialize database: %s", str(e))
        raise


async def close_db():
    """Close database connection pools."""
    global _pool, _transparency_pool
    if _transparency_pool:
        await _transparency_pool.close()
        _transparency_pool = None
        logger.info("Transparency database pool closed")
    if _pool:
        await _pool.close()
        _pool = None
        logger.info("Database connection pool closed")


async def _create_tables():
    """Create required tables if they don't exist.
    
    PRIVACY-FIRST SCHEMA:
    - oauth_id stores HASHED OAuth IDs (SHA-256), not raw IDs
    - email column kept for migration but will be deprecated
    - recovery_email_hash for optional account recovery (hashed)
    - total_messages for 500-message recovery email prompt
    """
    if not _pool:
        return
    
    async with _pool.acquire() as conn:
        # Base table - oauth_id is now a HASH, not the raw OAuth ID
        # PRIVACY: No email column - we don't store PII
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                oauth_provider VARCHAR(20) NOT NULL,
                oauth_id VARCHAR(64) NOT NULL,
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
            
            CREATE INDEX IF NOT EXISTS idx_users_stripe_customer 
                ON users(stripe_customer_id);
            
            CREATE INDEX IF NOT EXISTS idx_users_oauth 
                ON users(oauth_provider, oauth_id);
        """)
        
        # Add quota columns if they don't exist (migration for existing DBs)
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'message_quota_used'
                ) THEN
                    ALTER TABLE users ADD COLUMN message_quota_used INT DEFAULT 0;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'quota_period_start'
                ) THEN
                    ALTER TABLE users ADD COLUMN quota_period_start TIMESTAMP DEFAULT NOW();
                END IF;
            END $$;
        """)
        
        # PRIVACY: Add anonymous auth columns
        await conn.execute("""
            DO $$
            BEGIN
                -- Total lifetime messages (for 500-message recovery email prompt)
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'total_messages'
                ) THEN
                    ALTER TABLE users ADD COLUMN total_messages BIGINT DEFAULT 0;
                END IF;
                
                -- Recovery email (hashed) - optional, prompted at 500 messages
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'recovery_email_hash'
                ) THEN
                    ALTER TABLE users ADD COLUMN recovery_email_hash VARCHAR(64);
                END IF;
                
                -- When recovery email was set (for user info display)
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'recovery_email_set_at'
                ) THEN
                    ALTER TABLE users ADD COLUMN recovery_email_set_at TIMESTAMP;
                END IF;
            END $$;
        """)
        
        # Index for recovery email lookups
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_recovery_email 
                ON users(recovery_email_hash) WHERE recovery_email_hash IS NOT NULL;
        """)
        
        # TOMBSTONE TABLE: Tracks deleted accounts for abuse prevention
        # Stores oauth_id hash, deletion reason, strike history for repeat offender tracking
        # Auto-purged after 90 days unless permanent_ban = true
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS deleted_accounts (
                id SERIAL PRIMARY KEY,
                oauth_provider VARCHAR(20) NOT NULL,
                oauth_id VARCHAR(64) NOT NULL,
                deleted_at TIMESTAMP DEFAULT NOW(),
                purge_after TIMESTAMP DEFAULT (NOW() + INTERVAL '90 days'),
                strike_count INT DEFAULT 0,
                final_reason TEXT,
                permanent_ban BOOLEAN DEFAULT FALSE
            );
            
            CREATE INDEX IF NOT EXISTS idx_deleted_accounts_oauth 
                ON deleted_accounts(oauth_provider, oauth_id);
            
            CREATE INDEX IF NOT EXISTS idx_deleted_accounts_purge 
                ON deleted_accounts(purge_after);
        """)
        
        # MIGRATION: Add strike history columns to existing deleted_accounts table
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'deleted_accounts' AND column_name = 'strike_count'
                ) THEN
                    ALTER TABLE deleted_accounts ADD COLUMN strike_count INT DEFAULT 0;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'deleted_accounts' AND column_name = 'final_reason'
                ) THEN
                    ALTER TABLE deleted_accounts ADD COLUMN final_reason TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'deleted_accounts' AND column_name = 'permanent_ban'
                ) THEN
                    ALTER TABLE deleted_accounts ADD COLUMN permanent_ban BOOLEAN DEFAULT FALSE;
                END IF;
            END $$;
        """)
        
        # TRANSPARENCY VIEW: Pre-masked view of users table
        # This view does all masking in PostgreSQL - the data returned is already safe
        # If using a restricted role (transparency_reader), they only have SELECT on this view
        await conn.execute("""
            CREATE OR REPLACE VIEW transparency_users AS
            SELECT 
                '•••' as id,
                oauth_provider,
                LEFT(oauth_id, 8) || '...' as oauth_id,
                CASE WHEN stripe_customer_id IS NOT NULL THEN 'cus_•••••' ELSE NULL END as stripe_customer_id,
                '•••' as subscription_status,
                CASE WHEN subscription_id IS NOT NULL THEN '•••' ELSE NULL END as subscription_id,
                CASE WHEN subscription_ends_at IS NOT NULL THEN '•••' ELSE NULL END as subscription_ends_at,
                '•••' as message_quota_used,
                CASE WHEN quota_period_start IS NOT NULL THEN '•••' ELSE NULL END as quota_period_start,
                '•••' as total_messages,
                CASE WHEN recovery_email_hash IS NOT NULL THEN '•••' ELSE NULL END as recovery_email_hash,
                CASE WHEN recovery_email_set_at IS NOT NULL THEN '•••' ELSE NULL END as recovery_email_set_at,
                '•••' as created_at,
                '•••' as updated_at,
                '•••' as account_status
            FROM users;
        """)
        
        # ACCOUNT STATUS: Add account_status column to users table
        # Tracks: 'active' (default), 'suspended' (pending review), 'deleted'
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'account_status'
                ) THEN
                    ALTER TABLE users ADD COLUMN account_status VARCHAR(20) DEFAULT 'active';
                END IF;
            END $$;
        """)
        
        # V3.0.0: SUBSCRIPTION TIER: Add subscription_tier column to users table
        # Tracks: NULL (free), 'pro' ($9/month), 'plus' ($19/month)
        # Existing paid users are grandfathered as 'plus'
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'subscription_tier'
                ) THEN
                    ALTER TABLE users ADD COLUMN subscription_tier VARCHAR(10) DEFAULT NULL;
                    -- Grandfather existing paid users as 'plus'
                    UPDATE users SET subscription_tier = 'plus' 
                    WHERE subscription_status IN ('active', 'trialing');
                END IF;
            END $$;
        """)
        
        # STRIKES TABLE: Tracks abuse incidents for admin review
        # Each strike auto-suspends the account pending admin decision
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS strikes (
                id SERIAL PRIMARY KEY,
                user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                reason VARCHAR(50) NOT NULL,
                details TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                resolved_at TIMESTAMP,
                resolution VARCHAR(20),
                admin_notes TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_strikes_user_id 
                ON strikes(user_id);
            
            CREATE INDEX IF NOT EXISTS idx_strikes_unresolved 
                ON strikes(user_id) WHERE resolved_at IS NULL;
        """)
        
        # ANALYTICS TABLES: Anonymous event tracking
        # PRIVACY: No foreign keys to users table. Session IDs are random and ephemeral.
        # We cannot link events to user identities - by design.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analytics_events (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(32) NOT NULL,
                event_name VARCHAR(50) NOT NULL,
                event_data JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT NOW(),
                utm_source VARCHAR(100),
                utm_medium VARCHAR(100),
                utm_campaign VARCHAR(100),
                utm_content VARCHAR(100),
                landing_variant VARCHAR(20),
                referrer_domain VARCHAR(100),
                device_type VARCHAR(20)
            );
            
            CREATE INDEX IF NOT EXISTS idx_analytics_session 
                ON analytics_events(session_id);
            CREATE INDEX IF NOT EXISTS idx_analytics_event 
                ON analytics_events(event_name);
            CREATE INDEX IF NOT EXISTS idx_analytics_date 
                ON analytics_events(created_at);
            CREATE INDEX IF NOT EXISTS idx_analytics_campaign 
                ON analytics_events(utm_source, utm_campaign);
        """)
        
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS analytics_daily (
                date DATE PRIMARY KEY,
                visits INT DEFAULT 0,
                unique_sessions INT DEFAULT 0,
                signups_started INT DEFAULT 0,
                signups_completed INT DEFAULT 0,
                first_chat_created INT DEFAULT 0,
                first_message_sent INT DEFAULT 0,
                multi_model_response INT DEFAULT 0,
                attachment_added INT DEFAULT 0,
                bots_created INT DEFAULT 0,
                chats_created INT DEFAULT 0,
                messages_sent INT DEFAULT 0,
                summarize_used INT DEFAULT 0,
                export_used INT DEFAULT 0,
                deep_mode_used INT DEFAULT 0,
                return_24h INT DEFAULT 0,
                return_48h INT DEFAULT 0,
                checkout_started INT DEFAULT 0,
                payment_completed INT DEFAULT 0
            );
        """)
        
        # BUG REPORTS TABLE: Anonymous bug reports from users
        # PRIVACY: Completely anonymous - no user ID, no session ID, just content + timestamp
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS bug_reports (
                id SERIAL PRIMARY KEY,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            CREATE INDEX IF NOT EXISTS idx_bug_reports_created 
                ON bug_reports(created_at DESC);
        """)
        
        logger.info("Database tables and views created/verified")


def get_pool() -> Optional[Pool]:
    """Get the database connection pool."""
    return _pool


def get_transparency_pool() -> Optional[Pool]:
    """Get the transparency-specific connection pool.
    
    Returns the restricted pool if available (gold standard setup),
    otherwise falls back to the main pool.
    
    SECURITY: When TRANSPARENCY_DATABASE_URL is set, this returns a pool
    connected as a restricted role (transparency_reader) that can ONLY
    SELECT from the transparency_users VIEW - not the underlying users table.
    """
    return _transparency_pool or _pool


# -----------------------------
# User Operations
# NOTE: oauth_id parameter is now a HASH, not the raw OAuth ID
# -----------------------------

async def get_user_by_oauth(provider: str, oauth_id: str) -> Optional[dict]:
    """Get user by OAuth provider and hashed ID.
    
    PRIVACY: oauth_id is a SHA-256 hash, not the raw OAuth ID.
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, oauth_provider, oauth_id, stripe_customer_id,
                   subscription_status, subscription_id, subscription_ends_at,
                   subscription_tier,
                   message_quota_used, quota_period_start,
                   total_messages, recovery_email_hash, recovery_email_set_at,
                   account_status,
                   created_at, updated_at
            FROM users
            WHERE oauth_provider = $1 AND oauth_id = $2
            """,
            provider, oauth_id
        )
        return dict(row) if row else None


async def get_user_by_stripe_customer(customer_id: str) -> Optional[dict]:
    """Get user by Stripe customer ID."""
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, oauth_provider, oauth_id, stripe_customer_id,
                   subscription_status, subscription_id, subscription_ends_at,
                   subscription_tier,
                   message_quota_used, quota_period_start,
                   total_messages, recovery_email_hash, recovery_email_set_at,
                   created_at, updated_at
            FROM users
            WHERE stripe_customer_id = $1
            """,
            customer_id
        )
        return dict(row) if row else None


async def get_user_by_recovery_email(email: str) -> Optional[dict]:
    """Get user by recovery email hash.
    
    Used for account recovery when user loses access to OAuth provider.
    """
    if not _pool:
        return None
    
    email_hash = hash_recovery_email(email)
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, oauth_provider, oauth_id, stripe_customer_id,
                   subscription_status, subscription_id, subscription_ends_at,
                   message_quota_used, quota_period_start,
                   total_messages, recovery_email_hash, recovery_email_set_at,
                   created_at, updated_at
            FROM users
            WHERE recovery_email_hash = $1
            """,
            email_hash
        )
        return dict(row) if row else None


# NOTE: get_user_by_email removed - we no longer store emails
# Accounts are identified by hashed OAuth ID only.
# Recovery is possible via optional recovery_email_hash.


async def get_user_for_billing(provider: str, oauth_id: str, email: Optional[str] = None) -> Optional[dict]:
    """Get user for billing purposes by exact OAuth identity.
    
    PRIVACY: oauth_id is a hash, not the raw OAuth ID.
    The email parameter is ignored (kept for API compatibility during migration).
    """
    return await get_user_by_oauth(provider, oauth_id)


async def create_user(provider: str, oauth_id: str, email: Optional[str] = None) -> dict:
    """Create a new user or return existing user by OAuth identity.
    
    PRIVACY: oauth_id is a hash, not the raw OAuth ID.
    Email parameter is ignored (kept for API compatibility during migration).
    
    ABUSE PREVENTION: Checks tombstone table - if account was recently deleted,
    blocks re-registration until the cooldown period expires (90 days).
    """
    if not _pool:
        raise RuntimeError("Database not initialized")
    
    # Check if this exact OAuth identity exists
    existing = await get_user_by_oauth(provider, oauth_id)
    if existing:
        # Same provider + ID, just update timestamp
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE users
                SET updated_at = NOW()
                WHERE oauth_provider = $1 AND oauth_id = $2
                RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                          subscription_status, subscription_id, subscription_ends_at,
                          message_quota_used, quota_period_start,
                          total_messages, recovery_email_hash, recovery_email_set_at,
                          created_at, updated_at
                """,
                provider, oauth_id
            )
            return dict(row)
    
    # Check tombstone table - block re-registration if recently deleted or permanently banned
    async with _pool.acquire() as conn:
        tombstone = await conn.fetchrow(
            """
            SELECT deleted_at, purge_after, permanent_ban, strike_count, final_reason
            FROM deleted_accounts 
            WHERE oauth_provider = $1 AND oauth_id = $2 
            AND (permanent_ban = TRUE OR purge_after > NOW())
            ORDER BY deleted_at DESC
            LIMIT 1
            """,
            provider, oauth_id
        )
        
        if tombstone:
            if tombstone["permanent_ban"]:
                # Permanently banned - no re-registration ever
                raise AccountDeletedException(
                    "This account has been permanently banned due to Terms of Service violations."
                )
            # Temporary ban - block until purge_after
            purge_after = tombstone["purge_after"]
            raise AccountDeletedException(
                f"This account was recently deleted. "
                f"You can create a new account after {purge_after.strftime('%B %d, %Y')}."
            )
    
    # No existing user and no active tombstone - create new
    # NO EMAIL STORED - anonymous by design
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO users (oauth_provider, oauth_id, total_messages)
            VALUES ($1, $2, 0)
            RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                      subscription_status, subscription_id, subscription_ends_at,
                      message_quota_used, quota_period_start,
                      total_messages, recovery_email_hash, recovery_email_set_at,
                      created_at, updated_at
            """,
            provider, oauth_id
        )
        return dict(row)


async def update_user_stripe_customer(
    provider: str, 
    oauth_id: str, 
    stripe_customer_id: str
) -> Optional[dict]:
    """Update user's Stripe customer ID."""
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET stripe_customer_id = $3, updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                      subscription_status, subscription_id, subscription_ends_at,
                      created_at, updated_at
            """,
            provider, oauth_id, stripe_customer_id
        )
        return dict(row) if row else None


async def update_subscription_status(
    stripe_customer_id: str,
    status: str,
    subscription_id: Optional[str] = None,
    ends_at: Optional[datetime] = None,
    tier: Optional[str] = None  # V3.0.0: 'pro' | 'plus' | None
) -> Optional[dict]:
    """Update user's subscription status by Stripe customer ID."""
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET subscription_status = $2,
                subscription_id = $3,
                subscription_ends_at = $4,
                subscription_tier = $5,
                updated_at = NOW()
            WHERE stripe_customer_id = $1
            RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                      subscription_status, subscription_id, subscription_ends_at,
                      subscription_tier,
                      created_at, updated_at
            """,
            stripe_customer_id, status, subscription_id, ends_at, tier
        )
        return dict(row) if row else None


async def get_subscription_status(provider: str, oauth_id: str, email: Optional[str] = None) -> dict:
    """Get user's subscription status by OAuth identity.
    
    Returns a dict with:
    - status: 'none' | 'trialing' | 'active' | 'canceled' | 'past_due'
    - is_subscribed: bool (true if trialing or active)
    - tier: 'pro' | 'plus' | null (V3.0.0)
    - ends_at: Optional datetime
    
    Users are identified by {provider}:{oauth_id}. Email parameter is ignored.
    """
    user = await get_user_for_billing(provider, oauth_id, email)
    
    if not user:
        return {
            "status": "none",
            "is_subscribed": False,
            "tier": None,
            "ends_at": None,
        }
    
    status = user.get("subscription_status", "none")
    is_subscribed = status in ("trialing", "active")
    tier = user.get("subscription_tier")  # 'pro', 'plus', or None
    
    # Check if subscription has ended
    ends_at = user.get("subscription_ends_at")
    if ends_at and datetime.now() > ends_at:
        is_subscribed = False
        tier = None  # No tier if subscription ended
    
    return {
        "status": status,
        "is_subscribed": is_subscribed,
        "tier": tier if is_subscribed else None,  # Only return tier if subscribed
        "ends_at": ends_at.isoformat() if ends_at else None,
    }


# -----------------------------
# Quota Management
# -----------------------------

# Quota limits
FREE_TIER_QUOTA = 100  # messages per month for free users
PAID_TIER_QUOTA = 5000  # messages per month for paid users
QUOTA_PERIOD_DAYS = 30  # rolling period for free users


async def get_user_quota(provider: str, oauth_id: str, email: Optional[str] = None) -> dict:
    """Get user's message quota status.
    
    Returns:
    - used: messages used this period
    - limit: total allowed for this period
    - remaining: messages remaining
    - period_ends_at: when current period ends
    - is_paid: whether user has paid subscription
    """
    user = await get_user_for_billing(provider, oauth_id, email)
    
    if not user:
        return {
            "used": 0,
            "limit": FREE_TIER_QUOTA,
            "remaining": FREE_TIER_QUOTA,
            "period_ends_at": None,
            "is_paid": False,
        }
    
    # Determine if paid user
    status = user.get("subscription_status", "none")
    is_paid = status in ("trialing", "active")
    
    # Check if subscription has ended
    sub_ends_at = user.get("subscription_ends_at")
    if sub_ends_at and datetime.now() > sub_ends_at:
        is_paid = False
    
    # Determine quota limit
    limit = PAID_TIER_QUOTA if is_paid else FREE_TIER_QUOTA
    
    # Get quota period info
    quota_period_start = user.get("quota_period_start") or datetime.now()
    message_quota_used = user.get("message_quota_used") or 0
    
    # Check if period needs reset
    # For paid users: reset based on subscription_ends_at (next billing cycle)
    # For free users: 30-day rolling period from quota_period_start
    period_ends_at = None
    should_reset = False
    
    if is_paid and sub_ends_at:
        # Paid users: period aligns with subscription billing cycle
        period_ends_at = sub_ends_at
        # Check if we're past the subscription end (renewed)
        if datetime.now() > sub_ends_at:
            should_reset = True
    else:
        # Free users: 30-day rolling period
        period_ends_at = quota_period_start + timedelta(days=QUOTA_PERIOD_DAYS)
        if datetime.now() > period_ends_at:
            should_reset = True
    
    # If period expired, reset quota (will be committed on next increment)
    if should_reset:
        message_quota_used = 0
    
    remaining = max(0, limit - message_quota_used)
    
    return {
        "used": message_quota_used,
        "limit": limit,
        "remaining": remaining,
        "period_ends_at": period_ends_at.isoformat() if period_ends_at else None,
        "is_paid": is_paid,
    }


async def increment_quota(provider: str, oauth_id: str, count: int = 1) -> Optional[dict]:
    """Increment user's message quota usage.
    
    Also handles period reset if needed.
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID
        count: Number of messages to add (default 1)
    
    Returns:
        Updated quota info, or None if user not found
    """
    if not _pool:
        return None
    
    user = await get_user_by_oauth(provider, oauth_id)
    if not user:
        return None
    
    # Determine if paid user
    status = user.get("subscription_status", "none")
    is_paid = status in ("trialing", "active")
    sub_ends_at = user.get("subscription_ends_at")
    if sub_ends_at and datetime.now() > sub_ends_at:
        is_paid = False
    
    # Check if period needs reset
    quota_period_start = user.get("quota_period_start") or datetime.now()
    
    should_reset = False
    new_period_start = quota_period_start
    
    if is_paid and sub_ends_at:
        # Paid: check if past subscription end (billing renewed)
        if datetime.now() > sub_ends_at:
            should_reset = True
            new_period_start = datetime.now()
    else:
        # Free: 30-day rolling period
        period_ends_at = quota_period_start + timedelta(days=QUOTA_PERIOD_DAYS)
        if datetime.now() > period_ends_at:
            should_reset = True
            new_period_start = datetime.now()
    
    async with _pool.acquire() as conn:
        if should_reset:
            # Reset quota and start new period
            row = await conn.fetchrow(
                """
                UPDATE users
                SET message_quota_used = $3,
                    quota_period_start = $4,
                    updated_at = NOW()
                WHERE oauth_provider = $1 AND oauth_id = $2
                RETURNING message_quota_used, quota_period_start
                """,
                provider, oauth_id, count, new_period_start
            )
        else:
            # Increment existing quota
            row = await conn.fetchrow(
                """
                UPDATE users
                SET message_quota_used = COALESCE(message_quota_used, 0) + $3,
                    total_messages = COALESCE(total_messages, 0) + $3,
                    updated_at = NOW()
                WHERE oauth_provider = $1 AND oauth_id = $2
                RETURNING message_quota_used, quota_period_start, total_messages
                """,
                provider, oauth_id, count
            )
    
    if not row:
        return None
    
    limit = PAID_TIER_QUOTA if is_paid else FREE_TIER_QUOTA
    used = row['message_quota_used']
    
    return {
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
        "is_paid": is_paid,
        "total_messages": row.get('total_messages', 0),
    }


async def reset_user_quota(stripe_customer_id: str) -> Optional[dict]:
    """Reset user's quota when subscription renews.
    
    Called from Stripe webhook when subscription is renewed.
    NOTE: Does NOT reset total_messages (lifetime count).
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET message_quota_used = 0,
                quota_period_start = NOW(),
                updated_at = NOW()
            WHERE stripe_customer_id = $1
            RETURNING id, message_quota_used, quota_period_start, total_messages
            """,
            stripe_customer_id
        )
        return dict(row) if row else None


# -----------------------------
# Recovery Email & Anonymous Auth
# -----------------------------

async def set_recovery_email(provider: str, oauth_id: str, email: str) -> dict:
    """Set or update the user's recovery email (stored as hash).
    
    PRIVACY: Only the hash is stored, not the actual email.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")
    
    email_hash = hash_recovery_email(email)
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET recovery_email_hash = $3,
                recovery_email_set_at = NOW(),
                updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING id, oauth_provider, oauth_id, recovery_email_hash, 
                      recovery_email_set_at, total_messages
            """,
            provider, oauth_id, email_hash
        )
        if not row:
            raise ValueError("User not found")
        return dict(row)


async def remove_recovery_email(provider: str, oauth_id: str) -> dict:
    """Remove the user's recovery email."""
    if not _pool:
        raise RuntimeError("Database not initialized")
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET recovery_email_hash = NULL,
                recovery_email_set_at = NULL,
                updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING id, oauth_provider, oauth_id, total_messages
            """,
            provider, oauth_id
        )
        if not row:
            raise ValueError("User not found")
        return dict(row)


async def get_user_privacy_info(provider: str, oauth_id: str) -> Optional[dict]:
    """Get user's privacy-related info for settings display.
    
    Returns:
    - has_recovery_email: bool
    - recovery_email_set_at: datetime or None
    - total_messages: int
    - should_prompt_recovery: bool (true if >= 500 messages and no recovery email)
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT total_messages, recovery_email_hash, recovery_email_set_at
            FROM users
            WHERE oauth_provider = $1 AND oauth_id = $2
            """,
            provider, oauth_id
        )
        
        if not row:
            return None
        
        total = row['total_messages'] or 0
        has_recovery = row['recovery_email_hash'] is not None
        
        return {
            "has_recovery_email": has_recovery,
            "recovery_email_set_at": row['recovery_email_set_at'].isoformat() if row['recovery_email_set_at'] else None,
            "total_messages": total,
            "should_prompt_recovery": total >= 500 and not has_recovery,
        }


# -----------------------------
# Strike Management (Admin)
# -----------------------------

async def get_account_status(provider: str, oauth_id: str) -> Optional[str]:
    """Get the account status for a user.
    
    Returns: 'active', 'suspended', or None if user not found.
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT account_status FROM users
            WHERE oauth_provider = $1 AND oauth_id = $2
            """,
            provider, oauth_id
        )
        return row['account_status'] if row else None


async def create_strike(
    oauth_provider: str,
    oauth_id: str,
    reason: str,
    details: Optional[str] = None
) -> Optional[dict]:
    """Create a strike against a user and suspend their account.
    
    Args:
        oauth_provider: OAuth provider (google, github, etc.)
        oauth_id: Hashed OAuth ID
        reason: Strike reason ('provider_flag', 'rate_abuse', 'manual')
        details: Optional additional details
        
    Returns:
        Strike record dict, or None if user not found
    """
    if not _pool:
        raise RuntimeError("Database not initialized")
    
    async with _pool.acquire() as conn:
        async with conn.transaction():
            # Get user ID
            user_row = await conn.fetchrow(
                """
                SELECT id FROM users
                WHERE oauth_provider = $1 AND oauth_id = $2
                """,
                oauth_provider, oauth_id
            )
            if not user_row:
                return None
            
            user_id = user_row['id']
            
            # Create strike record
            strike_row = await conn.fetchrow(
                """
                INSERT INTO strikes (user_id, reason, details)
                VALUES ($1, $2, $3)
                RETURNING id, user_id, reason, details, created_at
                """,
                user_id, reason, details
            )
            
            # Suspend the account
            await conn.execute(
                """
                UPDATE users
                SET account_status = 'suspended',
                    updated_at = NOW()
                WHERE id = $1
                """,
                user_id
            )
            
            return dict(strike_row)


async def get_pending_strikes() -> list[dict]:
    """Get all unresolved strikes with user info for admin review.
    
    Returns list of strikes with user context (oauth_provider, masked oauth_id).
    """
    if not _pool:
        return []
    
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT 
                s.id as strike_id,
                s.user_id,
                s.reason,
                s.details,
                s.created_at,
                u.oauth_provider,
                LEFT(u.oauth_id, 8) || '...' as oauth_id_prefix,
                u.subscription_status,
                u.stripe_customer_id,
                u.total_messages
            FROM strikes s
            JOIN users u ON s.user_id = u.id
            WHERE s.resolved_at IS NULL
            ORDER BY s.created_at DESC
            """
        )
        return [dict(row) for row in rows]


async def resolve_strike(
    strike_id: int,
    resolution: str,
    admin_notes: Optional[str] = None,
    refund_amount_cents: Optional[int] = None
) -> Optional[dict]:
    """Resolve a strike with admin decision.
    
    Args:
        strike_id: Strike ID to resolve
        resolution: 'false_alarm' (restore), 'warning' (restore with note),
                   'suspend_30d', 'suspend_90d', 'delete'
        admin_notes: Optional notes about the decision
        refund_amount_cents: If provided, refund this amount (for delete resolution)
        
    Returns:
        Updated strike record with user info, or None if not found
    """
    if not _pool:
        raise RuntimeError("Database not initialized")
    
    async with _pool.acquire() as conn:
        async with conn.transaction():
            # Get strike and user info
            strike_row = await conn.fetchrow(
                """
                SELECT s.*, u.oauth_provider, u.oauth_id, u.stripe_customer_id, u.subscription_id
                FROM strikes s
                JOIN users u ON s.user_id = u.id
                WHERE s.id = $1 AND s.resolved_at IS NULL
                """,
                strike_id
            )
            if not strike_row:
                return None
            
            user_id = strike_row['user_id']
            oauth_provider = strike_row['oauth_provider']
            oauth_id = strike_row['oauth_id']
            
            # Update strike record
            await conn.execute(
                """
                UPDATE strikes
                SET resolved_at = NOW(),
                    resolution = $2,
                    admin_notes = $3
                WHERE id = $1
                """,
                strike_id, resolution, admin_notes
            )
            
            # Apply resolution to user account
            if resolution in ('false_alarm', 'warning'):
                # Restore account to active
                await conn.execute(
                    """
                    UPDATE users
                    SET account_status = 'active',
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    user_id
                )
            elif resolution in ('delete', 'permanent_ban'):
                # Count total strikes for this user (including current one)
                strike_count_row = await conn.fetchrow(
                    "SELECT COUNT(*) as count FROM strikes WHERE user_id = $1",
                    user_id
                )
                strike_count = strike_count_row['count'] if strike_count_row else 1
                
                # Delete account and create tombstone with strike history
                is_permanent = (resolution == 'permanent_ban')
                await conn.execute(
                    """
                    INSERT INTO deleted_accounts (
                        oauth_provider, oauth_id, deleted_at, 
                        strike_count, final_reason, permanent_ban,
                        purge_after
                    )
                    VALUES ($1, $2, NOW(), $3, $4, $5, 
                            CASE WHEN $5 THEN NULL ELSE NOW() + INTERVAL '90 days' END)
                    """,
                    oauth_provider, oauth_id, strike_count, 
                    admin_notes or strike_row['details'], is_permanent
                )
                await conn.execute(
                    "DELETE FROM users WHERE id = $1",
                    user_id
                )
            # For suspend_30d/suspend_90d, account stays suspended
            # Admin would need to manually restore after time period
            
            return {
                "strike_id": strike_id,
                "resolution": resolution,
                "user_id": user_id,
                "oauth_provider": oauth_provider,
                "oauth_id_prefix": oauth_id[:8] + "...",
            }


async def get_user_id_by_oauth(provider: str, oauth_id: str) -> Optional[int]:
    """Get database user ID from OAuth credentials.
    
    Used by admin endpoints to look up users.
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id FROM users WHERE oauth_provider = $1 AND oauth_id = $2",
            provider, oauth_id
        )
        return row['id'] if row else None


async def get_tombstone_history(provider: str, oauth_id: str) -> list[dict]:
    """Get all tombstone records for an OAuth identity.
    
    Returns complete history of deletions for repeat offender tracking.
    """
    if not _pool:
        return []
    
    async with _pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, oauth_provider, oauth_id, deleted_at, purge_after,
                   strike_count, final_reason, permanent_ban
            FROM deleted_accounts
            WHERE oauth_provider = $1 AND oauth_id = $2
            ORDER BY deleted_at DESC
            """,
            provider, oauth_id
        )
        return [dict(row) for row in rows]


async def upgrade_to_permanent_ban(provider: str, oauth_id: str, admin_notes: str) -> Optional[dict]:
    """Upgrade most recent tombstone to a permanent ban.
    
    Used when you want to permanently ban a deleted account
    (e.g., repeat offender whose 90-day cooldown is about to expire).
    
    Returns the updated tombstone record, or None if no tombstone found.
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        # Find and update the most recent tombstone
        row = await conn.fetchrow(
            """
            UPDATE deleted_accounts
            SET permanent_ban = TRUE,
                purge_after = NULL,
                final_reason = COALESCE(final_reason || ' | ', '') || $3
            WHERE id = (
                SELECT id FROM deleted_accounts
                WHERE oauth_provider = $1 AND oauth_id = $2
                ORDER BY deleted_at DESC
                LIMIT 1
            )
            RETURNING id, oauth_provider, oauth_id, deleted_at, purge_after,
                      strike_count, final_reason, permanent_ban
            """,
            provider, oauth_id, admin_notes
        )
        return dict(row) if row else None


# =============================================================================
# Magic Link Functions (Email Authentication)
# =============================================================================

async def create_magic_link(
    email_hash: str,
    token_hash: str,
    expires_at: datetime,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    user_id: Optional[int] = None,
) -> int:
    """Create a new magic link token.

    Args:
        email_hash: Hashed email address
        token_hash: Hashed token
        expires_at: Expiration timestamp (typically NOW() + 1 hour)
        ip_address: Request IP for rate limiting
        user_agent: User agent for abuse detection
        user_id: User ID if already registered (NULL for new signups)

    Returns:
        Magic link ID
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO magic_links (
                email_hash, token_hash, expires_at,
                ip_address, user_agent, user_id
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            """,
            email_hash, token_hash, expires_at,
            ip_address, user_agent, user_id
        )
        return row["id"]


async def get_magic_link_by_token(token_hash: str) -> Optional[dict]:
    """Get magic link by token hash.

    Returns None if token not found, expired, or already used.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, email_hash, user_id, created_at, expires_at, used_at
            FROM magic_links
            WHERE token_hash = $1
            AND used_at IS NULL
            AND expires_at > NOW()
            """,
            token_hash
        )

        if row:
            return dict(row)
        return None


async def mark_magic_link_used(token_hash: str) -> bool:
    """Mark magic link as used (one-time use).

    Returns True if successfully marked, False if token was invalid/expired/already used.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE magic_links
            SET used_at = NOW()
            WHERE token_hash = $1
            AND used_at IS NULL
            AND expires_at > NOW()
            """,
            token_hash
        )

        # Check if any rows were updated
        return result.split()[-1] == "1"


async def count_recent_magic_links(email_hash: str, minutes: int = 60) -> int:
    """Count magic links sent to this email in the last N minutes.

    Used for rate limiting to prevent abuse.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT COUNT(*) as count
            FROM magic_links
            WHERE email_hash = $1
            AND created_at > NOW() - make_interval(mins => $2)
            """,
            email_hash, minutes
        )
        return row["count"] if row else 0


async def cleanup_expired_magic_links() -> int:
    """Delete expired magic links (housekeeping).

    Should be called periodically (e.g., daily cron job).
    Returns number of deleted rows.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM magic_links
            WHERE expires_at < NOW() - INTERVAL '24 hours'
            """
        )
        count = int(result.split()[-1])
        if count > 0:
            logger.info("Cleaned up %d expired magic links", count)
        return count


async def get_user_by_email_hash(email_hash: str) -> Optional[dict]:
    """Get user by hashed email (for email provider).

    Returns None if user doesn't exist.
    """
    if not _pool:
        raise RuntimeError("Database not initialized")

    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, oauth_provider, oauth_id, stripe_customer_id,
                   subscription_status, subscription_id, subscription_ends_at,
                   message_quota_used, quota_period_start,
                   total_messages, recovery_email_hash, recovery_email_set_at,
                   created_at, updated_at, account_status
            FROM users
            WHERE oauth_provider = 'email'
            AND oauth_id = $1
            """,
            email_hash
        )

        if row:
            return dict(row)
        return None
