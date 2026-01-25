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
        # NOTE: Using ADD COLUMN IF NOT EXISTS for reliability across environments
        await conn.execute("""
            ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(10) DEFAULT NULL;
        """)
        
        # Grandfather existing paid users as 'plus' (only if not already set)
        await conn.execute("""
            UPDATE users SET subscription_tier = 'plus'
            WHERE subscription_status IN ('active', 'trialing')
            AND subscription_tier IS NULL;
        """)

        # V3.0.1: ANONYMOUS USER TRACKING: Server-side quota enforcement
        # Add columns to track anonymous users before they sign in
        # PRIVACY: anonymous_fingerprint is a SHA-256 hash generated client-side
        # We cannot reverse it to identify the user
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'is_anonymous'
                ) THEN
                    ALTER TABLE users ADD COLUMN is_anonymous BOOLEAN DEFAULT FALSE;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'anonymous_fingerprint'
                ) THEN
                    ALTER TABLE users ADD COLUMN anonymous_fingerprint VARCHAR(64);
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'users' AND column_name = 'promoted_at'
                ) THEN
                    ALTER TABLE users ADD COLUMN promoted_at TIMESTAMP;
                END IF;
            END $$;
        """)

        # V3.0.1: Update oauth_provider CHECK constraint to include 'anonymous'
        # This migration handles existing databases that have the old constraint
        await conn.execute("""
            DO $$
            DECLARE
                constraint_def text;
            BEGIN
                -- Check if constraint exists and doesn't include 'anonymous'
                SELECT pg_get_constraintdef(oid) INTO constraint_def
                FROM pg_constraint
                WHERE conname = 'users_oauth_provider_check';
                
                IF constraint_def IS NOT NULL AND constraint_def NOT LIKE '%anonymous%' THEN
                    -- Drop old constraint and add new one with 'anonymous'
                    ALTER TABLE users DROP CONSTRAINT users_oauth_provider_check;
                    ALTER TABLE users ADD CONSTRAINT users_oauth_provider_check
                        CHECK (oauth_provider IN ('github', 'google', 'apple', 'microsoft', 'email', 'dev', 'anonymous'));
                ELSIF constraint_def IS NULL THEN
                    -- No constraint exists, add it
                    ALTER TABLE users ADD CONSTRAINT users_oauth_provider_check
                        CHECK (oauth_provider IN ('github', 'google', 'apple', 'microsoft', 'email', 'dev', 'anonymous'));
                END IF;
            END $$;
        """)

        # Index for fast anonymous user lookups
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_anonymous_fingerprint
                ON users(anonymous_fingerprint)
                WHERE anonymous_fingerprint IS NOT NULL;
        """)

        # V3.0.1: Auto-clear fingerprints after 72 hours for privacy
        # This prevents indefinite fingerprint storage while still preventing immediate abuse
        await conn.execute("""
            CREATE OR REPLACE FUNCTION clear_old_fingerprints() RETURNS void AS $$
            BEGIN
                UPDATE users
                SET anonymous_fingerprint = NULL
                WHERE anonymous_fingerprint IS NOT NULL
                  AND is_anonymous = FALSE
                  AND promoted_at IS NOT NULL
                  AND promoted_at < NOW() - INTERVAL '72 hours';
            END;
            $$ LANGUAGE plpgsql;
        """)

        # Create index for efficient fingerprint cleanup
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_fingerprint_cleanup
                ON users(promoted_at)
                WHERE anonymous_fingerprint IS NOT NULL AND is_anonymous = FALSE;
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
                study_mode_used INT DEFAULT 0,
                return_24h INT DEFAULT 0,
                -- Mode-specific message counts (added v3.2.1)
                chat_messages INT DEFAULT 0,
                ask_messages INT DEFAULT 0,
                study_messages INT DEFAULT 0,
                return_48h INT DEFAULT 0,
                checkout_started INT DEFAULT 0,
                payment_completed INT DEFAULT 0,
                -- Token usage tracking (added v3.x)
                openai_input_tokens BIGINT DEFAULT 0,
                openai_output_tokens BIGINT DEFAULT 0,
                gemini_input_tokens BIGINT DEFAULT 0,
                gemini_output_tokens BIGINT DEFAULT 0,
                anthropic_input_tokens BIGINT DEFAULT 0,
                anthropic_output_tokens BIGINT DEFAULT 0,
                -- Mode-specific token tracking (added v3.2.1)
                openai_chat_input_tokens BIGINT DEFAULT 0,
                openai_chat_output_tokens BIGINT DEFAULT 0,
                openai_ask_input_tokens BIGINT DEFAULT 0,
                openai_ask_output_tokens BIGINT DEFAULT 0,
                openai_study_input_tokens BIGINT DEFAULT 0,
                openai_study_output_tokens BIGINT DEFAULT 0,
                gemini_chat_input_tokens BIGINT DEFAULT 0,
                gemini_chat_output_tokens BIGINT DEFAULT 0,
                gemini_ask_input_tokens BIGINT DEFAULT 0,
                gemini_ask_output_tokens BIGINT DEFAULT 0,
                gemini_study_input_tokens BIGINT DEFAULT 0,
                gemini_study_output_tokens BIGINT DEFAULT 0,
                anthropic_chat_input_tokens BIGINT DEFAULT 0,
                anthropic_chat_output_tokens BIGINT DEFAULT 0,
                anthropic_ask_input_tokens BIGINT DEFAULT 0,
                anthropic_ask_output_tokens BIGINT DEFAULT 0,
                anthropic_study_input_tokens BIGINT DEFAULT 0,
                anthropic_study_output_tokens BIGINT DEFAULT 0
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
        
        # ANONYMOUS USAGE TABLE: Rate limiting for unauthenticated users
        # PRIVACY: Only stores hashed identity (IP + User-Agent hash)
        # Automatically cleaned up when user authenticates
        # Used for abuse prevention on expensive endpoints (persona generation)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS anonymous_usage (
                id SERIAL PRIMARY KEY,
                identity_hash VARCHAR(64) NOT NULL,
                action_type VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            CREATE INDEX IF NOT EXISTS idx_anonymous_usage_identity 
                ON anonymous_usage(identity_hash);
            CREATE INDEX IF NOT EXISTS idx_anonymous_usage_action 
                ON anonymous_usage(identity_hash, action_type);
            CREATE INDEX IF NOT EXISTS idx_anonymous_usage_created 
                ON anonymous_usage(created_at);
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
                   account_status, brand, is_anonymous,
                   credit_balance, credit_cap, last_credit_refresh,
                   credits_earned_total, credits_spent_total,
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
                   account_status, brand, is_anonymous,
                   credit_balance, credit_cap, last_credit_refresh,
                   credits_earned_total, credits_spent_total,
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


async def create_user(provider: str, oauth_id: str, email: Optional[str] = None, brand: str = "botchat") -> dict:
    """Create a new user or return existing user by OAuth identity.
    
    PRIVACY: oauth_id is a hash, not the raw OAuth ID.
    Email parameter is ignored (kept for API compatibility during migration).
    Brand is stored for analytics separation between botchat and hushhush.
    
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
            INSERT INTO users (oauth_provider, oauth_id, total_messages, brand)
            VALUES ($1, $2, 0, $3)
            RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                      subscription_status, subscription_id, subscription_ends_at,
                      message_quota_used, quota_period_start,
                      total_messages, recovery_email_hash, recovery_email_set_at,
                      created_at, updated_at, brand
            """,
            provider, oauth_id, brand
        )
        return dict(row)


async def get_or_create_anonymous_user(fingerprint: str) -> dict:
    """Get or create an anonymous user by browser fingerprint hash.

    V3.0.1: Server-side quota enforcement for anonymous users.
    V3.2.2: Initialize with credit_balance system (10 credits cap).

    PRIVACY: fingerprint is a client-generated SHA-256 hash.
    We cannot reverse it to identify the user.

    ABUSE PREVENTION: Checks for promoted users (signed in then signed out)
    to prevent gaming the system by signing out and using anonymous mode again.
    Fingerprints are auto-cleared after 72 hours for privacy.

    Args:
        fingerprint: SHA-256 hash of browser signals (64-char hex string)

    Returns:
        User dict (may be is_anonymous=TRUE or is_anonymous=FALSE if promoted)
    """
    if not _pool:
        raise Exception("Database pool not initialized")

    async with _pool.acquire() as conn:
        # Periodically clean up old fingerprints (72+ hours after promotion)
        # This runs async and doesn't block the request
        try:
            await conn.execute("SELECT clear_old_fingerprints()")
        except Exception as e:
            logger.warning(f"Failed to clear old fingerprints: {e}")

        # Try to find existing user by fingerprint (anonymous OR promoted)
        # This prevents gaming: anonymous → sign in → sign out → use anonymous again
        row = await conn.fetchrow(
            """
            SELECT id, oauth_provider, oauth_id, message_quota_used,
                   quota_period_start, is_anonymous, anonymous_fingerprint,
                   subscription_status, subscription_tier, total_messages,
                   credit_balance, credit_cap, last_credit_refresh,
                   created_at, updated_at, account_status
            FROM users
            WHERE anonymous_fingerprint = $1
            """,
            fingerprint
        )

        if row:
            # Found existing user (either still anonymous or promoted to authenticated)
            return dict(row)

        # Create new anonymous user with credit_balance initialized
        row = await conn.fetchrow(
            """
            INSERT INTO users (
                oauth_provider,
                oauth_id,
                is_anonymous,
                anonymous_fingerprint,
                message_quota_used,
                total_messages,
                credit_balance,
                credit_cap,
                last_credit_refresh,
                credits_earned_total
            )
            VALUES ('anonymous', $1, TRUE, $1, 0, 0, $2, $2, NOW(), $2)
            RETURNING id, oauth_provider, oauth_id, message_quota_used,
                      quota_period_start, is_anonymous, anonymous_fingerprint,
                      subscription_status, subscription_tier, total_messages,
                      credit_balance, credit_cap, last_credit_refresh,
                      created_at, updated_at, account_status
            """,
            fingerprint,
            ANONYMOUS_CREDIT_CAP  # 10 credits
        )

        logger.info(f"Created anonymous user: fingerprint={fingerprint[:16]}... (db_id={row['id']}, credits={ANONYMOUS_CREDIT_CAP})")
        return dict(row)


async def promote_anonymous_to_authenticated(
    fingerprint: str,
    provider: str,
    oauth_id: str,
    brand: str = "botchat"
) -> dict:
    """Promote anonymous user to authenticated user on sign-in.

    V3.0.1: Merge anonymous usage into authenticated account.

    - Updates existing anonymous user record with OAuth info
    - Preserves message quota usage (carries over to authenticated account)
    - KEEPS anonymous_fingerprint (prevents gaming: sign out → use anonymous mode again)
    - OR creates new authenticated user if no anonymous record exists

    Args:
        fingerprint: Anonymous user's browser fingerprint
        provider: OAuth provider (github, google, etc.)
        oauth_id: Hashed OAuth ID
        brand: Brand context (botchat, hushhush)

    Returns:
        Updated or newly created user dict
    """
    if not _pool:
        raise Exception("Database pool not initialized")

    async with _pool.acquire() as conn:
        # Find anonymous user by fingerprint
        anon_user = await conn.fetchrow(
            """
            SELECT * FROM users
            WHERE anonymous_fingerprint = $1 AND is_anonymous = TRUE
            """,
            fingerprint
        )

        if anon_user:
            # Update existing anonymous user to authenticated
            # KEEP the fingerprint - prevents gaming by signing out and using anonymous mode
            # Also update brand for promoted users
            row = await conn.fetchrow(
                """
                UPDATE users
                SET oauth_provider = $1,
                    oauth_id = $2,
                    is_anonymous = FALSE,
                    promoted_at = NOW(),
                    updated_at = NOW(),
                    brand = $4
                WHERE id = $3
                RETURNING id, oauth_provider, oauth_id, stripe_customer_id,
                          subscription_status, subscription_id, subscription_ends_at,
                          message_quota_used, quota_period_start,
                          total_messages, recovery_email_hash, recovery_email_set_at,
                          created_at, updated_at, account_status, subscription_tier,
                          is_anonymous, promoted_at, brand
                """,
                provider, oauth_id, anon_user['id'], brand
            )
            logger.info(
                f"Promoted anonymous user {anon_user['id']} to {provider}:{oauth_id[:16]}... "
                f"(carried over {anon_user['message_quota_used']} messages, kept fingerprint, brand={brand})"
            )
            return dict(row)
        else:
            # No anonymous record - create new authenticated user normally
            logger.info(f"No anonymous user found for fingerprint, creating new: {provider}:{oauth_id[:16]}...")
            return await create_user(provider, oauth_id, brand=brand)


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
# Credit Balance System (v3.2.2)
# -----------------------------
# 
# Credits are now a decreasing balance, not used/limit.
# 
# Credit Rules:
# - Anonymous users: 10 credits, +10/week (rolling), cap at 10
# - Free signed-in: 25 credits, +10/week (rolling), cap at 25
# - Pro subscribers: +250/month on renewal, cap at 2,000
# - Plus subscribers: +1,000/month on renewal, cap at 2,000
# - Credits never expire
#
# All references to "messages" are now "credits"

# Credit caps per user type
ANONYMOUS_CREDIT_CAP = 10
FREE_SIGNED_IN_CREDIT_CAP = 25
PAID_CREDIT_CAP = 2000

# Credit grants
ANONYMOUS_INITIAL_CREDITS = 10
FREE_SIGNED_IN_INITIAL_CREDITS = 25
WEEKLY_CREDIT_REFRESH = 10  # +10/week for anonymous and free signed-in
PRO_MONTHLY_CREDITS = 250   # +250/month for Pro
PLUS_MONTHLY_CREDITS = 1000 # +1000/month for Plus

# Refresh timing
WEEKLY_REFRESH_DAYS = 7

# Legacy constants (kept for backwards compatibility during migration)
FREE_SIGNED_OUT_QUOTA = ANONYMOUS_INITIAL_CREDITS
FREE_TIER_QUOTA = FREE_SIGNED_IN_INITIAL_CREDITS


def get_credit_cap_for_user(tier: Optional[str], is_paid: bool, is_anonymous: bool) -> int:
    """Get the credit cap for a user based on their status.
    
    Args:
        tier: Subscription tier ('pro', 'plus', or None)
        is_paid: Whether user has active subscription
        is_anonymous: Whether user is anonymous
    
    Returns:
        Maximum credit balance allowed
    """
    if is_anonymous:
        return ANONYMOUS_CREDIT_CAP
    if is_paid:
        return PAID_CREDIT_CAP
    return FREE_SIGNED_IN_CREDIT_CAP


def get_initial_credits_for_user(tier: Optional[str], is_paid: bool, is_anonymous: bool) -> int:
    """Get initial credits for a new user.
    
    Args:
        tier: Subscription tier ('pro', 'plus', or None)
        is_paid: Whether user has active subscription
        is_anonymous: Whether user is anonymous
    
    Returns:
        Initial credit balance
    """
    if is_anonymous:
        return ANONYMOUS_INITIAL_CREDITS
    if is_paid:
        if tier == 'plus':
            return min(PLUS_MONTHLY_CREDITS, PAID_CREDIT_CAP)
        return min(PRO_MONTHLY_CREDITS, PAID_CREDIT_CAP)
    return FREE_SIGNED_IN_INITIAL_CREDITS


async def apply_weekly_credit_refresh(conn, user: dict) -> int:
    """Apply weekly credit refresh if eligible.
    
    Anonymous and free signed-in users get +10 credits per week (rolling).
    
    Args:
        conn: Database connection
        user: User record dict
    
    Returns:
        New credit balance after refresh (or current if no refresh needed)
    """
    is_anonymous = user.get('is_anonymous', False)
    is_paid = user.get('subscription_status') in ('active', 'trialing')
    
    # Paid users don't get weekly refresh
    if is_paid:
        return user.get('credit_balance', 0)
    
    # Check if refresh is due
    last_refresh = user.get('last_credit_refresh')
    if last_refresh is None:
        # First time - set baseline but don't add credits (they got initial credits)
        await conn.execute(
            """
            UPDATE users SET last_credit_refresh = NOW()
            WHERE id = $1
            """,
            user['id']
        )
        return user.get('credit_balance', 0)
    
    # Calculate time since last refresh
    now = datetime.now()
    if isinstance(last_refresh, str):
        last_refresh = datetime.fromisoformat(last_refresh.replace('Z', '+00:00'))
    
    days_since_refresh = (now - last_refresh.replace(tzinfo=None)).days
    
    if days_since_refresh >= WEEKLY_REFRESH_DAYS:
        # Apply refresh
        credit_cap = ANONYMOUS_CREDIT_CAP if is_anonymous else FREE_SIGNED_IN_CREDIT_CAP
        current_balance = user.get('credit_balance', 0)
        new_balance = min(current_balance + WEEKLY_CREDIT_REFRESH, credit_cap)
        
        # Update database
        await conn.execute(
            """
            UPDATE users 
            SET credit_balance = $2,
                last_credit_refresh = NOW(),
                credits_earned_total = COALESCE(credits_earned_total, 0) + $3
            WHERE id = $1
            """,
            user['id'],
            new_balance,
            new_balance - current_balance  # Actual credits added
        )
        
        logger.info(f"Weekly credit refresh: user {user['id']} {current_balance} → {new_balance}")
        return new_balance
    
    return user.get('credit_balance', 0)


async def get_user_quota(provider: str, oauth_id: str, email: Optional[str] = None) -> dict:
    """Get user's credit balance status.
    
    V3.2.2: Simplified credit balance system.
    - Returns credit_balance directly (no used/limit calculation)
    - Applies weekly refresh for free users if 7+ days passed
    - Paid users get monthly credits via Stripe webhook
    
    Returns:
    - credit_balance: current available credits
    - credit_cap: maximum credits user can accumulate
    - is_paid: whether user has paid subscription
    - tier: subscription tier ('pro', 'plus', or None)
    
    Legacy fields (for backward compatibility during transition):
    - used: 0 (deprecated)
    - limit: credit_cap (deprecated)
    - remaining: credit_balance (deprecated)
    """
    user = await get_user_for_billing(provider, oauth_id, email)
    
    is_anonymous = provider == 'anonymous'
    
    if not user:
        # New user - return initial credits based on type
        initial_credits = ANONYMOUS_INITIAL_CREDITS if is_anonymous else FREE_SIGNED_IN_INITIAL_CREDITS
        credit_cap = ANONYMOUS_CREDIT_CAP if is_anonymous else FREE_SIGNED_IN_CREDIT_CAP
        return {
            "credit_balance": initial_credits,
            "credit_cap": credit_cap,
            "is_paid": False,
            "tier": None,
            # Legacy fields
            "used": 0,
            "limit": credit_cap,
            "remaining": initial_credits,
            "period_ends_at": None,
        }
    
    # Determine if paid user
    status = user.get("subscription_status", "none")
    is_paid = status in ("trialing", "active")
    tier = user.get("subscription_tier")  # 'pro', 'plus', or None
    
    # Check if subscription has ended
    sub_ends_at = user.get("subscription_ends_at")
    if sub_ends_at and datetime.now() > sub_ends_at:
        is_paid = False
        tier = None
    
    # Get credit balance (may be refreshed)
    credit_balance = user.get('credit_balance')
    
    # If credit_balance is None, this user hasn't been migrated yet
    # Initialize based on their current state
    if credit_balance is None:
        credit_balance = await _initialize_credit_balance(user, is_paid, tier, is_anonymous)
    elif not is_paid:
        # Apply weekly refresh for non-paid users (anonymous + free signed-in)
        async with get_pool().acquire() as conn:
            credit_balance = await apply_weekly_credit_refresh(conn, user)
    
    # Get credit cap for this user type
    credit_cap = get_credit_cap_for_user(tier, is_paid, is_anonymous)
    
    return {
        "credit_balance": credit_balance,
        "credit_cap": credit_cap,
        "is_paid": is_paid,
        "tier": tier,
        # Legacy fields for backward compatibility
        "used": 0,
        "limit": credit_cap,
        "remaining": credit_balance,
        "period_ends_at": sub_ends_at.isoformat() if sub_ends_at else None,
    }


async def _initialize_credit_balance(user: dict, is_paid: bool, tier: Optional[str], is_anonymous: bool) -> int:
    """Initialize credit_balance for users who haven't been migrated yet.
    
    Called when credit_balance is NULL (pre-v3.2.2 users).
    Converts existing message_quota_used to credit_balance.
    """
    if not _pool:
        return 0
    
    # Calculate initial credits based on user type
    initial_credits = get_initial_credits_for_user(tier, is_paid, is_anonymous)
    credit_cap = get_credit_cap_for_user(tier, is_paid, is_anonymous)
    
    # For existing users, deduct their already-used messages from initial credits
    message_quota_used = user.get('message_quota_used', 0) or 0
    credit_balance = max(0, initial_credits - message_quota_used)
    
    # Cap at the maximum
    credit_balance = min(credit_balance, credit_cap)
    
    async with _pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE users 
            SET credit_balance = $2,
                credit_cap = $3,
                last_credit_refresh = NOW(),
                credits_earned_total = $2,
                updated_at = NOW()
            WHERE id = $1
            """,
            user['id'],
            credit_balance,
            credit_cap
        )
    
    logger.info(f"Initialized credit_balance for user {user['id']}: {credit_balance} (was {message_quota_used} used)")
    return credit_balance


async def spend_credits(provider: str, oauth_id: str, amount: int = 1) -> Optional[dict]:
    """Spend credits from user's balance.
    
    V3.2.2: Decrements credit_balance instead of incrementing quota_used.
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID
        amount: Number of credits to spend (default 1)
    
    Returns:
        Updated credit info, or None if user not found or insufficient credits
    """
    if not _pool:
        return None
    
    user = await get_user_by_oauth(provider, oauth_id)
    if not user:
        return None
    
    is_anonymous = provider == 'anonymous'
    
    # Determine if paid user
    status = user.get("subscription_status", "none")
    is_paid = status in ("trialing", "active")
    tier = user.get("subscription_tier")
    sub_ends_at = user.get("subscription_ends_at")
    if sub_ends_at and datetime.now() > sub_ends_at:
        is_paid = False
        tier = None
    
    # Get current balance (with potential weekly refresh for free users)
    current_balance = user.get('credit_balance')
    if current_balance is None:
        # User hasn't been migrated yet - initialize first
        current_balance = await _initialize_credit_balance(user, is_paid, tier, is_anonymous)
    elif not is_paid:
        # Apply weekly refresh for non-paid users before spending
        async with _pool.acquire() as conn:
            current_balance = await apply_weekly_credit_refresh(conn, user)
    
    # Check if user has enough credits
    if current_balance < amount:
        logger.warning(f"Insufficient credits: user {user['id']} has {current_balance}, needs {amount}")
        return {
            "error": "insufficient_credits",
            "credit_balance": current_balance,
            "credit_cap": get_credit_cap_for_user(tier, is_paid, is_anonymous),
            "required": amount,
        }
    
    # Deduct credits
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET credit_balance = credit_balance - $3,
                credits_spent_total = COALESCE(credits_spent_total, 0) + $3,
                total_messages = COALESCE(total_messages, 0) + $3,
                updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING credit_balance, credits_spent_total, total_messages
            """,
            provider, oauth_id, amount
        )
    
    if not row:
        return None
    
    new_balance = row['credit_balance']
    credit_cap = get_credit_cap_for_user(tier, is_paid, is_anonymous)
    
    logger.info(f"Spent {amount} credits: user {user['id']} {current_balance} → {new_balance}")
    
    return {
        "credit_balance": new_balance,
        "credit_cap": credit_cap,
        "is_paid": is_paid,
        "total_messages": row.get('total_messages', 0),
        # Legacy fields for backward compatibility
        "used": 0,
        "limit": credit_cap,
        "remaining": new_balance,
    }


# Keep increment_quota as alias for backward compatibility during transition
async def increment_quota(provider: str, oauth_id: str, count: int = 1) -> Optional[dict]:
    """DEPRECATED: Use spend_credits() instead.
    
    Kept for backward compatibility during v3.2.2 transition.
    """
    return await spend_credits(provider, oauth_id, count)


async def add_subscription_credits(stripe_customer_id: str, tier: str) -> Optional[dict]:
    """Add monthly credits when subscription renews.
    
    V3.2.2: Called from Stripe webhook on subscription renewal.
    Adds credits based on tier (Pro: 250, Plus: 1000).
    Credits are ADDITIVE, not resetting. Capped at 2000.
    
    Args:
        stripe_customer_id: Stripe customer ID
        tier: Subscription tier ('pro' or 'plus')
    
    Returns:
        Updated user info with new balance, or None if user not found
    """
    if not _pool:
        return None
    
    # Determine credits to add based on tier
    if tier == 'plus':
        credits_to_add = PLUS_MONTHLY_CREDITS  # 1000
    else:
        credits_to_add = PRO_MONTHLY_CREDITS   # 250
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET credit_balance = LEAST(COALESCE(credit_balance, 0) + $2, $3),
                credit_cap = $3,
                credits_earned_total = COALESCE(credits_earned_total, 0) + $2,
                updated_at = NOW()
            WHERE stripe_customer_id = $1
            RETURNING id, credit_balance, credit_cap, credits_earned_total, total_messages
            """,
            stripe_customer_id,
            credits_to_add,
            PAID_CREDIT_CAP  # 2000
        )
        
        if row:
            logger.info(f"Added {credits_to_add} subscription credits ({tier}): user {row['id']} → {row['credit_balance']}")
        
        return dict(row) if row else None


# Keep reset_user_quota as alias for backward compatibility
async def reset_user_quota(stripe_customer_id: str) -> Optional[dict]:
    """DEPRECATED: Use add_subscription_credits() instead.
    
    For backward compatibility, defaults to 'pro' tier (250 credits).
    """
    return await add_subscription_credits(stripe_customer_id, 'pro')


# -----------------------------
# Credit System (v3.2.0 - hushhush)
# -----------------------------

async def get_credit_balance(provider: str, oauth_id: str) -> int:
    """Get user's credit balance.
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID (hashed)
    
    Returns:
        Credit balance (0 if no credits)
    """
    if not _pool:
        return 0
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT COALESCE(credit_balance, 0) as credit_balance
            FROM users
            WHERE oauth_provider = $1 AND oauth_id = $2
            """,
            provider, oauth_id
        )
        return row['credit_balance'] if row else 0


async def add_credits(provider: str, oauth_id: str, amount: int) -> Optional[dict]:
    """Add credits to a user's balance.
    
    Called after successful Stripe credit pack purchase.
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID (hashed)
        amount: Number of credits to add
    
    Returns:
        Updated user info with new balance, or None if user not found
    """
    if not _pool:
        return None
    
    logger.info("Adding %d credits to user %s:%s...", amount, provider, oauth_id[:16])
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET credit_balance = COALESCE(credit_balance, 0) + $3,
                updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING id, credit_balance
            """,
            provider, oauth_id, amount
        )
        
        if row:
            logger.info("Credits added. New balance: %d", row['credit_balance'])
            return dict(row)
        return None


async def add_credits_by_stripe_customer(stripe_customer_id: str, amount: int) -> Optional[dict]:
    """Add credits to a user's balance by Stripe customer ID.
    
    Called from Stripe webhook after successful credit pack purchase.
    
    Args:
        stripe_customer_id: Stripe customer ID
        amount: Number of credits to add
    
    Returns:
        Updated user info with new balance, or None if user not found
    """
    if not _pool:
        return None
    
    logger.info("Adding %d credits to Stripe customer %s", amount, stripe_customer_id)
    
    async with _pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE users
            SET credit_balance = COALESCE(credit_balance, 0) + $2,
                updated_at = NOW()
            WHERE stripe_customer_id = $1
            RETURNING id, credit_balance, oauth_provider, oauth_id
            """,
            stripe_customer_id, amount
        )
        
        if row:
            logger.info("Credits added. New balance: %d for user id=%d", row['credit_balance'], row['id'])
            return dict(row)
        return None


async def deduct_credits(provider: str, oauth_id: str, amount: int = 1) -> Optional[dict]:
    """Deduct credits from a user's balance.
    
    Called when a message is sent by a hushhush credits user.
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID (hashed)
        amount: Number of credits to deduct (default 1)
    
    Returns:
        Updated info with new balance, or None if user not found or insufficient credits
    """
    if not _pool:
        return None
    
    async with _pool.acquire() as conn:
        # First check if user has enough credits
        row = await conn.fetchrow(
            """
            SELECT credit_balance FROM users
            WHERE oauth_provider = $1 AND oauth_id = $2
            """,
            provider, oauth_id
        )
        
        if not row or (row['credit_balance'] or 0) < amount:
            logger.warning("Insufficient credits for %s:%s... (balance: %d, requested: %d)",
                         provider, oauth_id[:16], row['credit_balance'] if row else 0, amount)
            return None
        
        # Deduct credits and increment total_messages
        row = await conn.fetchrow(
            """
            UPDATE users
            SET credit_balance = credit_balance - $3,
                total_messages = COALESCE(total_messages, 0) + $3,
                updated_at = NOW()
            WHERE oauth_provider = $1 AND oauth_id = $2
            RETURNING id, credit_balance, total_messages
            """,
            provider, oauth_id, amount
        )
        
        return dict(row) if row else None


async def get_user_quota_with_credits(
    provider: str, 
    oauth_id: str, 
    brand: str = "botchat"
) -> dict:
    """Get user's quota status, handling both subscription and credits models.
    
    v3.2.0: Brand-aware quota that handles:
    - botchat: Subscription-based (Pro/Plus monthly quotas)
    - hushhush: Credit-based (one-time purchase, no expiry) + weekly refresh for free
    
    Args:
        provider: OAuth provider
        oauth_id: OAuth user ID (hashed)
        brand: Brand context ('botchat' or 'hushhush')
    
    Returns:
        Quota info dict with used, limit, remaining, etc.
    """
    user = await get_user_for_billing(provider, oauth_id, None)
    
    if not user:
        return {
            "used": 0,
            "limit": FREE_TIER_QUOTA,
            "remaining": FREE_TIER_QUOTA,
            "period_ends_at": None,
            "is_paid": False,
            "credit_balance": 0,
        }
    
    # Check if user has credits (hushhush model)
    credit_balance = user.get("credit_balance") or 0
    
    if brand == "hushhush" and credit_balance > 0:
        # Credits model: user has purchased credits
        return {
            "used": user.get("total_messages") or 0,  # Lifetime total for reference
            "limit": credit_balance,  # Current balance is the "limit"
            "remaining": credit_balance,
            "period_ends_at": None,  # Credits don't expire
            "is_paid": True,
            "credit_balance": credit_balance,
        }
    
    # Fall back to subscription model (botchat) or free tier
    status = user.get("subscription_status", "none")
    is_paid = status in ("trialing", "active")
    tier = user.get("subscription_tier")
    
    # Check if subscription has ended
    sub_ends_at = user.get("subscription_ends_at")
    if sub_ends_at and datetime.now() > sub_ends_at:
        is_paid = False
        tier = None
    
    # Determine quota limit
    limit = get_quota_limit_for_tier(tier, is_paid, brand)
    
    # Get quota usage
    message_quota_used = user.get("message_quota_used") or 0
    is_lifetime = user.get("is_lifetime_quota", True)  # Default to lifetime for free users
    
    # For free users with lifetime quota
    if not is_paid and is_lifetime:
        # v3.2.0: Hushhush free users get weekly refresh (+5/week)
        if brand == "hushhush":
            # Calculate weekly refreshes since account creation or last reset
            quota_period_start = user.get("quota_period_start") or user.get("created_at") or datetime.now()
            weeks_elapsed = max(0, (datetime.now() - quota_period_start).days // WEEKLY_REFRESH_DAYS)
            
            # Total allowance = base + (weeks * weekly_refresh)
            # Cap at reasonable maximum to prevent abuse (e.g., 100 max from refreshes)
            max_refresh_weeks = 15  # Cap at 75 additional messages from refreshes
            effective_weeks = min(weeks_elapsed, max_refresh_weeks)
            total_allowance = FREE_TIER_QUOTA + (effective_weeks * SIGNED_IN_WEEKLY_REFRESH)
            
            # Calculate next refresh date
            next_refresh_at = quota_period_start + timedelta(days=((weeks_elapsed + 1) * WEEKLY_REFRESH_DAYS))
            
            return {
                "used": message_quota_used,
                "limit": total_allowance,
                "remaining": max(0, total_allowance - message_quota_used),
                "period_ends_at": next_refresh_at.isoformat(),  # Next weekly refresh
                "is_paid": False,
                "credit_balance": credit_balance,
                "weekly_refresh": SIGNED_IN_WEEKLY_REFRESH,
            }
        
        # Botchat: pure lifetime cap (no refresh)
        return {
            "used": message_quota_used,
            "limit": limit,
            "remaining": max(0, limit - message_quota_used),
            "period_ends_at": None,  # Lifetime, no reset
            "is_paid": False,
            "credit_balance": credit_balance,
        }
    
    # For paid users, handle period reset
    quota_period_start = user.get("quota_period_start") or datetime.now()
    period_ends_at = None
    
    if is_paid and sub_ends_at:
        period_ends_at = sub_ends_at
        if datetime.now() > sub_ends_at:
            message_quota_used = 0  # Would be reset
    else:
        period_ends_at = quota_period_start + timedelta(days=QUOTA_PERIOD_DAYS)
        if datetime.now() > period_ends_at:
            message_quota_used = 0  # Would be reset
    
    return {
        "used": message_quota_used,
        "limit": limit,
        "remaining": max(0, limit - message_quota_used),
        "period_ends_at": period_ends_at.isoformat() if period_ends_at else None,
        "is_paid": is_paid,
        "credit_balance": credit_balance,
    }


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
