# ============================================================================
# ⚠️  PUBLIC FILE - Part of botchat-oss transparency repo
# ============================================================================
# This file is publicly visible at: https://github.com/LeoooDias/botchat-oss
#
# Purpose: Demonstrate privacy-first authentication (no PII storage)
#
# ⚠️  DO NOT add proprietary business logic here
# ⚠️  Only privacy/security transparency code belongs in this file
# ============================================================================

"""Authentication module for botchat.

Handles OAuth token validation and JWT generation/verification.
Supports GitHub, Google, Apple, and Microsoft OAuth providers.

PSEUDONYMOUS AUTHENTICATION MODEL:
Users are identified by a stable pseudonym (hashed OAuth ID) that:
- Cannot be reversed to reveal real identity
- Is app-specific (different from hashes in other apps)
- Persists across sessions (allows quotas/subscriptions)

PRIVACY-FIRST SECURITY:
- OAuth IDs are hashed with an app-level pepper (OAUTH_HASH_SALT) before storage
- NO personally identifying information (PII) is stored:
  - No emails
  - No names  
  - No avatars/profile pictures
- JWTs contain only: provider + hashed_user_id
- Minimal OAuth scopes requested (openid only where possible)
- AI providers receive the same opaque hash - they can't identify users either
- Optional recovery email (stored as hash) offered after 500 messages
"""

import os
import time
import hmac
import logging
import hashlib
from typing import Any, Optional, Tuple
from dataclasses import dataclass

import httpx
from jose import jwt, JWTError
from fastapi import HTTPException, Header, Depends
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# -----------------------------
# Configuration
# -----------------------------

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 604800  # 7 days (was 1 hour)

# OAuth Client IDs/Secrets
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
APPLE_CLIENT_ID = os.environ.get("APPLE_CLIENT_ID", "")  # Service ID (e.g., com.botchat.auth)
APPLE_TEAM_ID = os.environ.get("APPLE_TEAM_ID", "")
APPLE_KEY_ID = os.environ.get("APPLE_KEY_ID", "")
APPLE_PRIVATE_KEY = os.environ.get("APPLE_PRIVATE_KEY", "")  # PEM format, newlines as \n
MICROSOFT_CLIENT_ID = os.environ.get("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.environ.get("MICROSOFT_CLIENT_SECRET", "")
MICROSOFT_TENANT_ID = os.environ.get("MICROSOFT_TENANT_ID", "common")  # 'common' for multi-tenant

# Auth mode - disable for local development
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "false").lower() == "true"

# GCP project for Secrets Manager (optional)
GCP_PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")


def _get_secret_from_gcp(secret_name: str) -> Optional[str]:
    """Fetch a secret from GCP Secret Manager.
    
    Returns None if GCP is not configured or secret doesn't exist.
    Caches the result for the lifetime of the process.
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
    """Get pepper/salt from GCP Secrets Manager with env var fallback.
    
    Priority:
    1. GCP Secret Manager (if GCP_PROJECT_ID is set)
    2. Environment variable
    3. Empty string (insecure, development only)
    """
    # Try GCP first
    gcp_value = _get_secret_from_gcp(secret_name)
    if gcp_value:
        logger.info("Loaded %s from GCP Secret Manager", secret_name)
        return gcp_value
    
    # Fall back to env var
    env_value = os.environ.get(env_var, "")
    if env_value:
        logger.info("Loaded %s from environment variable", env_var)
        return env_value
    
    # No value configured
    return ""


# OAuth ID hashing salt (pepper) - CRITICAL: keep this secret and never change it
# If changed, all existing users will be unable to log in
# Loaded from GCP Secret Manager (oauth-hash-salt) or OAUTH_HASH_SALT env var
OAUTH_HASH_SALT = _get_pepper("oauth-hash-salt", "OAUTH_HASH_SALT")

# Email hash salt (separate from OAuth salt for defense in depth)
# Used for magic link email authentication
# Loaded from GCP Secret Manager (email-hash-salt) or EMAIL_HASH_SALT env var
EMAIL_HASH_SALT = _get_pepper("email-hash-salt", "EMAIL_HASH_SALT")

# Email allowlist - comma-separated list of allowed OAuth IDs (empty = allow all)
# Used to restrict access in dev environments
# NOTE: These should be hashed OAuth IDs, not emails
_allowed_ids_raw = os.environ.get("ALLOWED_OAUTH_IDS", "")
ALLOWED_OAUTH_IDS: set[str] = {
    e.strip() for e in _allowed_ids_raw.split(",") if e.strip()
}


def hash_oauth_id(provider: str, oauth_id: str) -> str:
    """Hash an OAuth ID with the secret salt (app-level pepper).
    
    SECURITY PROPERTIES:
    - Deterministic: same input = same output (required for lookups)
    - Irreversible: cannot recover original OAuth ID from hash
    - App-specific: different apps using same OAuth provider get different hashes
    - Provider-namespaced: same user ID from different providers = different hash
    
    The salt (OAUTH_HASH_SALT) acts as an "app-level pepper" that ensures:
    - Our hashes can't be matched against OAuth ID leaks from other apps
    - Rainbow tables are infeasible (OAuth IDs have high entropy anyway)
    
    CRITICAL: The salt MUST be kept secret and NEVER changed.
    Changing it will orphan all existing user accounts.
    """
    if not OAUTH_HASH_SALT:
        # In development without salt, use raw ID (not for production!)
        logger.warning("OAUTH_HASH_SALT not set - using raw OAuth IDs (insecure)")
        return f"{provider}:{oauth_id}"
    
    # Create a secure hash: SHA-256(salt:provider:oauth_id)
    data = f"{OAUTH_HASH_SALT}:{provider}:{oauth_id}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hash_email(email: str) -> str:
    """Hash an email address for privacy-first storage.

    SECURITY PROPERTIES:
    - Deterministic: same email = same hash (required for lookups)
    - Irreversible: cannot recover original email from hash
    - App-specific: different apps using same email get different hashes
    - Normalized: case-insensitive, whitespace-trimmed

    The salt (EMAIL_HASH_SALT) acts as an "app-level pepper" separate from
    OAuth salt for defense in depth.

    CRITICAL: The salt MUST be kept secret and NEVER changed.
    Changing it will orphan all existing email user accounts.
    """
    if not EMAIL_HASH_SALT:
        # In development without salt, use raw email (not for production!)
        logger.warning("EMAIL_HASH_SALT not set - using raw emails (insecure)")
        return f"email:{email.lower()}"

    # Normalize: lowercase, strip whitespace
    normalized = email.strip().lower()

    # Validate basic format
    if "@" not in normalized or "." not in normalized.split("@")[1]:
        raise ValueError("Invalid email format")

    # Create a secure hash: SHA-256(salt:email:normalized_email)
    data = f"{EMAIL_HASH_SALT}:email:{normalized}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hash_magic_link_token(token: str) -> str:
    """Hash a magic link token for secure database storage.

    SECURITY: Tokens are hashed before storage so that database compromise
    doesn't expose valid tokens. Uses the same salt as email hashing.

    Note: Tokens are single-use and short-lived (1 hour), so hashing provides
    defense-in-depth rather than being strictly necessary.
    """
    if not EMAIL_HASH_SALT:
        logger.warning("EMAIL_HASH_SALT not set - storing raw tokens (insecure)")
        return token

    data = f"{EMAIL_HASH_SALT}:token:{token}".encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def check_user_allowed(hashed_id: str) -> None:
    """Check if user is in allowlist (if configured).
    
    Raises HTTPException 403 if user is not allowed.
    If ALLOWED_OAUTH_IDS is empty, all users are allowed.
    
    Uses constant-time comparison to prevent timing attacks that could
    reveal whether a specific hashed ID exists in the allowlist.
    """
    if not ALLOWED_OAUTH_IDS:
        return  # No restrictions
    
    # Constant-time comparison: iterate all entries to prevent timing leaks
    # An attacker shouldn't be able to determine if their hash is "close" to an allowed one
    is_allowed = False
    for allowed_id in ALLOWED_OAUTH_IDS:
        if hmac.compare_digest(hashed_id, allowed_id):
            is_allowed = True
            # Don't break early - continue checking all to maintain constant time
    
    if is_allowed:
        return
    
    # Only log truncated hash for privacy
    logger.warning("Access denied for hashed_id: %s (not in allowlist)", hashed_id[:16] + "...")
    raise HTTPException(
        status_code=403,
        detail="Access denied. This environment is restricted to authorized users only."
    )


# -----------------------------
# Models
# -----------------------------

@dataclass
class UserInfo:
    """Minimal anonymous user info extracted from OAuth/JWT.
    
    PRIVACY: This contains NO personally identifying information.
    - user_id is a hashed OAuth ID (irreversible)
    - No email, name, or avatar stored
    """
    provider: str  # "github", "google", "apple", or "microsoft"
    user_id: str   # Hashed OAuth ID (SHA-256 of salt:provider:raw_oauth_id)


class OAuthCallbackRequest(BaseModel):
    """OAuth callback with authorization code."""
    code: str
    provider: str  # "github", "google", "apple", or "microsoft"
    redirect_uri: str
    id_token: Optional[str] = None  # Apple sends id_token via POST


class AuthResponse(BaseModel):
    """Response containing JWT and user info."""
    token: str
    user: dict[str, Any]
    expires_at: int


class MagicLinkRequest(BaseModel):
    """Request a magic link to be sent to email."""
    email: str


class MagicLinkVerifyRequest(BaseModel):
    """Verify a magic link token."""
    token: str


class MagicLinkResponse(BaseModel):
    """Response after requesting magic link."""
    success: bool
    message: str
    # PRIVACY: Never reveal if email exists or not (timing attack protection)


# -----------------------------
# JWT Functions
# -----------------------------

def create_jwt(user: UserInfo) -> Tuple[str, int]:
    """Create a signed JWT for authenticated user.
    
    PRIVACY: JWT contains only anonymous data:
    - provider (github/google/apple/microsoft)
    - hashed user ID (cannot be reversed)
    - NO email, name, or avatar
    
    Returns (token, expires_at_timestamp)
    """
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET not configured")
    
    expires_at = int(time.time()) + JWT_EXPIRY_SECONDS
    payload: dict[str, Any] = {
        "sub": f"{user.provider}:{user.user_id}",
        "provider": user.provider,
        # NO PII: email, name, avatar intentionally omitted
        "exp": expires_at,
        "iat": int(time.time()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expires_at


def verify_jwt(token: str) -> UserInfo:
    """Verify JWT signature and extract user info.
    
    Raises HTTPException on invalid/expired token.
    """
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET not configured")
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as e:
        logger.warning("JWT verification failed: %s", str(e))
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    # Extract user info from payload
    sub = payload.get("sub", "")
    if ":" not in sub:
        raise HTTPException(status_code=401, detail="Invalid token format")
    
    provider, user_id = sub.split(":", 1)
    return UserInfo(
        provider=provider,
        user_id=user_id,
        # NO PII extracted - anonymous user
    )


# -----------------------------
# OAuth Token Exchange
# -----------------------------

async def exchange_github_code(code: str, redirect_uri: str) -> UserInfo:
    """Exchange GitHub OAuth code for user info.
    
    PRIVACY-FIRST: We only extract the user ID and immediately hash it.
    No email, name, or avatar is stored or returned.
    
    Flow:
    1. Exchange code for access token
    2. Fetch user ID from GitHub API
    3. Hash the ID and return anonymous UserInfo
    """
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Exchange code for token
        token_resp = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        
        if token_resp.status_code != 200:
            logger.error("GitHub token exchange failed: %s", token_resp.text)
            raise HTTPException(status_code=401, detail="GitHub authentication failed")
        
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            error = token_data.get("error_description", "Unknown error")
            logger.error("GitHub token missing: %s", error)
            raise HTTPException(status_code=401, detail=f"GitHub auth error: {error}")
        
        # Step 2: Fetch user ID only (we don't need profile data)
        user_resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
        )
        
        if user_resp.status_code != 200:
            logger.error("GitHub user fetch failed: %s", user_resp.text)
            raise HTTPException(status_code=401, detail="Failed to fetch GitHub profile")
        
        user_data = user_resp.json()
        raw_oauth_id = str(user_data["id"])
        
        # Step 3: Hash the OAuth ID - NO PII is stored
        hashed_id = hash_oauth_id("github", raw_oauth_id)
        
        # Check allowlist
        check_user_allowed(hashed_id)
        
        # Return anonymous user - NO PII
        return UserInfo(
            provider="github",
            user_id=hashed_id,
        )


async def exchange_google_code(code: str, redirect_uri: str) -> UserInfo:
    """Exchange Google OAuth code for user info.
    
    PRIVACY-FIRST: We only extract the user ID (sub claim) and hash it.
    No email, name, or avatar is stored or returned.
    
    Flow:
    1. Exchange code for tokens (including id_token)
    2. Decode id_token to get user ID only
    3. Hash the ID and return anonymous UserInfo
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")
    
    async with httpx.AsyncClient() as client:
        # Step 1: Exchange code for tokens
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        
        if token_resp.status_code != 200:
            logger.error("Google token exchange failed: %s", token_resp.text)
            raise HTTPException(status_code=401, detail="Google authentication failed")
        
        token_data = token_resp.json()
        id_token = token_data.get("id_token")
        
        if not id_token:
            raise HTTPException(status_code=401, detail="Google id_token missing")
        
        # Step 2: Decode id_token to get user ID
        try:
            claims = jwt.get_unverified_claims(id_token)
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid Google id_token")
        
        raw_oauth_id = claims["sub"]
        
        # Step 3: Hash the OAuth ID - NO PII is stored
        hashed_id = hash_oauth_id("google", raw_oauth_id)
        
        # Check allowlist
        check_user_allowed(hashed_id)
        
        # Return anonymous user - NO PII
        return UserInfo(
            provider="google",
            user_id=hashed_id,
        )


async def exchange_apple_code(code: str, redirect_uri: str, id_token: Optional[str] = None) -> UserInfo:
    """Exchange Apple OAuth code for user info.
    
    PRIVACY-FIRST: We only extract the user ID (sub claim) and hash it.
    No email, name, or avatar is stored or returned.
    
    Apple Sign In flow:
    1. Generate client_secret JWT signed with Apple private key
    2. Exchange code for tokens (including id_token)
    3. Decode id_token to get user ID only
    4. Hash the ID and return anonymous UserInfo
    """
    if not APPLE_CLIENT_ID or not APPLE_TEAM_ID or not APPLE_KEY_ID or not APPLE_PRIVATE_KEY:
        raise HTTPException(status_code=500, detail="Apple OAuth not configured")
    
    # Apple requires a client_secret JWT signed with your private key
    import time as time_module
    client_secret_payload: dict[str, Any] = {
        "iss": APPLE_TEAM_ID,
        "iat": int(time_module.time()),
        "exp": int(time_module.time()) + 86400 * 180,  # 6 months max
        "aud": "https://appleid.apple.com",
        "sub": APPLE_CLIENT_ID,
    }
    
    # Handle private key - may have \n as literal string
    private_key = APPLE_PRIVATE_KEY.replace("\\n", "\n")
    
    client_secret = jwt.encode(
        client_secret_payload,
        private_key,
        algorithm="ES256",
        headers={"kid": APPLE_KEY_ID}
    )
    
    async with httpx.AsyncClient() as client:
        # Exchange code for tokens
        token_resp = await client.post(
            "https://appleid.apple.com/auth/token",
            data={
                "client_id": APPLE_CLIENT_ID,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        if token_resp.status_code != 200:
            logger.error("Apple token exchange failed: %s", token_resp.text)
            raise HTTPException(status_code=401, detail="Apple authentication failed")
        
        token_data = token_resp.json()
        received_id_token = token_data.get("id_token") or id_token
        
        if not received_id_token:
            raise HTTPException(status_code=401, detail="Apple id_token missing")
        
        # Decode id_token to get user ID
        try:
            claims = jwt.get_unverified_claims(received_id_token)
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid Apple id_token")
        
        raw_oauth_id = claims["sub"]
        
        # Hash the OAuth ID - NO PII is stored
        hashed_id = hash_oauth_id("apple", raw_oauth_id)
        
        # Check allowlist
        check_user_allowed(hashed_id)
        
        # Return anonymous user - NO PII
        return UserInfo(
            provider="apple",
            user_id=hashed_id,
        )


async def exchange_microsoft_code(code: str, redirect_uri: str) -> UserInfo:
    """Exchange Microsoft OAuth code for user info.
    
    PRIVACY-FIRST: We only extract the user ID and hash it.
    No email, name, or avatar is stored or returned.
    
    Flow:
    1. Exchange code for tokens (including id_token)
    2. Decode id_token to get user ID only
    3. Hash the ID and return anonymous UserInfo
    """
    if not MICROSOFT_CLIENT_ID or not MICROSOFT_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Microsoft OAuth not configured")
    
    async with httpx.AsyncClient() as client:
        # Exchange code for tokens
        token_resp = await client.post(
            f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/token",
            data={
                "client_id": MICROSOFT_CLIENT_ID,
                "client_secret": MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        if token_resp.status_code != 200:
            logger.error("Microsoft token exchange failed: %s", token_resp.text)
            raise HTTPException(status_code=401, detail="Microsoft authentication failed")
        
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        id_token = token_data.get("id_token")
        
        if not access_token:
            raise HTTPException(status_code=401, detail="Microsoft access_token missing")
        
        # Get user ID from id_token or Graph API
        raw_oauth_id = None
        
        if id_token:
            try:
                claims = jwt.get_unverified_claims(id_token)
                raw_oauth_id = claims.get("sub") or claims.get("oid")
            except JWTError:
                pass
        
        # Fall back to Graph API if no ID from token
        if not raw_oauth_id:
            user_resp = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                raw_oauth_id = user_data.get("id")
        
        if not raw_oauth_id:
            raise HTTPException(status_code=401, detail="Failed to get Microsoft user ID")
        
        # Hash the OAuth ID - NO PII is stored
        hashed_id = hash_oauth_id("microsoft", raw_oauth_id)
        
        # Check allowlist
        check_user_allowed(hashed_id)
        
        # Return anonymous user - NO PII
        return UserInfo(
            provider="microsoft",
            user_id=hashed_id,
        )


async def exchange_oauth_code(req: OAuthCallbackRequest) -> UserInfo:
    """Exchange OAuth code for user info (dispatcher)."""
    if req.provider == "github":
        return await exchange_github_code(req.code, req.redirect_uri)
    elif req.provider == "google":
        return await exchange_google_code(req.code, req.redirect_uri)
    elif req.provider == "apple":
        # Apple uses backend callback URL (form_post) - must use that URL for token exchange
        backend_url = os.environ.get("BACKEND_URL", "")
        if not backend_url:
            raise HTTPException(status_code=500, detail="BACKEND_URL not configured for Apple Sign In")
        apple_redirect = f"{backend_url}/auth/apple/callback"
        return await exchange_apple_code(req.code, apple_redirect, req.id_token)
    elif req.provider == "microsoft":
        return await exchange_microsoft_code(req.code, req.redirect_uri)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")


# -----------------------------
# FastAPI Dependencies
# -----------------------------

async def get_current_user(
    authorization: Optional[str] = Header(None)
) -> Optional[UserInfo]:
    """Extract and verify user from Authorization header.
    
    Returns None if auth is disabled or no token provided.
    Raises HTTPException if auth is required and token is invalid.
    """
    if not REQUIRE_AUTH:
        return None
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization[7:]  # Remove "Bearer " prefix
    return verify_jwt(token)


async def require_auth(user: Optional[UserInfo] = Depends(get_current_user)) -> UserInfo:
    """Require authenticated user (use as dependency).
    
    When REQUIRE_AUTH=false, returns a dummy user for development.
    """
    if not REQUIRE_AUTH:
        return UserInfo(provider="dev", user_id="dev-user-hashed")
    
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    return user


# -----------------------------
# OAuth URL Builders
# PRIVACY: Minimal scopes - we only need user ID for authentication
# -----------------------------

def get_github_auth_url(redirect_uri: str, state: str = "") -> str:
    """Build GitHub OAuth authorization URL.
    
    PRIVACY: Minimal scope - only read:user for user ID.
    """
    from urllib.parse import urlencode
    
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "read:user",
    }
    if state:
        params["state"] = state
    return f"https://github.com/login/oauth/authorize?{urlencode(params)}"


def get_google_auth_url(redirect_uri: str, state: str = "") -> str:
    """Build Google OAuth authorization URL.
    
    PRIVACY: Minimal scope - only openid for user ID (sub claim).
    """
    from urllib.parse import urlencode
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"


def get_apple_auth_url(redirect_uri: str, state: str = "") -> str:
    """Build Apple OAuth authorization URL.
    
    PRIVACY: Minimal scope - Apple provides 'sub' claim regardless of scope.
    """
    from urllib.parse import urlencode
    
    params = {
        "client_id": APPLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "response_mode": "form_post",  # Apple requires form_post for web
    }
    if state:
        params["state"] = state
    return f"https://appleid.apple.com/auth/authorize?{urlencode(params)}"


def get_microsoft_auth_url(redirect_uri: str, state: str = "") -> str:
    """Build Microsoft OAuth authorization URL.
    
    PRIVACY: Minimal scope - only openid for user ID.
    """
    from urllib.parse import urlencode
    
    params = {
        "client_id": MICROSOFT_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid",
        "response_mode": "query",
    }
    if state:
        params["state"] = state
    return f"https://login.microsoftonline.com/{MICROSOFT_TENANT_ID}/oauth2/v2.0/authorize?{urlencode(params)}"
