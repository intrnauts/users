"""Token generation and policy for the two "prove you control this email" flows:
new-user email verification and password reset.

Tokens are generated as URL-safe random strings and handed to the user by email,
but only a SHA-256 digest is ever stored. A database dump, a leaked backup or a
SQL injection therefore yields no usable account-takeover link.
"""

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

# Number of random bytes behind each token. 32 bytes = 256 bits of entropy,
# rendered as a 43-character URL-safe string.
TOKEN_BYTES = 32

@dataclass
class VerificationConfig:
    """Policy for email verification and password reset.

    Defaults are chosen to be backwards compatible: an application that never
    calls configure_verification() keeps behaving as it did before email
    verification existed, except that registration now sends a verification
    email when an email service is configured.
    """

    # Refuse login for users whose email address is not verified.
    require_verified_email: bool = False

    # Move a PENDING user to ACTIVE when they verify their email. Set False to
    # keep an admin-approval step after verification.
    auto_activate_on_verify: bool = True

    # Send a verification email as part of create_user().
    send_verification_on_register: bool = True

    # Lifetime of each kind of token.
    verification_token_ttl_hours: int = 24
    password_reset_token_ttl_hours: int = 1

    # URL template containing a {token} placeholder, e.g.
    # "https://app.example.com/verify-email?token={token}". When None the email
    # carries the bare token.
    verification_url_template: Optional[str] = None

def generate_token() -> str:
    """Generate a new random token to send to a user."""
    return secrets.token_urlsafe(TOKEN_BYTES)

def hash_token(token: str) -> str:
    """Hash a token for storage.

    A plain SHA-256 is appropriate here (unlike for passwords): tokens carry
    256 bits of entropy, so there is nothing to brute force and no need for a
    slow KDF.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

# Global verification config instance
_verification_config: Optional[VerificationConfig] = None

def get_verification_config() -> VerificationConfig:
    """Get the configured verification policy, or the defaults."""
    if _verification_config is None:
        return VerificationConfig()
    return _verification_config

def configure_verification(config: VerificationConfig) -> VerificationConfig:
    """Configure the global verification policy."""
    global _verification_config
    _verification_config = config
    return _verification_config
