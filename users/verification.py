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

    # Let users change their own email address (#41). Off by default: the
    # change needs the current password, a confirmation from the new address,
    # and leaves the old address a way to cancel or revert it.
    allow_email_change: bool = False

    # How long the old address can undo an applied email change.
    email_change_revert_ttl_days: int = 7

    # Refuse an admin delete unless the account is suspended or inactive (#48),
    # so a delete always follows a reversible step. Set False for the old
    # behaviour, where any account can be deleted outright.
    admin_delete_requires_suspension: bool = True

    # How a suspended user can reach an admin, e.g. "support@example.com". It
    # goes into the suspension email. When None the email says to contact an
    # admin.
    suspension_contact: Optional[str] = None

    # Let users delete their own account (#29). Off by default. Needs migration
    # 0005. The account is deactivated at once and deleted for good once its
    # period ends, by purge_due_deletions(), which the app schedules.
    allow_self_delete: bool = False

    # Days until an unconfirmed deletion request is purged, counted from the
    # request.
    account_deletion_unconfirmed_days: int = 14

    # Days until a confirmed deletion is purged, counted from the confirmation.
    # The restore link works until then.
    account_deletion_grace_days: int = 14

    # URL template for the three account-deletion links, with {action}
    # (confirm, keep or restore) and {token} placeholders, e.g.
    # "https://app.example.com/account/delete/{action}?token={token}". When None
    # the emails carry the bare token.
    account_deletion_url_template: Optional[str] = None

    # URL template for the three email-change links, with {action} (confirm,
    # cancel or revert) and {token} placeholders, e.g.
    # "https://app.example.com/account/email/{action}?token={token}". When None
    # the emails carry the bare token.
    email_change_url_template: Optional[str] = None

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
