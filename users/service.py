import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import HTTPException, status
from .models import (
    User, UserCreate, UserUpdate, UserLogin, Token, UserResponse, UserStatus,
    PasswordResetRequest, PasswordResetConfirm,
    EmailVerificationConfirm, EmailVerificationResend,
    EmailChangeRequest, EmailChangeTokenAction, EmailChangeTokenPurpose,
    AccountDeletionRequest, AccountDeletionTokenAction, AccountDeletionTokenPurpose
)
from .repository import UserRepositoryInterface, RoleRepository, PermissionRepository
from .auth import get_auth_manager
from .email_service import get_email_service
from .verification import generate_token, hash_token, get_verification_config

logger = logging.getLogger(__name__)

class UserService:
    def __init__(
        self,
        user_repository: UserRepositoryInterface,
        role_repository: RoleRepository = None,
        permission_repository: PermissionRepository = None
    ):
        self.user_repo = user_repository
        self.role_repo = role_repository
        self.permission_repo = permission_repository

    async def create_user(self, user_data: UserCreate, *, trusted: bool = False) -> UserResponse:
        """Create a user.

        Untrusted by default: status, is_superuser and roles are reset to
        PENDING, False and [] so that a public endpoint passing a request body
        straight through cannot create an active superuser. Pass trusted=True
        only when those fields were set by server code (admin tooling, seed
        scripts, or a register route that deliberately activates new users).
        """
        if not trusted:
            if (user_data.status != UserStatus.PENDING or user_data.is_superuser
                    or user_data.roles):
                logger.warning(
                    "create_user() ignored status/is_superuser/roles for %s; "
                    "pass trusted=True if server code set them",
                    user_data.email
                )
            user_data = user_data.model_copy(update={
                "status": UserStatus.PENDING,
                "is_superuser": False,
                "roles": []
            })

        # Check if user already exists
        existing_user = await self.user_repo.get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        if user_data.username:
            existing_username = await self.user_repo.get_user_by_username(user_data.username)
            if existing_username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        # Hash password
        auth_manager = get_auth_manager()
        hashed_password = auth_manager.hash_password(user_data.password)

        # Create user with hashed password
        user_create_data = user_data.model_copy()
        user_create_data.password = hashed_password

        db_user = await self.user_repo.create_user(user_create_data)

        # Send the verification email. A failure here (no email service
        # configured, SMTP down) must not fail the registration - the user can
        # always request a new link via resend_verification_email().
        config = get_verification_config()
        if config.send_verification_on_register:
            await self._send_verification_email(db_user, config.verification_url_template)

        return self._user_to_response(db_user)

    async def _send_verification_email(
        self,
        user: User,
        verification_url_template: str = None
    ) -> bool:
        """Issue a fresh verification token for a user and email it to them.

        Returns True if the email was handed off successfully. Never raises:
        callers treat email delivery as best effort.
        """
        config = get_verification_config()

        if verification_url_template is None:
            verification_url_template = config.verification_url_template

        try:
            raw_token = generate_token()
            expires_at = datetime.utcnow() + timedelta(
                hours=config.verification_token_ttl_hours
            )

            # Only ever one live verification link per user.
            await self.user_repo.delete_user_verification_tokens(user.id)
            await self.user_repo.create_email_verification_token(
                user_id=user.id,
                token_hash=hash_token(raw_token),
                expires_at=expires_at
            )

            email_service = get_email_service()
            return await email_service.send_verification_email(
                recipient_email=user.email,
                verification_token=raw_token,
                verification_url_template=verification_url_template
            )
        except Exception as e:
            # Includes the token write, so that a database problem here cannot
            # fail a registration that has already been committed.
            logger.error(f"Failed to send verification email: {e}")
            return False

    async def authenticate_user(self, login_data: UserLogin) -> Optional[User]:
        user = await self.user_repo.get_user_by_email(login_data.email)
        if not user:
            return None

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(login_data.password, user.hashed_password):
            return None

        return user

    async def login(self, login_data: UserLogin) -> Token:
        user = await self.authenticate_user(login_data)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        config = get_verification_config()

        # A user who was sent a verification link and has not used it should be
        # told to check their email, not that they are waiting on an admin.
        awaiting_verification = not user.is_verified and (
            config.require_verified_email or config.send_verification_on_register
        )
        verification_error = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please verify your email address before logging in.",
        )

        # Reject non-active accounts with a clear message
        if user.status == UserStatus.PENDING.value:
            if awaiting_verification:
                raise verification_error
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your account is pending admin approval.",
            )
        if user.status == UserStatus.INACTIVE.value:
            # Read only with self-delete on, so apps without migration 0005
            # never touch the table (#29)
            if config.allow_self_delete and await self.user_repo.get_account_deletion(user.id):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Your account is scheduled for deletion. Use the link in the email we sent to keep or restore it.",
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your account has been deactivated. Please contact an admin.",
            )
        if user.status == UserStatus.SUSPENDED.value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your account has been suspended. Please contact an admin.",
            )

        if config.require_verified_email and not user.is_verified:
            raise verification_error

        # Only a login that issues a token counts, not a correct password on an
        # account rejected above
        await self.user_repo.touch_last_login(user.id)

        # Get user permissions
        permissions = await self.user_repo.get_user_permissions(user.id)

        # Create access token
        auth_manager = get_auth_manager()
        access_token = auth_manager.create_access_token(
            user_email=user.email,
            permissions=permissions,
            user_id=user.id
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=auth_manager.get_token_expiry_time()
        )

    async def get_user_by_id(self, user_id: int) -> Optional[UserResponse]:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None
        return self._user_to_response(user)

    async def get_user_by_email(self, email: str) -> Optional[UserResponse]:
        user = await self.user_repo.get_user_by_email(email)
        if not user:
            return None
        return self._user_to_response(user)

    async def update_user(self, user_id: int, user_data: UserUpdate) -> Optional[UserResponse]:
        # Check if email is being updated and if it's already taken
        if user_data.email:
            existing_user = await self.user_repo.get_user_by_email(user_data.email)
            if existing_user and existing_user.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already registered"
                )

        # Check if username is being updated and if it's already taken
        if user_data.username:
            existing_username = await self.user_repo.get_user_by_username(user_data.username)
            if existing_username and existing_username.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username already taken"
                )

        current = await self.user_repo.get_user_by_id(user_id)
        if not current:
            return None

        # Moving into or out of suspended goes through _change_status, so the
        # suspension fields and the emails follow the status (#48)
        new_status = user_data.status.value if user_data.status is not None else None
        status_change = new_status is not None and (
            (new_status == UserStatus.SUSPENDED.value)
            != (current.status == UserStatus.SUSPENDED.value)
        )
        if status_change:
            user_data = UserUpdate(**user_data.model_dump(exclude_unset=True, exclude={"status"}))

        user = await self.user_repo.update_user(user_id, user_data)
        if not user:
            return None
        if status_change:
            user = await self._change_status(user, new_status)
        return self._user_to_response(user)

    async def suspend_user(self, user_id: int, reason: Optional[str] = None) -> Optional[UserResponse]:
        """Suspend an account, store the optional reason and email the user (#48)."""
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None
        if user.status == UserStatus.SUSPENDED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already suspended"
            )

        reason = reason.strip() if reason else None
        user = await self._change_status(user, UserStatus.SUSPENDED.value, reason or None)
        return self._user_to_response(user)

    async def reactivate_user(self, user_id: int) -> Optional[UserResponse]:
        """Make a suspended account active again and email the user (#48)."""
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None
        if user.status != UserStatus.SUSPENDED.value:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is not suspended"
            )

        user = await self._change_status(user, UserStatus.ACTIVE.value)
        return self._user_to_response(user)

    async def _change_status(self, user: User, new_status: str, reason: Optional[str] = None) -> User:
        """Set a status that moves an account into or out of suspended.

        Suspending stores the reason and time; any other status clears them.
        The user is emailed when suspended and when made active again. Email is
        best effort: a failed send doesn't undo the change.
        """
        suspending = new_status == UserStatus.SUSPENDED.value
        updated = await self.user_repo.set_status(
            user.id, new_status,
            suspension_reason=reason if suspending else None,
            suspended_at=datetime.utcnow() if suspending else None,
        )

        try:
            email_service = get_email_service()
            if suspending:
                await email_service.send_account_suspended_notice(
                    recipient_email=updated.email,
                    reason=reason,
                    contact=get_verification_config().suspension_contact
                )
            elif new_status == UserStatus.ACTIVE.value:
                await email_service.send_account_reactivated_notice(updated.email)
        except Exception as e:
            logger.error(f"Failed to send account status email: {e}")

        return updated

    async def delete_user(self, user_id: int) -> bool:
        # An admin delete follows a reversible step (#48): only a suspended or
        # inactive account can be deleted, unless the app turned that off
        if get_verification_config().admin_delete_requires_suspension:
            user = await self.user_repo.get_user_by_id(user_id)
            if not user:
                return False
            if user.status not in (UserStatus.SUSPENDED.value, UserStatus.INACTIVE.value):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Suspend or deactivate the account before deleting it"
                )
        user = await self.user_repo.get_user_by_id(user_id)
        if user and await self._is_last_admin(user):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Can't delete the only active admin"
            )
        return await self.user_repo.delete_user(user_id)

    async def _is_last_admin(self, user: User) -> bool:
        """Whether removing this user would leave no active superuser (#29)."""
        if not user.is_superuser:
            return False
        admins = await self.user_repo.list_users(
            limit=2, filters={"is_superuser": True, "status": UserStatus.ACTIVE.value}
        )
        return not any(admin.id != user.id for admin in admins)

    async def list_users(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Dict[str, Any] = None
    ) -> List[UserResponse]:
        users = await self.user_repo.list_users(skip, limit, filters)
        return [self._user_to_response(user) for user in users]

    async def change_password(self, user_id: int, current_password: str, new_password: str) -> bool:
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return False

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        # Hash new password and update. This must go through set_password:
        # UserUpdate has no password field, so update_user() would drop it.
        new_hashed_password = auth_manager.hash_password(new_password)
        return await self.user_repo.set_password(user_id, new_hashed_password)

    async def verify_user(self, user_id: int) -> Optional[UserResponse]:
        """Mark a user verified and active without a token (admin action)."""
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return None

        # Must go through set_verified: UserUpdate has no is_verified field, so
        # update_user() would silently drop it.
        updated_user = await self.user_repo.set_verified(
            user_id, is_verified=True, status=UserStatus.ACTIVE.value
        )
        return self._user_to_response(updated_user)

    async def send_verification_email(
        self,
        user_id: int,
        verification_url_template: str = None
    ) -> bool:
        """Issue and send a verification link for a known user id."""
        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            return False
        return await self._send_verification_email(user, verification_url_template)

    async def resend_verification_email(
        self,
        request_data: EmailVerificationResend,
        verification_url_template: str = None
    ) -> bool:
        """Send a fresh verification link to an email address.

        Always returns True, whether or not the address belongs to an account,
        so the endpoint cannot be used to enumerate registered emails.
        """
        user = await self.user_repo.get_user_by_email(request_data.email)
        if not user:
            return True

        # Nothing to do for an already verified address, and re-issuing a token
        # would let anyone invalidate a verified user's state.
        if user.is_verified:
            return True

        await self._send_verification_email(user, verification_url_template)
        return True

    async def verify_email(self, confirm_data: EmailVerificationConfirm) -> UserResponse:
        """Consume an email verification token and mark the user verified.

        Raises:
            HTTPException: if the token is unknown, already used or expired.
        """
        token_hash = hash_token(confirm_data.token)
        verification_token = await self.user_repo.get_email_verification_token(token_hash)

        if not verification_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification token"
            )

        if verification_token.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification token has already been used"
            )

        if datetime.utcnow() > verification_token.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification token has expired"
            )

        user = await self.user_repo.get_user_by_id(verification_token.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Promote a pending signup to active only when configured to do so, so
        # projects that also want an admin approval step keep it.
        config = get_verification_config()
        new_status = None
        if config.auto_activate_on_verify and user.status == UserStatus.PENDING.value:
            new_status = UserStatus.ACTIVE.value

        updated_user = await self.user_repo.set_verified(
            user.id, is_verified=True, status=new_status
        )

        # Burn the token, then drop any others so a link cannot be replayed.
        await self.user_repo.mark_verification_token_as_used(token_hash)
        await self.user_repo.delete_user_verification_tokens(user.id)

        return self._user_to_response(updated_user)

    async def get_user_permissions(self, user_id: int) -> List[str]:
        return await self.user_repo.get_user_permissions(user_id)

    async def request_password_reset(
        self,
        request_data: PasswordResetRequest,
        reset_url_template: str = None
    ) -> bool:
        """
        Request a password reset for a user.

        Args:
            request_data: Password reset request with user email
            reset_url_template: URL template for reset link (e.g., "https://app.com/reset?token={token}")

        Returns:
            Always returns True to prevent email enumeration
        """
        # Look up user by email
        user = await self.user_repo.get_user_by_email(request_data.email)

        # Always return True even if user doesn't exist (prevent email enumeration)
        if not user:
            return True

        config = get_verification_config()

        # Generate secure random token
        reset_token = generate_token()

        expires_at = datetime.utcnow() + timedelta(
            hours=config.password_reset_token_ttl_hours
        )

        # Delete any existing reset tokens for this user
        await self.user_repo.delete_user_reset_tokens(user.id)

        # Store only the digest - the raw token goes out by email and is never
        # persisted, so a database dump yields no usable reset link.
        await self.user_repo.create_password_reset_token(
            user_id=user.id,
            token_hash=hash_token(reset_token),
            expires_at=expires_at
        )

        # Send reset email
        try:
            email_service = get_email_service()
            await email_service.send_password_reset_email(
                recipient_email=user.email,
                reset_token=reset_token,
                reset_url_template=reset_url_template
            )
        except Exception as e:
            # Log error but don't expose it to prevent information leakage
            logger.error(f"Failed to send password reset email: {e}")

        return True

    async def confirm_password_reset(self, confirm_data: PasswordResetConfirm) -> bool:
        """
        Confirm password reset with token and set new password.

        Args:
            confirm_data: Password reset confirmation with token and new password

        Returns:
            True if password was reset successfully

        Raises:
            HTTPException: If token is invalid, expired, or already used
        """
        # Look the token up by digest; only the digest is stored.
        token_hash = hash_token(confirm_data.token)
        reset_token = await self.user_repo.get_password_reset_token(token_hash)

        if not reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired reset token"
            )

        # Check if token is already used
        if reset_token.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has already been used"
            )

        # Check if token is expired
        if datetime.utcnow() > reset_token.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired"
            )

        # Get the user
        user = await self.user_repo.get_user_by_id(reset_token.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Hash new password
        auth_manager = get_auth_manager()
        new_hashed_password = auth_manager.hash_password(confirm_data.new_password)

        # Update user's password through the repository rather than reaching
        # into its session, so non-SQLAlchemy repositories work too.
        await self.user_repo.set_password(user.id, new_hashed_password)

        # The reset link reached only this inbox, which is the same proof a
        # verification link gives (#24). Mark the address verified, but leave
        # status alone: unlike verify_email(), a reset must never get around
        # an admin-approval step.
        if not user.is_verified:
            await self.user_repo.set_verified(user.id, is_verified=True)
            await self.user_repo.delete_user_verification_tokens(user.id)

        # Burn the token, then drop any others so a link cannot be replayed.
        await self.user_repo.mark_token_as_used(token_hash)
        await self.user_repo.delete_user_reset_tokens(user.id)

        return True

    # Email change (#41). A request sends a confirm link to the new address and
    # a cancel link to the old one. Confirming applies the change and sends the
    # old address a revert link. Cancel and revert both force a password reset:
    # a request needs the current password, so a change the owner didn't make
    # means someone else has it.

    _PENDING_EMAIL_CHANGE = [
        EmailChangeTokenPurpose.CONFIRM.value, EmailChangeTokenPurpose.CANCEL.value
    ]

    async def request_email_change(self, user_id: int, request_data: EmailChangeRequest) -> bool:
        """Start an email change for a logged-in user.

        Nothing changes on the account yet. Any earlier pending request is
        replaced, but a live revert link from an earlier change is kept, so a
        second change can't take away the owner's way back.

        Raises:
            HTTPException: 403 if email change is off, 400 if the password is
                wrong or the address is the current one or already taken.
        """
        config = get_verification_config()
        if not config.allow_email_change:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email change is not enabled"
            )

        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(request_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )

        new_email = request_data.new_email
        if new_email == user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="That is already your email address"
            )
        if await self.user_repo.get_user_by_email(new_email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        expires_at = datetime.utcnow() + timedelta(hours=config.verification_token_ttl_hours)
        await self.user_repo.delete_user_email_change_tokens(
            user.id, purposes=self._PENDING_EMAIL_CHANGE
        )
        confirm_token = await self._issue_email_change_token(
            user.id, EmailChangeTokenPurpose.CONFIRM, user.email, new_email, expires_at
        )
        cancel_token = await self._issue_email_change_token(
            user.id, EmailChangeTokenPurpose.CANCEL, user.email, new_email, expires_at
        )

        try:
            email_service = get_email_service()
            await email_service.send_email_change_confirmation(
                recipient_email=new_email,
                confirm_link=self._email_change_link("confirm", confirm_token),
                ttl_hours=config.verification_token_ttl_hours
            )
            await email_service.send_email_change_requested_notice(
                recipient_email=user.email,
                new_email=new_email,
                cancel_link=self._email_change_link("cancel", cancel_token)
            )
        except Exception as e:
            logger.error(f"Failed to send email change emails: {e}")

        return True

    async def confirm_email_change(self, action_data: EmailChangeTokenAction) -> UserResponse:
        """Apply a pending email change, using the token sent to the new address.

        Raises:
            HTTPException: if the token is not a live confirm token, the account
                has changed address since, or the new address was taken meanwhile.
        """
        token_hash, change = await self._redeem_email_change_token(
            action_data.token, EmailChangeTokenPurpose.CONFIRM
        )

        user = await self.user_repo.get_user_by_id(change.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        # A change requested from an address the account no longer has is stale.
        if user.email != change.old_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired email change token"
            )
        # Checked again here: someone may have registered the address since.
        if await self.user_repo.get_user_by_email(change.new_email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )

        await self.user_repo.update_user(user.id, UserUpdate(email=change.new_email))
        # The link reached the new inbox, which proves control of it.
        updated_user = await self.user_repo.set_verified(user.id, is_verified=True)

        await self.user_repo.mark_email_change_token_as_used(token_hash)
        await self.user_repo.delete_user_email_change_tokens(
            user.id, purposes=self._PENDING_EMAIL_CHANGE
        )
        await self.user_repo.delete_user_reset_tokens(user.id)
        await self.user_repo.delete_user_verification_tokens(user.id)

        config = get_verification_config()
        revert_token = await self._issue_email_change_token(
            user.id, EmailChangeTokenPurpose.REVERT, change.old_email, change.new_email,
            datetime.utcnow() + timedelta(days=config.email_change_revert_ttl_days)
        )
        try:
            email_service = get_email_service()
            await email_service.send_email_change_completed_notice(
                recipient_email=change.old_email,
                new_email=change.new_email,
                revert_link=self._email_change_link("revert", revert_token),
                ttl_days=config.email_change_revert_ttl_days
            )
        except Exception as e:
            logger.error(f"Failed to send email change notice: {e}")

        return self._user_to_response(updated_user)

    async def cancel_email_change(
        self, action_data: EmailChangeTokenAction, reset_url_template: str = None
    ) -> bool:
        """Stop a pending email change, using the token sent to the old address.

        Also forces a password reset, sent to the account's address.
        """
        token_hash, change = await self._redeem_email_change_token(
            action_data.token, EmailChangeTokenPurpose.CANCEL
        )
        user = await self.user_repo.get_user_by_id(change.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        await self.user_repo.mark_email_change_token_as_used(token_hash)
        await self.user_repo.delete_user_email_change_tokens(
            user.id, purposes=self._PENDING_EMAIL_CHANGE
        )
        await self._force_password_reset(user.id, user.email, reset_url_template)
        return True

    async def revert_email_change(
        self, action_data: EmailChangeTokenAction, reset_url_template: str = None
    ) -> bool:
        """Put back the address an email change replaced, using the token sent to it.

        Invalidates every other outstanding token for the account and forces a
        password reset, sent to the restored address.

        Raises:
            HTTPException: 409 if another account has taken the old address since.
        """
        token_hash, change = await self._redeem_email_change_token(
            action_data.token, EmailChangeTokenPurpose.REVERT
        )
        user = await self.user_repo.get_user_by_id(change.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        if user.email != change.old_email:
            holder = await self.user_repo.get_user_by_email(change.old_email)
            if holder and holder.id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This address now belongs to another account. Contact an administrator."
                )
            await self.user_repo.update_user(user.id, UserUpdate(email=change.old_email))
        # The link reached the old inbox, which proves control of it.
        await self.user_repo.set_verified(user.id, is_verified=True)

        await self.user_repo.mark_email_change_token_as_used(token_hash)
        await self.user_repo.delete_user_email_change_tokens(user.id)
        await self.user_repo.delete_user_verification_tokens(user.id)
        await self._force_password_reset(user.id, change.old_email, reset_url_template)
        return True

    async def _issue_email_change_token(
        self, user_id: int, purpose: EmailChangeTokenPurpose,
        old_email: str, new_email: str, expires_at: datetime
    ) -> str:
        """Store the digest of a new email-change token and return the raw token."""
        raw_token = generate_token()
        await self.user_repo.create_email_change_token(
            user_id=user_id,
            token_hash=hash_token(raw_token),
            purpose=purpose.value,
            old_email=old_email,
            new_email=new_email,
            expires_at=expires_at
        )
        return raw_token

    async def _redeem_email_change_token(self, token: str, purpose: EmailChangeTokenPurpose):
        """Look up a live email-change token of the given purpose.

        A token of another purpose gets the same error as an unknown one, so a
        cancel link can't be used to confirm, and the error says nothing more.
        """
        token_hash = hash_token(token)
        change = await self.user_repo.get_email_change_token(token_hash)

        if not change or change.purpose != purpose.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired email change token"
            )
        if change.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email change token has already been used"
            )
        if datetime.utcnow() > change.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email change token has expired"
            )
        return token_hash, change

    async def _force_password_reset(self, user_id: int, email: str, reset_url_template: str = None) -> None:
        """Make the current password stop working, then send a reset link.

        The password is replaced with the hash of a random value nobody knows.
        Access tokens already issued keep working until they expire (#7).
        """
        auth_manager = get_auth_manager()
        await self.user_repo.set_password(user_id, auth_manager.hash_password(generate_token()))
        await self.request_password_reset(
            PasswordResetRequest(email=email), reset_url_template=reset_url_template
        )

    def _email_change_link(self, action: str, token: str) -> str:
        template = get_verification_config().email_change_url_template
        if template is None:
            return token
        return template.format(action=action, token=token)

    # Self-delete (#29). The account is deactivated at once and deleted for good
    # by purge_due_deletions() once its period ends: unconfirmed requests
    # account_deletion_unconfirmed_days after the request, confirmed ones
    # account_deletion_grace_days after confirming. Until then the keep or
    # restore link puts it back.

    async def request_account_deletion(self, user_id: int, request_data: AccountDeletionRequest) -> datetime:
        """Start deleting a logged-in user's own account. Returns the purge date.

        Raises:
            HTTPException: 403 if self-delete is off, 400 if the password is
                wrong, 409 if this is the only active admin.
        """
        config = self._require_self_delete()

        user = await self.user_repo.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        auth_manager = get_auth_manager()
        if not auth_manager.verify_password(request_data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        if await self._is_last_admin(user):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="You're the only active admin. Make someone else an admin before deleting your account."
            )

        # A request left behind when an admin reactivated the account
        stale = await self.user_repo.get_account_deletion(user.id)
        if stale:
            await self.user_repo.cancel_account_deletion(stale.id)

        now = datetime.utcnow()
        purge_at = now + timedelta(days=config.account_deletion_unconfirmed_days)
        confirm_token, keep_token = generate_token(), generate_token()
        await self.user_repo.create_account_deletion(
            user.id, requested_at=now, purge_at=purge_at,
            token_hashes={
                AccountDeletionTokenPurpose.CONFIRM.value: hash_token(confirm_token),
                AccountDeletionTokenPurpose.KEEP.value: hash_token(keep_token),
            }
        )

        try:
            email_service = get_email_service()
            await email_service.send_account_deletion_requested(
                recipient_email=user.email,
                confirm_link=self._account_deletion_link("confirm", confirm_token),
                keep_link=self._account_deletion_link("keep", keep_token),
                purge_at=purge_at
            )
        except Exception as e:
            logger.error(f"Failed to send account deletion email: {e}")

        return purge_at

    async def confirm_account_deletion(self, action_data: AccountDeletionTokenAction) -> datetime:
        """Confirm a deletion request. Starts the grace period; returns the purge date."""
        config = self._require_self_delete()
        deletion = await self._redeem_account_deletion_token(
            action_data.token, AccountDeletionTokenPurpose.CONFIRM
        )

        now = datetime.utcnow()
        purge_at = now + timedelta(days=config.account_deletion_grace_days)
        restore_token = generate_token()
        await self.user_repo.confirm_account_deletion(
            deletion.id, confirmed_at=now, purge_at=purge_at,
            restore_token_hash=hash_token(restore_token)
        )

        user = await self.user_repo.get_user_by_id(deletion.user_id)
        try:
            email_service = get_email_service()
            await email_service.send_account_deletion_confirmed(
                recipient_email=user.email,
                restore_link=self._account_deletion_link("restore", restore_token),
                purge_at=purge_at
            )
        except Exception as e:
            logger.error(f"Failed to send account deletion email: {e}")

        return purge_at

    async def keep_account(self, action_data: AccountDeletionTokenAction) -> bool:
        """Cancel an unconfirmed deletion request; the account is active again."""
        self._require_self_delete()
        deletion = await self._redeem_account_deletion_token(
            action_data.token, AccountDeletionTokenPurpose.KEEP
        )
        return await self._end_account_deletion(deletion)

    async def restore_account(self, action_data: AccountDeletionTokenAction) -> bool:
        """Cancel a confirmed deletion before the purge; the account is active again."""
        self._require_self_delete()
        deletion = await self._redeem_account_deletion_token(
            action_data.token, AccountDeletionTokenPurpose.RESTORE
        )
        return await self._end_account_deletion(deletion)

    async def purge_due_deletions(self, now: datetime = None, limit: int = 100) -> int:
        """Delete for good every account whose deletion period has ended.

        The app schedules this; the package has no scheduler. It's safe to run
        often and from more than one place. Each delete runs the on_user_delete
        hook. A delete that fails is logged and retried on the next run.
        Returns the number of accounts deleted.
        """
        now = now or datetime.utcnow()
        deleted = 0
        for deletion in await self.user_repo.list_due_account_deletions(now, limit=limit):
            user = await self.user_repo.get_user_by_id(deletion.user_id)
            if user is None:
                continue
            # An admin changed the account's status while it was pending: the
            # admin's decision wins, and the request is dropped
            if user.status != UserStatus.INACTIVE.value:
                await self.user_repo.cancel_account_deletion(deletion.id)
                continue

            email = user.email
            try:
                await self.user_repo.delete_user(user.id)
            except Exception as e:
                logger.error(f"Failed to purge account {user.id}: {e}")
                continue
            deleted += 1

            try:
                await get_email_service().send_account_deleted(email)
            except Exception as e:
                logger.error(f"Failed to send account deleted email: {e}")

        return deleted

    async def _end_account_deletion(self, deletion) -> bool:
        user = await self.user_repo.get_user_by_id(deletion.user_id)
        # Back to active only from the inactive state the request set. If an
        # admin suspended the account meanwhile, it stays suspended.
        new_status = UserStatus.ACTIVE.value if user.status == UserStatus.INACTIVE.value else None
        return await self.user_repo.cancel_account_deletion(deletion.id, status=new_status)

    def _require_self_delete(self):
        config = get_verification_config()
        if not config.allow_self_delete:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account deletion is not enabled"
            )
        return config

    async def _redeem_account_deletion_token(self, token: str, purpose: AccountDeletionTokenPurpose):
        """Look up a live account-deletion token of the given purpose, and its request.

        Tokens are removed once acted on, so an unknown, spent, or wrong-purpose
        token all get the same error.
        """
        found = await self.user_repo.get_account_deletion_token(hash_token(token))
        if not found or found.purpose != purpose.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired account deletion token"
            )
        if datetime.utcnow() > found.expires_at:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Account deletion token has expired"
            )
        return await self.user_repo.get_account_deletion_by_id(found.deletion_id)

    def _account_deletion_link(self, action: str, token: str) -> str:
        template = get_verification_config().account_deletion_url_template
        if template is None:
            return token
        return template.format(action=action, token=token)

    def _user_to_response(self, user: User) -> UserResponse:
        role_names = [role.name for role in user.roles] if user.roles else []
        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            status=user.status,
            is_superuser=user.is_superuser,
            is_verified=user.is_verified,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login,
            suspension_reason=user.suspension_reason,
            suspended_at=user.suspended_at,
            roles=role_names
        )

class RoleService:
    def __init__(self, role_repository: RoleRepository):
        self.role_repo = role_repository

    async def create_role(self, name: str, description: str = None, permissions: List[str] = None):
        existing_role = await self.role_repo.get_role_by_name(name)
        if existing_role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Role already exists"
            )

        return await self.role_repo.create_role(name, description, permissions)

    async def get_role_by_name(self, name: str):
        return await self.role_repo.get_role_by_name(name)

    async def list_roles(self):
        return await self.role_repo.list_roles()

    async def delete_role(self, role_id: int):
        return await self.role_repo.delete_role(role_id)

class PermissionService:
    def __init__(self, permission_repository: PermissionRepository):
        self.permission_repo = permission_repository

    async def create_permission(self, name: str, resource: str, action: str, description: str = None):
        existing_permission = await self.permission_repo.get_permission_by_name(name)
        if existing_permission:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Permission already exists"
            )

        return await self.permission_repo.create_permission(name, resource, action, description)

    async def list_permissions(self):
        return await self.permission_repo.list_permissions()

    async def delete_permission(self, permission_id: int):
        return await self.permission_repo.delete_permission(permission_id)