"""Email change (#41): storage and configuration."""

from datetime import datetime, timedelta

import pytest

from users.models import EmailChangeToken, EmailChangeTokenPurpose
from users.verification import VerificationConfig, hash_token


def test_email_change_is_off_by_default():
    config = VerificationConfig()
    assert config.allow_email_change is False
    assert config.email_change_revert_ttl_days == 7


@pytest.mark.asyncio
class TestEmailChangeTokenStorage:
    async def _token(self, user_repository, user_id, raw="raw-token", **overrides):
        fields = dict(
            purpose=EmailChangeTokenPurpose.CONFIRM.value,
            old_email="test@example.com",
            new_email="new@example.com",
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        fields.update(overrides)
        return await user_repository.create_email_change_token(
            user_id, hash_token(raw), **fields
        )

    async def test_stores_a_digest_and_both_addresses(self, user_repository, create_test_user, db_session):
        user = await create_test_user()

        await self._token(user_repository, user.id, raw="raw-token")

        row = db_session.query(EmailChangeToken).one()
        assert row.token == hash_token("raw-token")
        assert row.token != "raw-token"
        assert row.purpose == "confirm"
        assert (row.old_email, row.new_email) == ("test@example.com", "new@example.com")
        assert row.used is False

    async def test_normalizes_both_addresses(self, user_repository, create_test_user):
        user = await create_test_user()

        token = await self._token(
            user_repository, user.id,
            old_email=" Test@Example.com ", new_email="NEW@example.COM",
        )

        assert (token.old_email, token.new_email) == ("test@example.com", "new@example.com")

    async def test_get_and_mark_used(self, user_repository, create_test_user):
        user = await create_test_user()
        await self._token(user_repository, user.id, raw="raw-token")

        found = await user_repository.get_email_change_token(hash_token("raw-token"))
        assert found is not None and found.user_id == user.id
        assert await user_repository.get_email_change_token("raw-token") is None

        assert await user_repository.mark_email_change_token_as_used(hash_token("raw-token")) is True
        assert (await user_repository.get_email_change_token(hash_token("raw-token"))).used is True
        assert await user_repository.mark_email_change_token_as_used(hash_token("missing")) is False

    async def test_delete_user_email_change_tokens_leaves_other_users_alone(self, user_repository, create_test_user, db_session):
        user = await create_test_user()
        other = await create_test_user(email="other@example.com", username="other")
        await self._token(user_repository, user.id, raw="a")
        await self._token(
            user_repository, user.id, raw="b",
            purpose=EmailChangeTokenPurpose.CANCEL.value,
        )
        await self._token(
            user_repository, other.id, raw="c", old_email="other@example.com",
        )

        await user_repository.delete_user_email_change_tokens(user.id)

        assert [t.user_id for t in db_session.query(EmailChangeToken).all()] == [other.id]

    async def test_delete_user_removes_their_email_change_tokens(self, user_service, user_repository, create_test_user, db_session):
        """The table references users with no ON DELETE CASCADE, like the others (#21)."""
        user = await create_test_user()
        await self._token(user_repository, user.id)

        assert await user_service.delete_user(user.id) is True

        assert await user_service.get_user_by_id(user.id) is None
        assert db_session.query(EmailChangeToken).count() == 0
