"""The on_user_delete hook (#49): the application's own cleanup, run inside
delete_user() in the same transaction, before the user row is deleted."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

import users.deletion as deletion_module
from users.deletion import configure_user_deletion
from users.models import EmailVerificationToken, User


@pytest.fixture(autouse=True)
def no_hook(monkeypatch):
    """Every test starts with no hook; whatever it registers is undone after."""
    monkeypatch.setattr(deletion_module, "_on_user_delete", None)


@pytest.fixture
def app_table(db_session):
    """An application table referencing users.id without ON DELETE CASCADE.

    It lives in the attached `users` database because SQLite can't enforce a
    foreign key across attached databases.
    """
    db_session.execute(text(
        "CREATE TABLE users.app_notes ("
        " id INTEGER PRIMARY KEY,"
        " user_id INTEGER NOT NULL REFERENCES users(id))"
    ))
    db_session.commit()


def note_count(test_db, user_id):
    # Read from a fresh session, so an uncommitted change can't pass
    fresh = test_db()
    try:
        return fresh.execute(
            text("SELECT COUNT(*) FROM users.app_notes WHERE user_id = :u"),
            {"u": user_id},
        ).scalar()
    finally:
        fresh.close()


def user_exists(test_db, user_id):
    fresh = test_db()
    try:
        return fresh.query(User).filter(User.id == user_id).first() is not None
    finally:
        fresh.close()


@pytest.mark.asyncio
class TestOnUserDelete:

    async def test_without_a_hook_delete_works_as_before(self, user_service, create_test_user, test_db):
        user = await create_test_user()

        assert await user_service.delete_user(user.id) is True
        assert not user_exists(test_db, user.id)

    async def test_hook_runs_once_with_the_session_and_user(self, user_service, create_test_user, db_session):
        user = await create_test_user()
        calls = []

        def hook(db, deleted):
            # The user row is still there while the hook runs
            calls.append((db, deleted.id, deleted.email))

        configure_user_deletion(on_user_delete=hook)
        await user_service.delete_user(user.id)

        assert calls == [(db_session, user.id, "test@example.com")]

    async def test_hook_cleanup_lets_the_delete_through(
        self, user_service, create_test_user, db_session, app_table, test_db
    ):
        user = await create_test_user()
        db_session.execute(text("INSERT INTO users.app_notes (user_id) VALUES (:u)"), {"u": user.id})
        db_session.commit()

        def hook(db, deleted):
            db.execute(text("DELETE FROM users.app_notes WHERE user_id = :u"), {"u": deleted.id})

        configure_user_deletion(on_user_delete=hook)

        assert await user_service.delete_user(user.id) is True
        assert not user_exists(test_db, user.id)
        assert note_count(test_db, user.id) == 0

    async def test_async_hook_is_awaited(self, user_service, create_test_user):
        user = await create_test_user()
        seen = []

        async def hook(db, deleted):
            seen.append(deleted.id)

        configure_user_deletion(on_user_delete=hook)
        await user_service.delete_user(user.id)

        assert seen == [user.id]

    async def test_failing_hook_deletes_nothing(
        self, user_service, user_repository, create_test_user, db_session, app_table, test_db
    ):
        user = await create_test_user()
        # A token row, which delete_user() removes before running the hook
        await user_repository.create_email_verification_token(
            user.id, "digest", datetime.utcnow() + timedelta(hours=1)
        )
        db_session.execute(text("INSERT INTO users.app_notes (user_id) VALUES (:u)"), {"u": user.id})
        db_session.commit()
        # Registration may have sent one too, so count rather than assume
        tokens_before = db_session.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id
        ).count()
        assert tokens_before >= 1

        def hook(db, deleted):
            # Its own write must be rolled back with everything else
            db.execute(text("DELETE FROM users.app_notes WHERE user_id = :u"), {"u": deleted.id})
            raise RuntimeError("cleanup failed")

        configure_user_deletion(on_user_delete=hook)

        with pytest.raises(RuntimeError, match="cleanup failed"):
            await user_service.delete_user(user.id)
        # An app that catches the error and commits the same session later
        # must not land half a delete
        db_session.commit()

        assert user_exists(test_db, user.id)
        assert note_count(test_db, user.id) == 1
        fresh = test_db()
        try:
            assert fresh.query(EmailVerificationToken).filter(
                EmailVerificationToken.user_id == user.id
            ).count() == tokens_before
        finally:
            fresh.close()

    async def test_configuring_none_removes_the_hook(self, user_service, create_test_user):
        user = await create_test_user()
        calls = []
        configure_user_deletion(on_user_delete=lambda db, u: calls.append(u.id))
        configure_user_deletion(None)

        await user_service.delete_user(user.id)

        assert calls == []
