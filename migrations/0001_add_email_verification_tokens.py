"""Add email verification tokens, and clear plaintext password reset tokens.

Copy this file into your project's alembic/versions/ directory and set
down_revision to your current head, then run `alembic upgrade head`.

Two things happen here:

1. users.email_verification_tokens is created, backing the signup verification
   flow.
2. users.password_reset_tokens is emptied. Reset tokens are now stored as
   SHA-256 digests, so the plaintext rows written by earlier versions can never
   match a lookup again. They are dead weight that still leaks a working reset
   link if the database is read, so they are deleted rather than left behind.
   Anyone mid-reset simply requests a new link.

Existing users keep is_verified = false. Leave require_verified_email off until
you have decided what to do with them - see the downgrade note below.

Revision ID: 0001_email_verification
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_email_verification"
down_revision = None  # set to your current head
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.create_table(
        "email_verification_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        # SHA-256 digest of the token, never the value emailed to the user.
        sa.Column("token", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_email_verification_tokens_id"),
        "email_verification_tokens", ["id"], unique=False, schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_email_verification_tokens_token"),
        "email_verification_tokens", ["token"], unique=True, schema=SCHEMA,
    )

    # Plaintext reset tokens are unusable under digest lookup and are a
    # standing liability. Drop them.
    op.execute(f"DELETE FROM {SCHEMA}.password_reset_tokens")

def downgrade() -> None:
    op.drop_index(
        op.f("ix_users_email_verification_tokens_token"),
        table_name="email_verification_tokens", schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_users_email_verification_tokens_id"),
        table_name="email_verification_tokens", schema=SCHEMA,
    )
    op.drop_table("email_verification_tokens", schema=SCHEMA)

    # Reset tokens issued after the upgrade are digests, which the old
    # plaintext lookup cannot match. Clear them so users get a clean error and
    # request a new link, rather than a token that silently never works.
    op.execute(f"DELETE FROM {SCHEMA}.password_reset_tokens")
