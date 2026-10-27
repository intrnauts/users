"""Add email change tokens, backing the self-service email change (#41).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

users.email_change_tokens is created. Each row is one token for one email
change: a confirm link sent to the new address, or a cancel or revert link
sent to the old one. Both addresses are stored on every row, so a revert can
put the old address back.

Nothing existing is changed. Email change stays off until an application sets
VerificationConfig.allow_email_change.

Revision ID: 0003_email_change_tokens
"""

from alembic import op
import sqlalchemy as sa

revision = "0003_email_change_tokens"
down_revision = "0002_normalize_email_case"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.create_table(
        "email_change_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        # SHA-256 digest of the token, never the value emailed to the user.
        sa.Column("token", sa.String(length=255), nullable=False),
        sa.Column("purpose", sa.String(length=20), nullable=False),
        sa.Column("old_email", sa.String(length=255), nullable=False),
        sa.Column("new_email", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"]),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_email_change_tokens_id"),
        "email_change_tokens", ["id"], unique=False, schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_email_change_tokens_token"),
        "email_change_tokens", ["token"], unique=True, schema=SCHEMA,
    )

def downgrade() -> None:
    # Pending changes and revert links are lost. Users keep whatever address
    # their account holds at the time.
    op.drop_index(
        op.f("ix_users_email_change_tokens_token"),
        table_name="email_change_tokens", schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_users_email_change_tokens_id"),
        table_name="email_change_tokens", schema=SCHEMA,
    )
    op.drop_table("email_change_tokens", schema=SCHEMA)
