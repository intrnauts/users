"""Add account deletions, backing self-service account deletion (#29).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

ONLY NEEDED IF YOU TURN SELF-DELETE ON (VerificationConfig.allow_self_delete).
Nothing else in the package reads these tables, so an app that leaves the
feature off can upgrade without this migration and run it later.

Two tables are created, and nothing existing is changed:

- users.account_deletions: one row per account whose owner asked to delete it,
  with when they asked, when they confirmed, and when it will be purged.
- users.account_deletion_tokens: the digests of the confirm, keep and restore
  links for each request.

Both reference their parent with ON DELETE CASCADE, so deleting a user (or a
request) removes its rows without the package touching these tables.

Revision ID: 0005_account_deletions
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_account_deletions"
down_revision = "0004_suspension_fields"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.create_table(
        "account_deletions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("requested_at", sa.DateTime(), nullable=False),
        sa.Column("confirmed_at", sa.DateTime(), nullable=True),
        sa.Column("purge_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], [f"{SCHEMA}.users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_account_deletions_id"),
        "account_deletions", ["id"], unique=False, schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_account_deletions_purge_at"),
        "account_deletions", ["purge_at"], unique=False, schema=SCHEMA,
    )
    op.create_table(
        "account_deletion_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("deletion_id", sa.Integer(), nullable=False),
        # SHA-256 digest of the token, never the value emailed to the user.
        sa.Column("token", sa.String(length=255), nullable=False),
        sa.Column("purpose", sa.String(length=20), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["deletion_id"], [f"{SCHEMA}.account_deletions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_account_deletion_tokens_id"),
        "account_deletion_tokens", ["id"], unique=False, schema=SCHEMA,
    )
    op.create_index(
        op.f("ix_users_account_deletion_tokens_token"),
        "account_deletion_tokens", ["token"], unique=True, schema=SCHEMA,
    )

def downgrade() -> None:
    # Pending deletions are lost. Their accounts stay inactive, and an admin
    # decides what happens to them.
    op.drop_index(
        op.f("ix_users_account_deletion_tokens_token"),
        table_name="account_deletion_tokens", schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_users_account_deletion_tokens_id"),
        table_name="account_deletion_tokens", schema=SCHEMA,
    )
    op.drop_table("account_deletion_tokens", schema=SCHEMA)
    op.drop_index(
        op.f("ix_users_account_deletions_purge_at"),
        table_name="account_deletions", schema=SCHEMA,
    )
    op.drop_index(
        op.f("ix_users_account_deletions_id"),
        table_name="account_deletions", schema=SCHEMA,
    )
    op.drop_table("account_deletions", schema=SCHEMA)
