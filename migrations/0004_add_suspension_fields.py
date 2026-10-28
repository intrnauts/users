"""Add the suspension fields, backing suspension with a reason (#48).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

users.users gets two nullable columns: suspension_reason, the optional reason
an admin gave, and suspended_at. Both are set while an account is suspended and
cleared when it leaves that status.

Existing rows are left as they are: accounts already suspended keep their
status, with no reason and no suspension time.

Revision ID: 0004_suspension_fields
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_suspension_fields"
down_revision = "0003_email_change_tokens"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.add_column(
        "users", sa.Column("suspension_reason", sa.Text(), nullable=True), schema=SCHEMA,
    )
    op.add_column(
        "users", sa.Column("suspended_at", sa.DateTime(), nullable=True), schema=SCHEMA,
    )

def downgrade() -> None:
    # Reasons are lost. Suspended accounts stay suspended.
    op.drop_column("users", "suspended_at", schema=SCHEMA)
    op.drop_column("users", "suspension_reason", schema=SCHEMA)
