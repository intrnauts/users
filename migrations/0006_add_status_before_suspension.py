"""Remember the status an account had when it was suspended (#75).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

users.users gets one nullable column, status_before_suspension. It's set when
an account is suspended and cleared when it leaves that status, so
POST /users/{user_id}/reactivate puts the account back where it was instead of
always making it active.

Existing rows are left as they are: accounts already suspended have no recorded
status, and reactivating them makes them active, as before.

Revision ID: 0006_status_before_suspension
"""

from alembic import op
import sqlalchemy as sa

revision = "0006_status_before_suspension"
down_revision = "0005_account_deletions"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("status_before_suspension", sa.String(length=20), nullable=True),
        schema=SCHEMA,
    )

def downgrade() -> None:
    # Suspended accounts stay suspended; reactivating them makes them active again.
    op.drop_column("users", "status_before_suspension", schema=SCHEMA)
