"""Give every account a scope, and make email and username unique per scope (#70).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

users.users gets a non-null column, scope, defaulting to "". Every existing
account lands in the default scope, so an app that doesn't use scopes sees no
change. The unique indexes on email and username become plain indexes, and
uniqueness moves to (scope, email) and (scope, username).

Required: the column is on the User model, so every user query fails without it.

Downgrading puts the global unique indexes back. It ABORTS, naming the
accounts, if any email or username is used in more than one scope, since those
can't all be kept under a global unique index.

Revision ID: 0007_user_scope
"""

from alembic import op
import sqlalchemy as sa

revision = "0007_user_scope"
down_revision = "0006_status_before_suspension"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("scope", sa.String(length=100), nullable=False, server_default=""),
        schema=SCHEMA,
    )
    for column in ("email", "username"):
        op.drop_index(f"ix_users_users_{column}", table_name="users", schema=SCHEMA)
        op.create_index(f"ix_users_users_{column}", "users", [column], unique=False, schema=SCHEMA)
        op.create_unique_constraint(
            f"uq_users_scope_{column}", "users", ["scope", column], schema=SCHEMA
        )

def downgrade() -> None:
    conn = op.get_bind()
    for column in ("email", "username"):
        shared = conn.execute(sa.text(f"""
            SELECT {column} AS value,
                   string_agg(id::text || ':' || quote_literal(scope), ', ' ORDER BY id) AS accounts
            FROM {SCHEMA}.users
            WHERE {column} IS NOT NULL
            GROUP BY {column}
            HAVING count(*) > 1
            ORDER BY {column}
        """)).fetchall()
        if shared:
            detail = "\n".join(f"  {row.value} <- {row.accounts}" for row in shared)
            raise RuntimeError(
                f"Cannot downgrade 0007: these {column}s are used in more than one "
                f"scope (id:scope).\n\n{detail}\n\n"
                "Delete or rename all but one of each, then run the downgrade again."
            )

    for column in ("email", "username"):
        op.drop_constraint(f"uq_users_scope_{column}", "users", type_="unique", schema=SCHEMA)
        op.drop_index(f"ix_users_users_{column}", table_name="users", schema=SCHEMA)
        op.create_index(f"ix_users_users_{column}", "users", [column], unique=True, schema=SCHEMA)
    op.drop_column("users", "scope", schema=SCHEMA)
