"""Give every account a scope, and make email and username unique per scope (#70).

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

users.users gets a non-null column, scope, defaulting to "". Every existing
account lands in the default scope, so an app that doesn't use scopes sees no
change. The unique indexes on email and username become plain indexes, and
uniqueness moves to (scope, email) and (scope, username).

Required: the column is on the User model, so every user query fails without it.

The existing uniqueness on email and username is found by its column, not by
name (#83). A schema built by the package's create_all has unique indexes
named ix_users_users_email and ix_users_users_username; one built from raw SQL
may have a unique constraint such as users_email_key instead. Either is
dropped, and the plain ix_users_users_<column> index is created if it's missing.

Downgrading puts back global unique indexes named ix_users_users_email and
ix_users_users_username, whatever the schema had before. It ABORTS, naming the
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
COLUMNS = ("email", "username")

def _single_column_uniques(conn, column):
    """The unique constraints and unique indexes on users.users(column) alone.

    Returns (constraints, indexes) as lists of names. Indexes that back a
    constraint are left out, since dropping the constraint drops them.
    Expression and partial indexes aren't single-column uniqueness on the
    column, so they're left alone.
    """
    params = {"schema": SCHEMA, "column": column}
    constraints = conn.execute(sa.text("""
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attname = :column
        WHERE n.nspname = :schema AND t.relname = 'users'
          AND c.contype = 'u' AND c.conkey = ARRAY[a.attnum]
        ORDER BY c.conname
    """), params).scalars().all()
    indexes = conn.execute(sa.text("""
        SELECT ic.relname
        FROM pg_index i
        JOIN pg_class ic ON ic.oid = i.indexrelid
        JOIN pg_class t ON t.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attname = :column
        WHERE n.nspname = :schema AND t.relname = 'users'
          AND i.indisunique AND NOT i.indisprimary
          AND i.indnatts = 1 AND i.indkey[0] = a.attnum
          AND i.indpred IS NULL AND i.indexprs IS NULL
          AND NOT EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = i.indexrelid)
        ORDER BY ic.relname
    """), params).scalars().all()
    return constraints, indexes

def upgrade() -> None:
    conn = op.get_bind()
    op.add_column(
        "users",
        sa.Column("scope", sa.String(length=100), nullable=False, server_default=""),
        schema=SCHEMA,
    )
    for column in COLUMNS:
        constraints, indexes = _single_column_uniques(conn, column)
        for name in constraints:
            op.drop_constraint(name, "users", type_="unique", schema=SCHEMA)
        for name in indexes:
            op.drop_index(name, table_name="users", schema=SCHEMA)
        op.execute(
            f'CREATE INDEX IF NOT EXISTS "ix_users_users_{column}" ON {SCHEMA}.users ({column})'
        )
        op.create_unique_constraint(
            f"uq_users_scope_{column}", "users", ["scope", column], schema=SCHEMA
        )

def downgrade() -> None:
    conn = op.get_bind()
    for column in COLUMNS:
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

    for column in COLUMNS:
        op.drop_constraint(f"uq_users_scope_{column}", "users", type_="unique", schema=SCHEMA)
        op.execute(f'DROP INDEX IF EXISTS {SCHEMA}."ix_users_users_{column}"')
        op.create_index(f"ix_users_users_{column}", "users", [column], unique=True, schema=SCHEMA)
    op.drop_column("users", "scope", schema=SCHEMA)
