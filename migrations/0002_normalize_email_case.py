"""Lowercase and trim every stored email address.

Copy this file into your project's alembic/versions/ directory, set
down_revision to your current head, then run `alembic upgrade head`.

The package now stores and matches addresses in one canonical lowercase form.
Rows written by earlier versions may hold mixed case, and those users would no
longer be found at login or password reset - this backfill is what stops that.

If two accounts differ only by case, this migration ABORTS and names them
rather than half-applying. Deciding which of a user's two accounts survives is
not something a migration should guess at: merge or delete them, then re-run.

Revision ID: 0002_normalize_email_case
"""

from alembic import op
import sqlalchemy as sa

revision = "0002_normalize_email_case"
down_revision = "0001_email_verification"
branch_labels = None
depends_on = None

SCHEMA = "users"

def upgrade() -> None:
    conn = op.get_bind()

    collisions = conn.execute(sa.text(f"""
        SELECT lower(btrim(email)) AS canonical,
               count(*)            AS n,
               string_agg(id::text || ':' || email, ', ' ORDER BY id) AS accounts
        FROM {SCHEMA}.users
        GROUP BY lower(btrim(email))
        HAVING count(*) > 1
        ORDER BY canonical
    """)).fetchall()

    if collisions:
        detail = "\n".join(
            f"  {row.canonical} <- {row.n} accounts: {row.accounts}"
            for row in collisions
        )
        raise RuntimeError(
            "Cannot normalize email case: these addresses map to more than one "
            "account.\n\n"
            f"{detail}\n\n"
            "Merge or delete the duplicates, then run this migration again. "
            "Check which account owns the real data before deleting anything - "
            "a login, roles, or rows in your own tables keyed on the user id."
        )

    result = conn.execute(sa.text(f"""
        UPDATE {SCHEMA}.users
        SET email = lower(btrim(email))
        WHERE email <> lower(btrim(email))
    """))
    print(f"Normalized {result.rowcount} email address(es).")

def downgrade() -> None:
    # The original casing is not recoverable, and lowercase addresses remain
    # valid under the old case-sensitive lookup, so there is nothing to undo.
    pass
