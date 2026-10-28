"""A hook for the application's own cleanup when a user is deleted (#49).

The package deletes its own rows (the user and their tokens) but cannot see the
application's tables. An application whose rows reference users.id without
ON DELETE CASCADE, or that wants to keep some rows and anonymize them, registers
a callback here:

    def on_user_delete(db: Session, user: User) -> None:
        db.query(Review).filter(Review.user_id == user.id).update({"user_id": None})

    configure_user_deletion(on_user_delete=on_user_delete)

The callback runs inside delete_user(), in the same transaction, after the
user's tokens are removed and before the user row is. It may be a plain function
or a coroutine function. It must not commit: if it raises, the whole delete is
rolled back, its own writes included, and the exception propagates.
"""

import inspect
from typing import Any, Awaitable, Callable, Optional, Union

from sqlalchemy.orm import Session

from .models import User

OnUserDelete = Callable[[Session, User], Union[None, Awaitable[None]]]

# Global hook, None when the application registered nothing
_on_user_delete: Optional[OnUserDelete] = None

def configure_user_deletion(on_user_delete: Optional[OnUserDelete] = None) -> None:
    """Register the callback run before a user row is deleted.

    Passing None removes a previously registered callback.
    """
    global _on_user_delete
    _on_user_delete = on_user_delete

def get_on_user_delete() -> Optional[OnUserDelete]:
    """Get the registered callback, or None."""
    return _on_user_delete

async def run_on_user_delete(db: Session, user: User) -> None:
    """Run the registered callback, if any, awaiting it when it is async."""
    if _on_user_delete is None:
        return
    result: Any = _on_user_delete(db, user)
    if inspect.isawaitable(result):
        await result
