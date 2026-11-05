"""Scopes: separate sets of accounts in one database (#70).

Every account belongs to exactly one scope, a string. Email and username are
unique within a scope, so the same address can hold one account in each.

Scopes are off until the app turns them on with configure_scope(). Off, every
account is in the default scope, "", and the package behaves as it did before
scopes: a request body or a UserCreate naming any other scope is refused with
400, so nobody can create a second account for an address.

The public flows (register, login, password reset, resending verification)
take the scope from the request body's optional `scope` field. Login puts the
account's scope in the token, and every authenticated request after that is
for the token's scope.

An app may also tell the package which scope a request belongs to, for example
from its subdomain:

    def request_scope(request: Request) -> Optional[str]:
        host = request.headers.get("host", "")
        return host.split(".")[0] if host.endswith(".example.com") else None

    configure_scope(enabled=True, request_scope=request_scope)

The function may be a plain function or a coroutine function. When it returns a
scope, a token for another scope is rejected, and a body `scope` that differs
is refused with 400. When it returns None, or no function is registered, the
body's scope (default "") and the token's scope stand.
"""

import inspect
from typing import Awaitable, Callable, Optional, Union

from fastapi import HTTPException, Request, status

DEFAULT_SCOPE = ""

# Longest scope value accepted: long enough for a UUID or a slug
SCOPE_MAX_LENGTH = 100

RequestScope = Callable[[Request], Union[Optional[str], Awaitable[Optional[str]]]]

SCOPES_OFF_MESSAGE = "Scopes are not enabled"

# Off until the application turns them on
_enabled: bool = False
# Global hook, None when the application registered nothing
_request_scope: Optional[RequestScope] = None

def configure_scope(enabled: bool = True, request_scope: Optional[RequestScope] = None) -> None:
    """Turn scopes on or off, and register the function that returns a
    request's scope.

    configure_scope() turns them on with no request-scope function.
    configure_scope(enabled=False) turns them off and removes the function.

    Raises:
        ValueError: if a request-scope function is given with enabled=False.
    """
    global _enabled, _request_scope
    if request_scope is not None and not enabled:
        raise ValueError("A request-scope function needs scopes enabled")
    _enabled = enabled
    _request_scope = request_scope

def scopes_enabled() -> bool:
    """Whether the application turned scopes on."""
    return _enabled

def check_scope_allowed(scope: Optional[str]) -> None:
    """Refuse a scope other than the default while scopes are off.

    Raises:
        HTTPException: 400 if scopes are off and scope names another scope.
    """
    if not _enabled and scope not in (None, DEFAULT_SCOPE):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=SCOPES_OFF_MESSAGE)

def get_request_scope_function() -> Optional[RequestScope]:
    """Get the registered function, or None."""
    return _request_scope

async def get_request_scope(request: Optional[Request]) -> Optional[str]:
    """The scope the app says this request belongs to, or None."""
    if not _enabled or _request_scope is None or request is None:
        return None
    result = _request_scope(request)
    if inspect.isawaitable(result):
        result = await result
    return result

async def resolve_scope(request: Optional[Request], body_scope: Optional[str]) -> str:
    """The scope a public flow acts in: the request's if the app gives one,
    else the body's, else the default.

    Raises:
        HTTPException: 400 if the body names a different scope from the
            request's, or names any scope but the default while scopes are off.
    """
    check_scope_allowed(body_scope)
    request_scope = await get_request_scope(request)
    if request_scope is None:
        return body_scope if body_scope is not None else DEFAULT_SCOPE
    if body_scope is not None and body_scope != request_scope:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scope doesn't match this request"
        )
    return request_scope

def scope_of(user) -> str:
    """An account's scope. A custom repository's users may not have one."""
    return getattr(user, "scope", None) or DEFAULT_SCOPE
