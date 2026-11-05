"""Scopes: separate sets of accounts in one database (#70).

Every account belongs to exactly one scope, a string. Email and username are
unique within a scope, so the same address can hold one account in each. An
app that doesn't use scopes never sees them: every account is in the default
scope, "".

The public flows (register, login, password reset, resending verification)
take the scope from the request body's optional `scope` field. Login puts the
account's scope in the token, and every authenticated request after that is
for the token's scope.

An app may also tell the package which scope a request belongs to, for example
from its subdomain:

    def request_scope(request: Request) -> Optional[str]:
        host = request.headers.get("host", "")
        return host.split(".")[0] if host.endswith(".example.com") else None

    configure_scope(request_scope=request_scope)

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

# Global hook, None when the application registered nothing
_request_scope: Optional[RequestScope] = None

def configure_scope(request_scope: Optional[RequestScope] = None) -> None:
    """Register the function that returns a request's scope.

    Passing None removes a previously registered function.
    """
    global _request_scope
    _request_scope = request_scope

def get_request_scope_function() -> Optional[RequestScope]:
    """Get the registered function, or None."""
    return _request_scope

async def get_request_scope(request: Optional[Request]) -> Optional[str]:
    """The scope the app says this request belongs to, or None."""
    if _request_scope is None or request is None:
        return None
    result = _request_scope(request)
    if inspect.isawaitable(result):
        result = await result
    return result

async def resolve_scope(request: Optional[Request], body_scope: Optional[str]) -> str:
    """The scope a public flow acts in: the request's if the app gives one,
    else the body's, else the default.

    Raises:
        HTTPException: 400 if the body names a different scope from the request's.
    """
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
