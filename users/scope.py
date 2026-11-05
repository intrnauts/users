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

Email links can differ per scope too, e.g. one subdomain per tenant. Register a
function that returns the base URL for a scope, and give the URL templates as
paths starting with "/":

    configure_scope(enabled=True, base_url=lambda scope: f"https://{scope}.example.com")
    configure_verification(VerificationConfig(
        verification_url_template="/verify-email?token={token}"))

Every template that starts with "/" is prefixed with the base URL of the
account's scope: password reset, verification, email change and account
deletion. Absolute templates are used as they are.
"""

import inspect
from typing import Awaitable, Callable, Optional, Union

from fastapi import HTTPException, Request, status

DEFAULT_SCOPE = ""

# Longest scope value accepted: long enough for a UUID or a slug
SCOPE_MAX_LENGTH = 100

RequestScope = Callable[[Request], Union[Optional[str], Awaitable[Optional[str]]]]
BaseUrl = Callable[[str], Union[Optional[str], Awaitable[Optional[str]]]]

SCOPES_OFF_MESSAGE = "Scopes are not enabled"

# Off until the application turns them on
_enabled: bool = False
# Global hooks, None when the application registered nothing
_request_scope: Optional[RequestScope] = None
_base_url: Optional[BaseUrl] = None

def configure_scope(
    enabled: bool = True,
    request_scope: Optional[RequestScope] = None,
    base_url: Optional[BaseUrl] = None,
) -> None:
    """Turn scopes on or off, and register the functions that return a
    request's scope and a scope's base URL for email links.

    configure_scope() turns them on with neither function.
    configure_scope(enabled=False) turns them off and removes both.

    Raises:
        ValueError: if a function is given with enabled=False.
    """
    global _enabled, _request_scope, _base_url
    if (request_scope is not None or base_url is not None) and not enabled:
        raise ValueError("A request-scope or base-URL function needs scopes enabled")
    _enabled = enabled
    _request_scope = request_scope
    _base_url = base_url

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

async def scoped_template(template: Optional[str], scope: str) -> Optional[str]:
    """An email URL template, with the base URL of the scope in front if it's
    a path ("/...") (#70). Absolute templates and None come back unchanged.

    Raises:
        ValueError: for a path template when there is no base URL for the
            scope. The callers send email best effort, so this is logged and
            that email isn't sent.
    """
    if template is None or not template.startswith("/"):
        return template
    base = None
    if _enabled and _base_url is not None:
        base = _base_url(scope)
        if inspect.isawaitable(base):
            base = await base
    if not base:
        raise ValueError(
            f"The URL template {template!r} is a path, and there's no base URL for "
            f"scope {scope!r}. Register one with configure_scope(base_url=...)"
        )
    # The template is formatted afterwards, so braces in the base stay literal
    return base.rstrip("/").replace("{", "{{").replace("}", "}}") + template

def scope_of(user) -> str:
    """An account's scope. A custom repository's users may not have one."""
    return getattr(user, "scope", None) or DEFAULT_SCOPE
