# Handoff: email cannot be delivered by SMTP — the `users` package needs an HTTPS provider

**Written 2026-08-26 from dyner.z. Intended to be handed to the `intrnauts/users` package
project as a self-contained problem statement.** No prior context assumed.

---

## The ask, in one line

**The `users` package can only send email over SMTP, and SMTP is blocked at the network
level on the VPS that hosts every one of these projects. It needs a third provider that
sends over HTTPS.**

---

## Evidence

### 1. The application does everything right, and then the network refuses

Production log, `dynerz-be`, 2026-08-26 21:38:55 UTC, after a real password-reset request:

```
users.email_service - ERROR - Failed to send email via SMTP to <address>:
[Errno 101] Network is unreachable
```

The user was found, the reset token was minted and persisted, and the send was attempted.
Only the network leg failed.

### 2. Every SMTP port is blocked, outbound, from the host itself

Run on the Dokploy VPS (`ubuntu-s-2vcpu-4gb-nyc1-01`, a DigitalOcean droplet, NYC1):

```
$ nc -zv smtp.gmail.com 465
nc: connect to smtp.gmail.com (172.253.62.109) port 465 (tcp) failed: Connection timed out
nc: connect to smtp.gmail.com (2607:f8b0:4004:c07::6d) port 465 (tcp) failed: Network is unreachable

$ for p in 465 587 2525 25; do
    timeout 5 bash -c "</dev/tcp/smtp.gmail.com/$p" 2>/dev/null && echo "$p OPEN" || echo "$p blocked"
  done
465 blocked
587 blocked
2525 blocked
25 blocked
```

Two distinct failures in that first command, and the distinction matters:

- **IPv4 → `Connection timed out`.** Packets are silently dropped. This is egress
  filtering upstream of the machine, which is DigitalOcean's default anti-spam policy.
- **IPv6 → `Network is unreachable`.** The droplet has no IPv6 route. This is the
  `Errno 101` the application reported — but it is the *second* failure, not the cause.
  Fixing IPv6 would change the error message and nothing else.

This is from the **host**, not from inside a container, so it is not a Docker networking
problem and no container-level fix applies.

### 3. STARTTLS on 587 is not a way out

`users/email_service.py` uses `smtplib.SMTP_SSL(...)` unconditionally, so it only supports
implicit TLS on 465. Adding STARTTLS would be the obvious smaller fix — **but 587 is
blocked too**, so it buys nothing here.

---

## Why not just ask DigitalOcean to unblock it

It can be requested, and is often declined. But even if granted, mail would leave from a
shared droplet IP with no sending reputation, frequently present on consumer blocklists.
That produces delivery to spam — **a worse outcome than not sending, because it looks like
success**. A transactional provider owns IP reputation, SPF/DKIM signing and bounce
handling.

---

## What the package supports today

`users/email_service.py`:

```python
@dataclass
class EmailConfig:
    provider: str = "ses"        # 'ses' or 'smtp'
    sender_email: str = None
    sender_name: str = "User Management"
    enabled: bool = True
    aws_region: str = "us-east-1"
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 465
    smtp_username: str = None
    smtp_password: str = None
```

Both existing providers are unusable on this infrastructure: `smtp` is blocked, and `ses`
is not an option because AWS was fully decommissioned for these projects on 2026-04-12.

---

## What is needed

A third provider — e.g. `provider="http"` or a named one — that sends via an **outbound
HTTPS request**, which is not blocked and is how every project already reaches the outside
world.

### Constraints to preserve

The integration surface is already load-bearing in at least one consumer and should not
change shape:

- `configure_email_service(EmailConfig(...))` — the module-level singleton, called once at
  application startup. `get_email_service()` **raises** if it was never called.
- `send_password_reset_email(recipient_email, reset_token, reset_url_template)` — awaited.
- `send_verification_email(...)` — same shape, used by the registration flow.
- Failures must stay **non-fatal and logged**. The calling service already wraps sends in
  `try/except` and logs, which is the only reason the failure above was diagnosable at all.
  Please keep that property; the error text is the entire diagnostic surface.
- Async. Both send paths are `await`ed inside request handlers.

### Worth considering while you are in there

- **Configuration should fail loudly at startup, not silently at send time.** Today an
  unconfigured or unreachable service is only discovered when a user asks for a reset and
  nothing arrives.
- The provider will need **domain verification** (SPF/DKIM DNS records) to send as a custom
  domain such as `manzoor@dynerz.net`. That is DNS work in Cloudflare, not package work,
  but the package's config may want a place for an API key and a sending domain.

### Suggested providers

All are a single authenticated HTTPS POST:

| provider | note |
|---|---|
| **Resend** | simplest API, free tier comfortably covers password resets and verification |
| **Postmark** | strongest transactional deliverability; paid |
| **SendGrid / Mailgun** | established, more configuration surface |

---

## Who is affected

Every project on this VPS that uses the `users` package for email. Confirmed:

- **dyner.z** — password reset is fully wired and working up to the network boundary. It
  becomes functional the moment a working provider exists, with no further code change on
  the dyner.z side. Email verification is blocked behind the same wall, and verification is
  the only measure that would have stopped a set of bot signups seen on 2026-08-02/08.
- **microlearn** — ships `docs/auth-email-setup-guide.md`, a reusable guide for exactly this
  stack, describing SMTP configuration. It runs on the same droplet, so the same block
  applies. **Whether its email has ever actually delivered is unverified**, and there is no
  recollection of it working. That guide should carry a warning either way.

---

## Verifying the fix, from the outside

dyner.z exposes `GET /debug/email`, which reports configuration state as booleans without
revealing values. Useful for confirming a deployment picked up new settings.

⚠️ Do **not** trust `POST /debug/send-test-email` in dyner.z as a test: it calls an
`async def` without `await`, so it reports `"Test email sent successfully"` having sent
nothing. That is a dyner.z bug, noted here only so it is not mistaken for evidence.

---

## The general lesson worth carrying into the fix

Every failure in this chain reported success:

- the password-reset endpoint returns 200 regardless, deliberately, to prevent email
  enumeration
- the frontend then renders "Email Sent!"
- `/debug/send-test-email` reports success without sending
- and a documented setup guide described a flow that may never have delivered

**Delivery is the only evidence of delivery.** Whatever provider lands, it is worth having
one place that can answer "did the last send actually succeed" without needing to read
container logs.
