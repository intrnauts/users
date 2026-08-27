from typing import Optional
import logging
from dataclasses import dataclass
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

@dataclass
class EmailConfig:
    """Configuration for email service"""
    provider: str = "ses"  # 'ses' or 'smtp'
    sender_email: str = None
    sender_name: str = "User Management"
    enabled: bool = True

    # AWS SES settings
    aws_region: str = "us-east-1"

    # HTTPS API settings (provider="resend")
    #
    # SMTP is blocked outbound on the VPS that hosts these projects, and SES means
    # an AWS account this estate no longer has, so an HTTPS provider is the only
    # path that reaches the outside world (#15).
    api_key: Optional[str] = None
    api_base_url: str = "https://api.resend.com"
    # A send happens inside a request handler. Without a timeout a hung provider
    # would hold the worker open for the socket default, turning an undelivered
    # email into a slow endpoint.
    timeout_seconds: float = 10.0

    # SMTP settings (for Gmail, etc.)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 465  # SSL port
    smtp_username: str = None  # Usually same as sender_email
    smtp_password: str = None  # Gmail App Password

class EmailService:
    """Email service supporting AWS SES and SMTP (Gmail, etc.)"""

    def __init__(self, config: EmailConfig):
        self.config = config
        self._ses_client = None

        if not self.config.enabled:
            logger.warning("Email service is disabled")
            return

        if not self.config.sender_email:
            logger.warning("Sender email not configured - email service will not work")
            return

        # Initialize based on provider
        if config.provider == "ses":
            try:
                import boto3
                self._ses_client = boto3.client('ses', region_name=config.aws_region)
                logger.info(f"Email service initialized with SES in region {config.aws_region}")
            except ImportError:
                logger.error("boto3 not installed - email service will not work")
            except Exception as e:
                logger.error(f"Failed to initialize SES client: {e}")

        elif config.provider == "smtp":
            if not config.smtp_username or not config.smtp_password:
                logger.warning("SMTP username/password not configured - email service will not work")
            else:
                logger.info(f"Email service initialized with SMTP ({config.smtp_host}:{config.smtp_port})")

        elif config.provider == "resend":
            # Report both faults at startup rather than at first send. An
            # undelivered email is discovered by a user who never receives it,
            # which is a terrible place to learn the API key was missing.
            if not config.api_key:
                logger.error("Resend API key not configured - email service will not work")
            try:
                import httpx  # noqa: F401
                if config.api_key:
                    logger.info(f"Email service initialized with Resend ({config.api_base_url})")
            except ImportError:
                logger.error(
                    "httpx not installed - email service will not work. "
                    "Install the extra: pip install 'users[resend]'"
                )

        else:
            logger.error(f"Unknown email provider: {config.provider}")

    def _send_via_smtp(self, recipient_email: str, subject: str, body_text: str, body_html: str) -> bool:
        """Send email via SMTP (Gmail, etc.)"""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.sender_name} <{self.config.sender_email}>"
            msg['To'] = recipient_email

            # Attach both plain text and HTML versions
            part1 = MIMEText(body_text, 'plain')
            part2 = MIMEText(body_html, 'html')
            msg.attach(part1)
            msg.attach(part2)

            # Send via SMTP
            with smtplib.SMTP_SSL(self.config.smtp_host, self.config.smtp_port) as server:
                server.login(self.config.smtp_username, self.config.smtp_password)
                server.send_message(msg)

            logger.info(f"Email sent via SMTP to {recipient_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email via SMTP to {recipient_email}: {e}")
            return False

    def _send_via_ses(self, recipient_email: str, subject: str, body_text: str, body_html: str) -> bool:
        """Send email via AWS SES"""
        try:
            response = self._ses_client.send_email(
                Source=f"{self.config.sender_name} <{self.config.sender_email}>",
                Destination={
                    'ToAddresses': [recipient_email]
                },
                Message={
                    'Subject': {
                        'Data': subject,
                        'Charset': 'UTF-8'
                    },
                    'Body': {
                        'Text': {
                            'Data': body_text,
                            'Charset': 'UTF-8'
                        },
                        'Html': {
                            'Data': body_html,
                            'Charset': 'UTF-8'
                        }
                    }
                }
            )
            logger.info(f"Email sent via SES to {recipient_email}. MessageId: {response['MessageId']}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email via SES to {recipient_email}: {e}")
            return False

    async def _send_via_resend(
        self, recipient_email: str, subject: str, body_text: str, body_html: str
    ) -> bool:
        """Send via Resend's HTTPS API.

        This is the only provider that is genuinely async — SES and SMTP both block
        the event loop, which they always have. Kept that way deliberately: making
        them async too would be a behaviour change to paths this issue is not about.
        """
        try:
            import httpx
        except ImportError:
            logger.error(
                "httpx not installed - cannot send via Resend. "
                "Install the extra: pip install 'users[resend]'"
            )
            return False

        payload = {
            "from": f"{self.config.sender_name} <{self.config.sender_email}>",
            "to": [recipient_email],
            "subject": subject,
            "text": body_text,
            "html": body_html,
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(
                    f"{self.config.api_base_url.rstrip('/')}/emails",
                    headers={
                        "Authorization": f"Bearer {self.config.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )

            if response.status_code >= 400:
                # The body carries the actual reason (unverified domain, bad key,
                # rate limit). Logging only the status would strip the one detail
                # that makes the failure actionable.
                logger.error(
                    f"Failed to send email via Resend to {recipient_email}: "
                    f"HTTP {response.status_code} {response.text[:500]}"
                )
                return False

            message_id = ""
            try:
                message_id = response.json().get("id", "")
            except ValueError:
                pass  # a 2xx with an unparseable body still means it was accepted

            logger.info(f"Email sent via Resend to {recipient_email}. MessageId: {message_id}")
            return True

        except Exception as e:
            # Non-fatal by contract: the caller logs and carries on, and this text
            # is the entire diagnostic surface when mail silently fails to arrive.
            logger.error(f"Failed to send email via Resend to {recipient_email}: {e}")
            return False

    def _readiness_error(self) -> Optional[str]:
        """Return why this service cannot send, or None if it can.

        Extracted because the same checks were duplicated across both send methods;
        a third provider would have meant four more near-identical branches.
        """
        if self.config.provider == "ses" and not self._ses_client:
            return "SES client not initialized"
        if self.config.provider == "smtp" and (
            not self.config.smtp_username or not self.config.smtp_password
        ):
            return "SMTP credentials not configured"
        if self.config.provider == "resend" and not self.config.api_key:
            return "Resend API key not configured"
        if self.config.provider not in ("ses", "smtp", "resend"):
            return f"Unknown email provider: {self.config.provider}"
        return None

    async def _dispatch(
        self, recipient_email: str, subject: str, body_text: str, body_html: str
    ) -> bool:
        """Route one message to the configured provider."""
        if self.config.provider == "resend":
            return await self._send_via_resend(recipient_email, subject, body_text, body_html)
        if self.config.provider == "ses":
            return self._send_via_ses(recipient_email, subject, body_text, body_html)
        if self.config.provider == "smtp":
            return self._send_via_smtp(recipient_email, subject, body_text, body_html)
        logger.error(f"Unknown email provider: {self.config.provider}")
        return False

    async def send_password_reset_email(
        self,
        recipient_email: str,
        reset_token: str,
        reset_url_template: str = None
    ) -> bool:
        """
        Send password reset email to user.

        Args:
            recipient_email: Email address to send to
            reset_token: Password reset token
            reset_url_template: URL template with {token} placeholder.
                               If None, just sends the token.

        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.config.enabled:
            logger.info(f"Email service disabled - would send reset token to {recipient_email}: {reset_token}")
            return True

        # Check if email service is properly configured
        readiness_error = self._readiness_error()
        if readiness_error:
            logger.error(readiness_error)
            return False

        # Construct reset URL or use token directly
        if reset_url_template:
            reset_link = reset_url_template.format(token=reset_token)
        else:
            reset_link = reset_token

        # Email subject
        subject = "Password Reset Request"

        # Email body (plain text)
        body_text = f"""
Hello,

You requested to reset your password. Please use the following to reset your password:

{reset_link}

This link will expire in 1 hour.

If you did not request this password reset, please ignore this email.

Best regards,
{self.config.sender_name}
"""

        # Email body (HTML)
        body_html = f"""
<html>
<head></head>
<body>
  <h2>Password Reset Request</h2>
  <p>Hello,</p>
  <p>You requested to reset your password. Please click the link below to reset your password:</p>
  <p><a href="{reset_link}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
  <p>Or copy and paste this link into your browser:</p>
  <p>{reset_link}</p>
  <p>This link will expire in <strong>1 hour</strong>.</p>
  <p>If you did not request this password reset, please ignore this email.</p>
  <p>Best regards,<br>{self.config.sender_name}</p>
</body>
</html>
"""

        return await self._dispatch(recipient_email, subject, body_text, body_html)

    async def send_verification_email(
        self,
        recipient_email: str,
        verification_token: str,
        verification_url_template: str = None
    ) -> bool:
        """
        Send email verification to user.

        Args:
            recipient_email: Email address to send to
            verification_token: Email verification token
            verification_url_template: URL template with {token} placeholder

        Returns:
            True if email sent successfully, False otherwise
        """
        if not self.config.enabled:
            logger.info(f"Email service disabled - would send verification token to {recipient_email}: {verification_token}")
            return True

        # Check if email service is properly configured
        readiness_error = self._readiness_error()
        if readiness_error:
            logger.error(readiness_error)
            return False

        # Construct verification URL or use token directly
        if verification_url_template:
            verification_link = verification_url_template.format(token=verification_token)
        else:
            verification_link = verification_token

        subject = "Verify Your Email Address"

        body_text = f"""
Hello,

Thank you for signing up! Please verify your email address by using the following link:

{verification_link}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Best regards,
{self.config.sender_name}
"""

        body_html = f"""
<html>
<head></head>
<body>
  <h2>Verify Your Email Address</h2>
  <p>Hello,</p>
  <p>Thank you for signing up! Please click the link below to verify your email address:</p>
  <p><a href="{verification_link}" style="padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
  <p>Or copy and paste this link into your browser:</p>
  <p>{verification_link}</p>
  <p>This link will expire in <strong>24 hours</strong>.</p>
  <p>If you did not create an account, please ignore this email.</p>
  <p>Best regards,<br>{self.config.sender_name}</p>
</body>
</html>
"""

        return await self._dispatch(recipient_email, subject, body_text, body_html)

# Global email service instance
_email_service: Optional[EmailService] = None

def get_email_service() -> EmailService:
    """Get the configured email service instance"""
    if _email_service is None:
        raise RuntimeError(
            "Email service not configured. Call configure_email_service() first."
        )
    return _email_service

def configure_email_service(config: EmailConfig) -> EmailService:
    """Configure the global email service instance"""
    global _email_service
    _email_service = EmailService(config)
    return _email_service
