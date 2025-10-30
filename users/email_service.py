from typing import Optional
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class EmailConfig:
    """Configuration for email service"""
    aws_region: str = "us-east-1"
    sender_email: str = None
    sender_name: str = "User Management"
    enabled: bool = True

class EmailService:
    """Email service using AWS SES"""

    def __init__(self, config: EmailConfig):
        self.config = config
        self._ses_client = None

        if not self.config.enabled:
            logger.warning("Email service is disabled")
            return

        if not self.config.sender_email:
            logger.warning("Sender email not configured - email service will not work")
            return

        try:
            import boto3
            self._ses_client = boto3.client('ses', region_name=config.aws_region)
            logger.info(f"Email service initialized with SES in region {config.aws_region}")
        except ImportError:
            logger.error("boto3 not installed - email service will not work")
        except Exception as e:
            logger.error(f"Failed to initialize SES client: {e}")

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

        if not self._ses_client:
            logger.error("SES client not initialized")
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
            logger.info(f"Password reset email sent to {recipient_email}. MessageId: {response['MessageId']}")
            return True
        except Exception as e:
            logger.error(f"Failed to send password reset email to {recipient_email}: {e}")
            return False

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

        if not self._ses_client:
            logger.error("SES client not initialized")
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
            logger.info(f"Verification email sent to {recipient_email}. MessageId: {response['MessageId']}")
            return True
        except Exception as e:
            logger.error(f"Failed to send verification email to {recipient_email}: {e}")
            return False

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
