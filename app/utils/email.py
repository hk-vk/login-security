import random
import string
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib # Use standard SMTP library
import os
from fastapi import BackgroundTasks

# Setup logging
logger = logging.getLogger(__name__)

# Store verification codes temporarily
verification_codes = {}

# --- Brevo SMTP Configuration --- 
# WARNING: Hardcoding credentials is insecure. Use environment variables.
BREVO_SMTP_HOST = "smtp-relay.brevo.com"
BREVO_SMTP_PORT = 587
BREVO_SMTP_LOGIN = "89329e001@smtp-brevo.com"
BREVO_SMTP_PASSWORD = "4XdVQTJzayhBD8qn"

# --- Sender Configuration --- 
# Using the specific sender email provided by the user.
# Ensure this email address is validated as a sender in your Brevo account.
SENDER_EMAIL = "harikrishnanvadakkumkarayil@gmail.com" # Hardcoded sender
# SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@yourdomain.com") # Previous env var logic
SENDER_NAME = os.getenv("SENDER_NAME", "Adaptive Login Security System")

def generate_verification_code(length=6) -> str:
    """Generate a random numerical verification code"""
    return ''.join(random.choices(string.digits, k=length))

def store_verification_code(email: str, code: str, expires_in_minutes=15) -> None:
    """Store verification code with expiration time"""
    verification_codes[email] = {
        "code": code,
        "expires_at": datetime.utcnow() + timedelta(minutes=expires_in_minutes)
    }
    logger.info(f"Verification code stored for {email}, expires in {expires_in_minutes} minutes")

def verify_code(email: str, code: str) -> bool:
    """Verify if the provided code is valid and not expired"""
    if email not in verification_codes:
        logger.warning(f"No verification code found for {email}")
        return False
    
    stored_data = verification_codes[email]
    if stored_data["expires_at"] < datetime.utcnow():
        logger.warning(f"Verification code for {email} has expired")
        del verification_codes[email]
        return False
    
    if stored_data["code"] != code:
        logger.warning(f"Invalid verification code for {email}")
        return False
    
    del verification_codes[email]
    logger.info(f"Verification code for {email} validated successfully")
    return True

def send_email(
    recipient_email: str,
    subject: str,
    html_content: str,
    text_content: Optional[str] = None
) -> bool:
    """
    Send an email using Brevo SMTP.
    """
    if not all([BREVO_SMTP_HOST, BREVO_SMTP_PORT, BREVO_SMTP_LOGIN, BREVO_SMTP_PASSWORD, SENDER_EMAIL]):
        logger.error("Brevo SMTP configuration is incomplete. Cannot send email.")
        return False

    logger.info(f"Attempting to send email via Brevo SMTP to {recipient_email}")
    
    # Create the email message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg['To'] = recipient_email
    
    # Attach parts
    if text_content:
        msg.attach(MIMEText(text_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))

    try:
        # Connect to Brevo SMTP server
        with smtplib.SMTP(BREVO_SMTP_HOST, BREVO_SMTP_PORT) as server:
            server.ehlo() # Greet server
            server.starttls() # Enable encryption
            server.ehlo() # Greet again after TLS
            logger.info(f"Logging into Brevo SMTP with user: {BREVO_SMTP_LOGIN}")
            server.login(BREVO_SMTP_LOGIN, BREVO_SMTP_PASSWORD)
            logger.info("SMTP login successful.")
            server.send_message(msg)
            logger.info(f"Email sent successfully to {recipient_email} via Brevo SMTP.")
        return True

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"Brevo SMTP Authentication Error: {auth_err}. Check credentials.")
        return False
    except Exception as e:
        logger.error(f"Error sending email via Brevo SMTP: {str(e)}", exc_info=True)
        return False

def send_verification_email(background_tasks: BackgroundTasks, email: str) -> str:
    """
    Generate and send a verification code via email
    Returns the generated code (for development purposes)
    """
    code = generate_verification_code()
    store_verification_code(email, code)
    subject = "Your Login Verification Code"
    html_content = f"""
    <html><body>
    <p>Your verification code is: <b>{code}</b></p>
    <p>It expires in 15 minutes.</p>
    </body></html>
    """
    text_content = f"Your verification code is: {code}. It expires in 15 minutes."
    
    background_tasks.add_task(
        send_email,
        recipient_email=email,
        subject=subject,
        html_content=html_content,
        text_content=text_content
    )
    logger.info(f"Verification email queued for {email}")
    return code

async def send_mfa_code_email(recipient_email: str, code: str) -> bool:
    """Send the MFA enablement code via email using the send_email function."""
    subject = "Your MFA Verification Code"
    html_content = f"""
    <html><body>
    <p>Your MFA verification code is: <b>{code}</b></p>
    <p>It expires in 5 minutes.</p>
    </body></html>
    """
    text_content = f"Your MFA verification code is: {code}. It expires in 5 minutes."
    
    # Use the refactored send_email function (now using Brevo)
    return send_email(
        recipient_email=recipient_email,
        subject=subject,
        html_content=html_content,
        text_content=text_content
    )

async def send_test_email(
    server: str,
    port: int,
    username: str,
    password: str,
    use_tls: bool,
    from_addr: str,
    from_name: str,
    to_addr: str
) -> bool:
    """
    Send a test email using the provided SMTP configuration.
    This function is used by the admin settings test functionality.
    """
    logger.info(f"Sending test email from {from_addr} to {to_addr} via {server}:{port}")
    
    # Create the email message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Test Email from Adaptive Login Security System"
    msg['From'] = f"{from_name} <{from_addr}>"
    msg['To'] = to_addr
    
    # Test email content
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #f7f7f7; border-radius: 5px; padding: 20px; border: 1px solid #ddd;">
            <h2 style="color: #4f46e5; margin-top: 0;">Email Configuration Test</h2>
            <p>This is a test email from your Adaptive Login Security System.</p>
            <p>If you're receiving this email, your SMTP settings are configured correctly.</p>
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            <p style="font-size: 12px; color: #777;">SMTP Server: {server}:{port}<br>
            From: {from_addr}<br>
            TLS: {'Enabled' if use_tls else 'Disabled'}</p>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    Email Configuration Test
    
    This is a test email from your Adaptive Login Security System.
    If you're receiving this email, your SMTP settings are configured correctly.
    
    --
    SMTP Server: {server}:{port}
    From: {from_addr}
    TLS: {'Enabled' if use_tls else 'Disabled'}
    """
    
    # Attach parts
    msg.attach(MIMEText(text_content, 'plain'))
    msg.attach(MIMEText(html_content, 'html'))

    try:
        # Connect to SMTP server
        with smtplib.SMTP(server, port) as smtp:
            smtp.ehlo()  # Greet server
            if use_tls:
                smtp.starttls()  # Enable encryption if TLS is enabled
                smtp.ehlo()  # Greet again after TLS
            logger.info(f"Logging into SMTP with user: {username}")
            if username and password:
                smtp.login(username, password)
            logger.info("SMTP login successful.")
            smtp.send_message(msg)
            logger.info(f"Test email sent successfully to {to_addr}.")
        return True

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error(f"SMTP Authentication Error: {auth_err}. Check credentials.")
        raise Exception(f"Authentication failed: {str(auth_err)}")
    except Exception as e:
        logger.error(f"Error sending test email: {str(e)}", exc_info=True)
        raise Exception(f"Failed to send test email: {str(e)}") 