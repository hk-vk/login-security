import random
import string
import logging
# import requests # No longer needed for sending
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
# from email.mime.text import MIMEText # No longer needed
# from email.mime.multipart import MIMEMultipart # No longer needed
# import smtplib # No longer needed
import os
from fastapi import BackgroundTasks
from mailtrap import Mail, Address, MailtrapClient # Import Mailtrap SDK components

# Setup logging
logger = logging.getLogger(__name__)

# Store verification codes temporarily (in a real app, use a database or Redis)
# Format: {email: {"code": "123456", "expires_at": datetime}}
verification_codes = {}

# --- Mailtrap Configuration --- 
# Using the specific token and sender from the user's example.
# WARNING: Hardcoding tokens is insecure. Use environment variables in production.
MAILTRAP_TOKEN = "38069ceb37f64b247b000bc121897652" # Hardcoded token from user example
SENDER_EMAIL = "hello@demomailtrap.co" # Hardcoded sender email from user example
SENDER_NAME = "Mailtrap Test" # Corrected sender name from user example

# --- Initialize Mailtrap Client --- 
mailtrap_client = None
try:
    if MAILTRAP_TOKEN:
        logger.info(f"Initializing MailtrapClient with token ending in: {MAILTRAP_TOKEN[-4:]}")
        mailtrap_client = MailtrapClient(token=MAILTRAP_TOKEN)
    else:
        # This case should not happen now with hardcoded token, but kept for safety
        logger.error("MAILTRAP_TOKEN is missing. Email sending disabled.") 
except Exception as e:
    logger.error(f"Failed to initialize MailtrapClient: {e}. Email sending disabled.")
    mailtrap_client = None # Ensure client is None if init fails

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
        # Clean up expired code
        del verification_codes[email]
        return False
    
    if stored_data["code"] != code:
        logger.warning(f"Invalid verification code for {email}")
        return False
    
    # Code is valid - clean up after successful verification
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
    Send an email using the Mailtrap SDK, following documentation examples.
    """
    if not mailtrap_client:
        logger.error("Mailtrap client is not initialized or failed to initialize. Cannot send email.")
        # Log essential info for debugging when client is not available
        logger.info(f"[Mailtrap Disabled] Would send to: {recipient_email}, Subject: {subject}")
        return False # Indicate failure clearly when client isn't ready
        
    logger.info(f"Attempting to send email via Mailtrap SDK to {recipient_email}")
    
    # Create Mail object as per documentation
    mail = Mail(
        sender=Address(email=SENDER_EMAIL, name=SENDER_NAME),
        to=[Address(email=recipient_email)],
        subject=subject,
        text=text_content or "Please enable HTML to view this email.", # Provide default text
        html=html_content
        # category="Your Category" # Optional: Add category if needed
        # attachments=[] # Optional: Add attachments if needed
        # headers={} # Optional: Add custom headers if needed
    )

    try:
        # Send using the initialized client
        response = mailtrap_client.send(mail)
        
        # Check response - Assuming success if no exception. 
        # The SDK might offer better ways to check success (e.g., response properties)
        # Logging the response might be helpful during debugging.
        logger.info(f"Mailtrap SDK send successful for {recipient_email}. Response: {response}")
        return True

    except Exception as e:
        # Log the specific error from the SDK
        logger.error(f"Error sending email via Mailtrap SDK: {str(e)}") 
        # Log context for debugging
        logger.info(f"[SDK Failure] Failed sending to: {recipient_email}, Subject: {subject}")
        return False # Indicate failure

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
    
    # Use the refactored send_email function
    return send_email(
        recipient_email=recipient_email,
        subject=subject,
        html_content=html_content,
        text_content=text_content
    ) 