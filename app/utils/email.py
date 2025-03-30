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

# Mailtrap Configuration
# IMPORTANT: Use your actual Mailtrap *Sending* API token here.
# The token you provided (940...) might be a Sandbox token.
MAILTRAP_API_TOKEN = "94078df43c7a5f01fe7753a75587b7d2" # Directly using the provided token
SENDER_EMAIL = os.getenv("MAILTRAP_SENDER_EMAIL", "noreply@securitysystem.com")
SENDER_NAME = os.getenv("MAILTRAP_SENDER_NAME", "Adaptive Login Security System")

# Initialize Mailtrap Client
# Check if the token is set, otherwise log a warning.
# MAILTRAP_API_TOKEN = os.getenv("MAILTRAP_SENDING_TOKEN", "94078df43c7a5f01fe7753a75587b7d2") # Use env var or default
mailtrap_client = None # Initialize as None first
if not MAILTRAP_API_TOKEN:
    logger.error("MAILTRAP_API_TOKEN is not set. Email sending will be disabled.")
else:
    # Always try to initialize if a token is present
    logger.info(f"Initializing MailtrapClient with token: {...MAILTRAP_API_TOKEN[-4:]}") # Log last 4 chars for confirmation
    try:
        mailtrap_client = MailtrapClient(token=MAILTRAP_API_TOKEN)
        # Optionally add a check here if the SDK provides one, e.g., client.check_connection()
    except Exception as e:
        logger.error(f"Failed to initialize MailtrapClient: {e}. Email sending will be disabled.")
        mailtrap_client = None # Ensure it's None if initialization fails

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
    Send an email using the Mailtrap SDK.
    """
    if not mailtrap_client:
        logger.error("Mailtrap client is not initialized. MAILTRAP_SENDING_TOKEN might be missing or invalid.")
        # Fallback to logging in development/test environments
        logger.info(f"[Mailtrap SDK Disabled] Email would be sent to: {recipient_email}")
        logger.info(f"[Mailtrap SDK Disabled] Subject: {subject}")
        logger.info(f"[Mailtrap SDK Disabled] HTML Content: {html_content[:100]}...")
        return True # Or False depending on desired behavior when not configured
        
    logger.info(f"Attempting to send email via Mailtrap SDK to {recipient_email}")
    mail = Mail(
        sender=Address(email=SENDER_EMAIL, name=SENDER_NAME),
        to=[Address(email=recipient_email)], # Can add name if available
        subject=subject,
        text=text_content or "", # SDK requires text content
        html=html_content
        # Can add attachments, custom headers etc. here if needed
    )

    try:
        response = mailtrap_client.send(mail)
        # The SDK response structure might vary, check its documentation.
        # Assuming response indicates success if no exception is raised or based on a status field.
        # Example check (adjust based on actual SDK response):
        if hasattr(response, 'status_code') and response.status_code == 200: 
             logger.info(f"Email sent successfully to {recipient_email} via Mailtrap SDK.")
             return True
        elif response: # If response is truthy, assume success if no specific status code
             logger.info(f"Email sent successfully to {recipient_email} via Mailtrap SDK (response: {response}).")
             return True
        else:
             logger.error(f"Mailtrap SDK returned an unexpected response: {response}")
             return False

    except Exception as e:
        logger.error(f"Error sending email via Mailtrap SDK: {str(e)}")
        # Log essential info for debugging
        logger.info(f"[SDK Failure] Email would be sent to: {recipient_email}")
        logger.info(f"[SDK Failure] Subject: {subject}")
        return False # Indicate failure

def send_verification_email(background_tasks: BackgroundTasks, email: str) -> str:
    """
    Generate and send a verification code via email
    Returns the generated code (for development purposes)
    """
    # Generate a verification code
    code = generate_verification_code()
    
    # Store the code with expiration time
    store_verification_code(email, code)
    
    # Prepare email content
    subject = "Your Login Verification Code"
    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h2 style="color: #4F46E5;">Verification Code</h2>
                <p>Hello,</p>
                <p>Your verification code for logging in is:</p>
                <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
                    {code}
                </div>
                <p>This code will expire in 15 minutes.</p>
                <p>If you didn't request this code, please ignore this email or contact support if you have concerns.</p>
                <p>Thank you,<br>Adaptive Login Security System</p>
            </div>
        </body>
    </html>
    """
    
    text_content = f"""
    Verification Code
    
    Hello,
    
    Your verification code for logging in is: {code}
    
    This code will expire in 15 minutes.
    
    If you didn't request this code, please ignore this email or contact support if you have concerns.
    
    Thank you,
    Adaptive Login Security System
    """
    
    # Send email in background
    background_tasks.add_task(
        send_email,
        recipient_email=email,
        subject=subject,
        html_content=html_content,
        text_content=text_content
    )
    
    logger.info(f"Verification email queued for {email}")
    return code  # Return code for development purposes

async def send_mfa_code_email(recipient_email: str, code: str) -> bool:
    """Send the MFA enablement/verification code via email using the send_email function."""
    subject = "Your MFA Verification Code"
    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h2 style="color: #4F46E5;">MFA Verification Code</h2>
                <p>Hello,</p>
                <p>Please use the following code to verify and enable Multi-Factor Authentication for your account:</p>
                <div style="background-color: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; font-size: 24px; letter-spacing: 5px; font-weight: bold;">
                    {code}
                </div>
                <p>This code will expire in 5 minutes.</p>
                <p>If you did not request to enable MFA, please ignore this email or contact support.</p>
                <p>Thank you,<br>Adaptive Login Security System</p>
            </div>
        </body>
    </html>
    """
    text_content = f"Your MFA verification code is: {code}. It expires in 5 minutes."
    
    # Send synchronously for this flow (can be made async if needed)
    # The actual sending mechanism is now handled by the refactored send_email function
    return send_email(
        recipient_email=recipient_email,
        subject=subject,
        html_content=html_content,
        text_content=text_content
    ) 