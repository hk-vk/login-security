import random
import string
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import os
from fastapi import BackgroundTasks

# Setup logging
logger = logging.getLogger(__name__)

# Store verification codes temporarily (in a real app, use a database or Redis)
# Format: {email: {"code": "123456", "expires_at": datetime}}
verification_codes = {}

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
    Send an email to the specified recipient
    
    For development purposes, this logs the email instead of sending it.
    In production, you would configure SMTP settings.
    """
    # For development, just log the email
    logger.info(f"Email would be sent to: {recipient_email}")
    logger.info(f"Subject: {subject}")
    logger.info(f"Content: {html_content[:100]}...")
    
    # Uncomment in production with proper SMTP configuration
    # try:
    #     msg = MIMEMultipart('alternative')
    #     msg['Subject'] = subject
    #     msg['From'] = SMTP_FROM_EMAIL
    #     msg['To'] = recipient_email
    #     
    #     # Attach text and HTML versions
    #     if text_content:
    #         msg.attach(MIMEText(text_content, 'plain'))
    #     msg.attach(MIMEText(html_content, 'html'))
    #     
    #     # Send email via SMTP
    #     with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
    #         server.starttls()
    #         server.login(SMTP_USERNAME, SMTP_PASSWORD)
    #         server.send_message(msg)
    #     return True
    # except Exception as e:
    #     logger.error(f"Failed to send email: {str(e)}")
    #     return False
    
    # For development, always return success
    return True

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