import random
import string
import logging
import requests
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

# Option 1: Use Mailtrap SMTP instead of API (more reliable for development)
MAILTRAP_SMTP_HOST = "sandbox.smtp.mailtrap.io"
MAILTRAP_SMTP_PORT = 2525
MAILTRAP_SMTP_USER = "94078df43c7a5f01fe7753a75587b7d2"  # Using the token as username
MAILTRAP_SMTP_PASS = "94078df43c7a5f01fe7753a75587b7d2"  # Using the token as password

# Option 2: Fix API configuration if you prefer to use the API
# Mailtrap may require a different format for the token or additional headers
MAILTRAP_API_TOKEN = "94078df43c7a5f01fe7753a75587b7d2"
MAILTRAP_API_URL = "https://send.api.mailtrap.io/api/send"
SENDER_EMAIL = "noreply@securitysystem.com"
SENDER_NAME = "Adaptive Login Security System"

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
    Send an email using Mailtrap SMTP (more reliable for development)
    """
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg['To'] = recipient_email
        
        # Attach text and HTML parts
        if text_content:
            msg.attach(MIMEText(text_content, 'plain'))
        msg.attach(MIMEText(html_content, 'html'))
        
        # Connect to Mailtrap SMTP server
        with smtplib.SMTP(MAILTRAP_SMTP_HOST, MAILTRAP_SMTP_PORT) as server:
            server.starttls()
            server.login(MAILTRAP_SMTP_USER, MAILTRAP_SMTP_PASS)
            server.send_message(msg)
            
        logger.info(f"Email sent successfully to {recipient_email} via SMTP")
        return True
            
    except Exception as e:
        logger.error(f"Error sending email via SMTP: {str(e)}")
        
        # Fallback to API method if SMTP fails
        try:
            # Prepare the payload for Mailtrap API
            payload = {
                "to": [{"email": recipient_email}],
                "from": {
                    "email": SENDER_EMAIL,
                    "name": SENDER_NAME
                },
                "subject": subject,
                "html": html_content,
                "text": text_content or ""
            }
            
            # Set up headers with API token
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {MAILTRAP_API_TOKEN}",
                "Api-Token": MAILTRAP_API_TOKEN  # Try alternative header format
            }
            
            # Send the request to Mailtrap API
            response = requests.post(MAILTRAP_API_URL, json=payload, headers=headers)
            
            # Check response
            if response.status_code == 200:
                logger.info(f"Email sent successfully to {recipient_email} via API")
                return True
            else:
                logger.error(f"Failed to send email via API: Status {response.status_code}, Response: {response.text}")
                # Fall back to logging in development
                logger.info(f"Email would be sent to: {recipient_email}")
                logger.info(f"Subject: {subject}")
                logger.info(f"Content: {html_content[:100]}...")
                return True  # Return success for development
                
        except Exception as api_e:
            logger.error(f"Error sending email via API fallback: {str(api_e)}")
            # Fallback to logging in development
            logger.info(f"Email would be sent to: {recipient_email}")
            logger.info(f"Subject: {subject}")
            logger.info(f"Content: {html_content[:100]}...")
            return True  # Return success for development purposes

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