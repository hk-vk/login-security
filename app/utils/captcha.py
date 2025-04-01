import random
import string
from captcha.image import ImageCaptcha
from io import BytesIO

# Initialize ImageCaptcha with custom settings
image_captcha = ImageCaptcha(width=180, height=80)

def generate_captcha_text(length=6):
    """Generate random CAPTCHA text"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_captcha_image(text):
    """Generate CAPTCHA image from text"""
    image = image_captcha.generate(text)
    return BytesIO(image.read())

def verify_captcha(session_captcha, user_input):
    """Verify CAPTCHA input"""
    if not session_captcha or not user_input:
        return False
    return session_captcha.upper() == user_input.upper() 