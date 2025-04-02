import random
import string
from PIL import Image, ImageDraw, ImageFont
import io
import base64

def generate_captcha_text(length=6):
    """Generate random text for captcha"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_captcha_image(text):
    """Generate a captcha image from text"""
    # Create image with white background
    width = 200
    height = 80
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    try:
        # Try to use Arial font, fallback to default if not available
        font = ImageFont.truetype("arial.ttf", 36)
    except:
        font = ImageFont.load_default()
    
    # Calculate text size and position
    text_width = draw.textlength(text, font=font)
    text_height = 36
    x = (width - text_width) // 2
    y = (height - text_height) // 2
    
    # Add noise (random dots)
    for _ in range(1000):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        draw.point((x1, y1), fill='gray')
    
    # Add random lines
    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill='gray', width=1)
    
    # Draw text with slight random offset for each character
    for i, char in enumerate(text):
        char_x = x + (i * 30) + random.randint(-5, 5)
        char_y = y + random.randint(-5, 5)
        draw.text((char_x, char_y), char, font=font, fill='black')
    
    # Convert image to base64
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    image_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{image_base64}"

def verify_captcha(session_captcha, user_input):
    """Verify CAPTCHA input"""
    if not session_captcha or not user_input:
        return False
    return session_captcha.upper() == user_input.upper() 