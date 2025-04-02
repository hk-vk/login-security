/**
 * Simple Character Captcha
 * A client-side captcha implementation that generates and validates 
 * character-based captchas without server storage.
 */

class SimpleCaptcha {
    constructor(options = {}) {
        this.options = {
            length: options.length || 6,
            width: options.width || 200,
            height: options.height || 60,
            fonts: options.fonts || ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia'],
            backgroundColor: options.backgroundColor || '#f9f9f9',
            fontColor: options.fontColor || '#333',
            noiseColor: options.noiseColor || '#999',
            noiseLines: options.noiseLines || 6,
            noiseDots: options.noiseDots || 100,
            formId: options.formId || null,
            captchaInputId: options.captchaInputId || 'captcha-input'
        };
        
        this.captchaText = '';
        this.canvas = null;
        this.input = null;
        this.container = null;
        this.refreshButton = null;
    }

    // Generate a random string of characters
    generateCaptchaText() {
        const possible = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
        let text = '';
        for (let i = 0; i < this.options.length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    // Draw the captcha on the canvas
    drawCaptcha() {
        if (!this.canvas) return;
        
        const ctx = this.canvas.getContext('2d');
        const { width, height } = this.options;
        
        // Clear canvas
        ctx.fillStyle = this.options.backgroundColor;
        ctx.fillRect(0, 0, width, height);
        
        // Generate new captcha text
        this.captchaText = this.generateCaptchaText();
        
        // Draw noise (lines)
        for (let i = 0; i < this.options.noiseLines; i++) {
            ctx.beginPath();
            ctx.moveTo(Math.random() * width, Math.random() * height);
            ctx.lineTo(Math.random() * width, Math.random() * height);
            ctx.strokeStyle = this.options.noiseColor;
            ctx.lineWidth = Math.random() * 2;
            ctx.stroke();
        }
        
        // Draw noise (dots)
        for (let i = 0; i < this.options.noiseDots; i++) {
            ctx.fillStyle = this.options.noiseColor;
            ctx.fillRect(
                Math.random() * width,
                Math.random() * height,
                1,
                1
            );
        }
        
        // Draw captcha text
        ctx.font = `bold ${Math.floor(height/2)}px ${this.options.fonts[Math.floor(Math.random() * this.options.fonts.length)]}`;
        ctx.fillStyle = this.options.fontColor;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        
        // Add rotation and distortion to each character
        const textWidth = width * 0.8;
        const charWidth = textWidth / this.captchaText.length;
        const startX = width * 0.1;
        
        for (let i = 0; i < this.captchaText.length; i++) {
            const charX = startX + i * charWidth + charWidth / 2;
            const charY = height / 2 + (Math.random() - 0.5) * 10;
            
            ctx.save();
            ctx.translate(charX, charY);
            ctx.rotate((Math.random() - 0.5) * 0.4);
            ctx.fillText(this.captchaText[i], 0, 0);
            ctx.restore();
        }
    }

    // Validate user input against captcha
    validate(userInput) {
        if (!userInput) return false;
        return userInput.toLowerCase() === this.captchaText.toLowerCase();
    }

    // Refresh the captcha
    refresh() {
        this.drawCaptcha();
    }

    // Initialize the captcha
    init(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            console.error(`Captcha container with ID "${containerId}" not found.`);
            return;
        }
        
        // Create the canvas
        this.canvas = document.createElement('canvas');
        this.canvas.width = this.options.width;
        this.canvas.height = this.options.height;
        this.canvas.style.display = 'block';
        this.canvas.style.margin = '0 auto 10px';
        this.canvas.style.borderRadius = '4px';
        this.canvas.style.cursor = 'pointer';
        this.canvas.title = 'Click to refresh the captcha';
        
        // Create the input field
        this.input = document.createElement('input');
        this.input.type = 'text';
        this.input.id = this.options.captchaInputId;
        this.input.name = 'captcha';
        this.input.placeholder = 'Enter the captcha text';
        this.input.className = 'form-control';
        this.input.style.textAlign = 'center';
        this.input.style.letterSpacing = '3px';
        this.input.required = true;
        this.input.autocomplete = 'off';
        
        // Create the refresh button
        this.refreshButton = document.createElement('button');
        this.refreshButton.type = 'button';
        this.refreshButton.className = 'btn-icon captcha-refresh';
        this.refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i>';
        this.refreshButton.title = 'Refresh Captcha';
        
        // Create a hidden field to store the original captcha text (hashed)
        this.hiddenInput = document.createElement('input');
        this.hiddenInput.type = 'hidden';
        this.hiddenInput.name = 'captcha_hash';
        this.hiddenInput.id = 'captcha-hash';
        
        // Create a wrapper div
        const wrapper = document.createElement('div');
        wrapper.className = 'captcha-wrapper';
        wrapper.style.display = 'flex';
        wrapper.style.alignItems = 'center';
        wrapper.style.marginBottom = '15px';
        
        wrapper.appendChild(this.input);
        wrapper.appendChild(this.refreshButton);
        
        // Add elements to the container
        this.container.appendChild(this.canvas);
        this.container.appendChild(wrapper);
        this.container.appendChild(this.hiddenInput);
        
        // Add event listeners
        this.canvas.addEventListener('click', () => this.refresh());
        this.refreshButton.addEventListener('click', () => this.refresh());
        
        // If a form id was provided, find the form and add validation
        if (this.options.formId) {
            const form = document.getElementById(this.options.formId);
            if (form) {
                form.addEventListener('submit', (e) => {
                    const isValid = this.validate(this.input.value);
                    if (!isValid) {
                        e.preventDefault();
                        alert('Incorrect captcha, please try again');
                        this.refresh();
                        this.input.value = '';
                        this.input.focus();
                    }
                });
            }
        }
        
        // Draw initial captcha
        this.drawCaptcha();
        
        // Store a hash of the captcha text in the hidden field
        this.updateHash();
    }
    
    // Create a simple hash of the captcha text for validation
    hashCaptchaText() {
        let hash = 0;
        for (let i = 0; i < this.captchaText.length; i++) {
            hash = ((hash << 5) - hash) + this.captchaText.charCodeAt(i);
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash.toString(16);
    }
    
    updateHash() {
        this.hiddenInput.value = this.hashCaptchaText();
    }
}

// Initialize the captcha on DOM load if data attributes are present
document.addEventListener('DOMContentLoaded', () => {
    const captchaContainers = document.querySelectorAll('[data-captcha]');
    captchaContainers.forEach(container => {
        const options = {
            formId: container.getAttribute('data-captcha-form'),
            length: parseInt(container.getAttribute('data-captcha-length') || 6),
            width: parseInt(container.getAttribute('data-captcha-width') || 200),
            height: parseInt(container.getAttribute('data-captcha-height') || 60)
        };
        
        const captcha = new SimpleCaptcha(options);
        captcha.init(container.id);
    });
}); 