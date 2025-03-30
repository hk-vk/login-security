# Adaptive Login Security System - Comprehensive Technical Analysis

## 1. Introduction & System Architecture

### 1.1. Project Overview
The Adaptive Login Security System is a sophisticated web application implementing a dynamic, risk-based authentication framework. Unlike traditional systems that apply uniform security measures to all users, this system analyzes multiple risk factors in real-time to determine the appropriate level of authentication requirements for each login attempt.

### 1.2. Technology Stack - Detailed Breakdown

#### 1.2.1. Backend Framework: FastAPI
* **Version**: 0.95.0+
* **Implementation Details**: The system leverages FastAPI's built-in dependency injection system for managing database sessions, authentication, and configuration. Route handlers are organized by functionality (`/auth`, `/admin`, `/api`) and utilize Pydantic models for automatic data validation and OpenAPI schema generation.
* **Technical Advantages**:
  * **Performance**: FastAPI's ASGI foundation (using Uvicorn server) enables high-performance asynchronous request handling with significantly lower latency compared to traditional WSGI frameworks.
  * **Type Safety**: Leverages Python's type hints for static analysis, reducing runtime errors.
  * **Automatic Documentation**: Self-documenting API with interactive Swagger UI (/docs) and ReDoc (/redoc) endpoints.
  * **Dependency Injection**: Clean separation of concerns through FastAPI's dependency system, simplifying testing and maintenance.

#### 1.2.2. Database Technology
* **Primary Database**: SQLite 3.36+
* **ORM**: SQLAlchemy 2.0+
* **Schema Management**: Uses SQLAlchemy declarative base model for table definitions with explicit column types and constraints.
* **Database Interface Implementation**:
  * **Connection Management**: Implements a context-dependent database session using FastAPI's dependency system (`get_db()` function returning an SQLAlchemy `Session` object).
  * **Transaction Handling**: Follows the pattern of creating a session, performing operations, committing upon success, and rolling back on exceptions.
  * **Model Relationships**: Implements complex bidirectional relationships (one-to-many, many-to-one) using SQLAlchemy's `relationship()` with explicit `back_populates` parameters to avoid relationship conflicts.

#### 1.2.3. Frontend Technologies
* **Templating Engine**: Jinja2 3.1+
* **Template Organization**: Utilizes template inheritance with a base template containing common elements (header, footer, navigation) and child templates for specific pages.
* **JavaScript Framework**: Vanilla JavaScript with Fetch API for AJAX requests to backend endpoints.
* **CSS Framework**: Custom CSS with responsive design principles.
* **Data Visualization**: Chart.js 3.9+ for rendering interactive security analytics dashboards.

#### 1.2.4. Authentication Framework
* **Authentication Mechanism**: OAuth2 implementation with Password flow
* **Token Implementation**: JSON Web Tokens (PyJWT 2.6+)
* **Password Security**: Argon2id or bcrypt hashing via passlib with high work factors
* **Multi-Factor Authentication**: Email-based TOTP implementation

### 1.3. System Architecture Details
* **Deployment Model**: Single-server deployment with Uvicorn ASGI server
* **Component Interaction**: API-driven architecture with RESTful endpoints
* **Data Flow**: 
  1. Client sends request to API endpoint
  2. FastAPI router dispatches to appropriate handler
  3. Handler functions use dependencies to access database, authentication, and services
  4. Service layer implements business logic for authentication, risk assessment, and admin functions
  5. SQLAlchemy models represent and persist data to SQLite

## 2. Authentication Subsystem - Detailed Implementation

### 2.1. User Registration System

#### 2.1.1. Registration Workflow Algorithm
1. **Input Validation**:
   * Username validation: Regex pattern `^[a-zA-Z0-9_-]{3,20}$` ensures usernames are 3-20 characters containing only alphanumeric characters, underscores, and hyphens.
   * Email validation: Uses Pydantic's `EmailStr` type for RFC-compliant email validation.
   * Password validation: Custom validator enforcing minimum length (8+ characters), complexity requirements (uppercase, lowercase, numbers, special characters), and common password checks.

2. **Database Uniqueness Verification**:
   ```python
   def check_username_email_unique(username, email, db_session):
       existing_user = db_session.query(User).filter(
           or_(
               User.username == username,
               User.email == email
           )
       ).first()
       if existing_user:
           if existing_user.username == username:
               raise ValueError("Username already taken")
           raise ValueError("Email already registered")
   ```

3. **Password Hashing Algorithm**:
   * Library: `passlib.hash` with Argon2id
   * Configuration parameters:
     * Memory cost: 65536 KiB
     * Time cost (iterations): 3
     * Parallelism factor: 4
     * Salt length: 16 bytes (cryptographically random)
     * Hash length: 32 bytes
   * Implementation:
   ```python
   from passlib.hash import argon2
   
   def hash_password(password: str) -> str:
       # Argon2id with memory=65536, iterations=3, parallelism=4
       return argon2.using(
           type='id',
           memory_cost=65536,
           time_cost=3,
           parallelism=4
       ).hash(password)
   ```

4. **Email Verification Token Generation**:
   * Algorithm: Cryptographically secure random token generation using Python's `secrets` module
   * Token length: 32 bytes (converted to 64 character hex string)
   * Storage: Hashed using SHA-256 before database storage for additional security
   * Expiration: 24-hour time limit enforced via timestamp comparison
   ```python
   def generate_verification_token():
       # Generate 32 bytes of cryptographically secure random data
       token_bytes = secrets.token_bytes(32)
       # Convert to hex string for URL-safe token
       token = token_bytes.hex()
       # Store hash of token in database (not the plain token)
       token_hash = hashlib.sha256(token.encode()).hexdigest()
       return token, token_hash
   ```

5. **User Record Creation**:
   * Creates new `User` instance with validated data
   * Sets initial security values:
     * `is_active = False` (pending email verification)
     * `failed_login_attempts = 0`
     * `risk_score = 0`
     * `created_at = datetime.utcnow()`
   * Persists to database within a transaction

6. **Email Delivery System**:
   * Email library: `fastapi-mail`
   * Template-based: Uses Jinja2 templates for email content
   * Contains personalized verification link with secure token
   * Transport: SMTP with TLS

#### 2.1.2. Email Verification Process
* **Token Validation Algorithm**:
  1. Extract token from verification URL
  2. Calculate SHA-256 hash of the token
  3. Query database for matching token record that is not expired
  4. If found, update associated user account to `is_active = True`
  5. Delete the verification token record (single use)
  6. Return success response and redirect to login page

* **Implementation Details**:
  ```python
  @router.get("/verify/{token}")
  async def verify_email(token: str, db: Session = Depends(get_db)):
      # Hash the token for comparison with stored value
      token_hash = hashlib.sha256(token.encode()).hexdigest()
      
      # Look up the verification record
      verification = db.query(EmailVerification).filter(
          EmailVerification.token_hash == token_hash,
          EmailVerification.expires_at > datetime.utcnow()
      ).first()
      
      if not verification:
          raise HTTPException(status_code=400, detail="Invalid or expired verification token")
      
      # Update user status
      user = db.query(User).filter(User.id == verification.user_id).first()
      if not user:
          raise HTTPException(status_code=400, detail="User not found")
          
      user.is_active = True
      
      # Remove verification record (one-time use)
      db.delete(verification)
      db.commit()
      
      return {"detail": "Email verified successfully"}
  ```

### 2.2. Multi-Factor Authentication Implementation

#### 2.2.1. TOTP (Time-based One-Time Password) System
* **Algorithm**: HMAC-SHA1 based TOTP (RFC 6238)
* **Library**: `pyotp` for TOTP generation and validation
* **Parameters**:
  * Secret key: 32-character base32-encoded random string
  * Time step: 30 seconds
  * Code length: 6 digits
  * Verification window: ±1 step (allows for slight time drift)

* **Secret Generation**:
  ```python
  def generate_totp_secret():
      # Generate a secure random key
      return pyotp.random_base32()
  ```

* **Code Generation**:
  ```python
  def generate_totp_code(secret):
      totp = pyotp.TOTP(secret)
      return totp.now()  # Returns current 6-digit code
  ```

* **Code Verification**:
  ```python
  def verify_totp_code(secret, code):
      totp = pyotp.TOTP(secret)
      # Verify with a window of 1 step before/after
      return totp.verify(code, valid_window=1)
  ```

#### 2.2.2. Email-based MFA Delivery
* **Process Flow**:
  1. User completes password authentication successfully
  2. System generates TOTP code using user's secret 
  3. Code is sent via email using `fastapi-mail` with high priority flag
  4. User enters code on the MFA verification page
  5. System validates the code against the user's secret with time window consideration
  6. If valid, authentication completes and JWT is issued

* **Code Example (TOTP Email Delivery)**:
  ```python
  async def send_mfa_code(user_email, code):
      message = MessageSchema(
          subject="Your login verification code",
          recipients=[user_email],
          body=f"Your verification code is: {code}\nValid for 30 seconds.",
          subtype=MessageType.plain
      )
      
      await fm.send_message(message)
  ```

#### 2.2.3. MFA Enrollment Algorithm
1. Generate new TOTP secret
2. Create QR code URL (for potential future app support) 
3. Generate current verification code
4. Send code via email
5. User verifies received code
6. On successful verification, enable MFA and store secret
   ```python
   @router.post("/mfa/enable")
   async def enable_mfa(
       current_user: User = Depends(get_current_active_user),
       db: Session = Depends(get_db)
   ):
       # Generate new secret for user
       secret = generate_totp_secret()
       
       # Generate and send verification code
       code = generate_totp_code(secret)
       await send_mfa_code(current_user.email, code)
       
       # Store secret temporarily (until verified)
       temp_secret = TempMFASecret(
           user_id=current_user.id,
           secret=secret,
           created_at=datetime.utcnow()
       )
       db.add(temp_secret)
       db.commit()
       
       return {"detail": "Verification code sent"}
   
   @router.post("/mfa/verify")
   async def verify_mfa_setup(
       code: str,
       current_user: User = Depends(get_current_active_user),
       db: Session = Depends(get_db)
   ):
       # Retrieve temporary secret
       temp_secret = db.query(TempMFASecret).filter(
           TempMFASecret.user_id == current_user.id
       ).first()
       
       if not temp_secret:
           raise HTTPException(status_code=400, detail="No pending MFA setup")
       
       # Verify code against secret
       if not verify_totp_code(temp_secret.secret, code):
           raise HTTPException(status_code=400, detail="Invalid verification code")
       
       # Enable MFA for user
       current_user.mfa_enabled = True
       current_user.mfa_secret = temp_secret.secret
       
       # Remove temporary secret
       db.delete(temp_secret)
       db.commit()
       
       return {"detail": "MFA enabled successfully"}
   ```

### 2.3. Adaptive Security System

#### 2.3.1. Progressive Security Algorithm
* **Implementation**: Dynamic security challenge selector based on real-time risk assessment
* **Challenge Levels**:
  1. **Level 0** (Risk score < 20): Standard password authentication only
  2. **Level 1** (Risk score 20-40): Password + CAPTCHA verification
  3. **Level 2** (Risk score 41-70): Password + Email verification code (non-TOTP)
  4. **Level 3** (Risk score > 70): Password + TOTP (if enabled) or mandatory stepped-up verification
  5. **Level 4** (Risk score > 90): Block authentication attempt entirely

* **Selection Algorithm**:
  ```python
  def determine_security_level(risk_score, user):
      if risk_score > 90:
          return SecurityLevel.BLOCK
      elif risk_score > 70:
          return SecurityLevel.MFA_REQUIRED
      elif risk_score > 40:
          return SecurityLevel.EMAIL_VERIFICATION
      elif risk_score > 20:
          return SecurityLevel.CAPTCHA
      else:
          return SecurityLevel.STANDARD
  ```

#### 2.3.2. Risk Factor Computation
* **Implementation**: Weighted scoring algorithm combining multiple risk signals
* **Risk Factors and Weights**:
  * New IP address for user (Weight: 15)
  * Geographic distance from common locations (Weight: 10-25 based on distance)
  * Time deviation from typical patterns (Weight: 5-20)
  * Login velocity (recent attempts) (Weight: 10-30)
  * Failed login history for IP (Weight: 15-25)
  * Device/browser fingerprint new to user (Weight: 15)
  * IP address reputation score (Weight: 20-40)
  * Day/time anomaly score (Weight: 5-15)

* **Factor Normalization**: Each factor is normalized to a 0-100 scale before applying weights
* **Calculation Formula**:
  ```
  FinalRiskScore = (Σ (NormalizedFactorValue × FactorWeight)) ÷ (Σ FactorWeights)
  ```

* **Implementation Snippet**:
  ```python
  def calculate_risk_score(user_id, ip_address, user_agent, timestamp, db):
      risk_factors = []
      weights = []
      
      # Get user's login history
      login_history = get_user_login_history(user_id, db)
      
      # Factor 1: IP newness
      ip_newness_score = calculate_ip_newness(user_id, ip_address, login_history)
      risk_factors.append(ip_newness_score)
      weights.append(15)
      
      # Factor 2: Geographic distance
      geo_score = calculate_geo_distance_score(ip_address, login_history)
      risk_factors.append(geo_score)
      weight = min(25, max(10, geo_score / 4))  # Dynamic weight based on score
      weights.append(weight)
      
      # Additional factors calculated similarly...
      
      # Calculate weighted average
      if sum(weights) > 0:
          final_score = sum(f * w for f, w in zip(risk_factors, weights)) / sum(weights)
          return min(100, max(0, final_score))  # Ensure within 0-100 range
      
      return 0  # Default low risk
  ```

### 2.4. Password Management System

#### 2.4.1. Password Complexity Enforcement
* **Implementation**: Custom password validator with multiple criteria
* **Validation Rules**:
  * Minimum length: 8 characters
  * Complexity requirements: 
    * At least one uppercase letter (regex: `[A-Z]`)
    * At least one lowercase letter (regex: `[a-z]`)
    * At least one number (regex: `[0-9]`)
    * At least one special character (regex: `[^A-Za-z0-9]`)
  * Common password check: Validates against a database of known compromised passwords (optional integration with HIBP API)

* **Code Example**:
  ```python
  def validate_password_strength(password: str) -> bool:
      """
      Validates password strength against multiple criteria
      """
      if len(password) < 8:
          return False
          
      # Check for uppercase
      if not re.search(r'[A-Z]', password):
          return False
          
      # Check for lowercase
      if not re.search(r'[a-z]', password):
          return False
          
      # Check for digits
      if not re.search(r'[0-9]', password):
          return False
          
      # Check for special characters
      if not re.search(r'[^A-Za-z0-9]', password):
          return False
      
      # Optional: Check against common password list
      # if is_common_password(password):
      #     return False
          
      return True
  ```

#### 2.4.2. Password Reset Process Algorithm
1. **Request Initiation**:
   * User submits email address
   * System validates email exists in database
   * Rate-limiting applied to prevent enumeration attacks (max 3 requests per email per hour)

2. **Token Generation**:
   ```python
   def generate_password_reset_token(user_id):
       # Generate secure random token
       token_bytes = secrets.token_bytes(32)
       token = token_bytes.hex()
       
       # Create hash for storage
       token_hash = hashlib.sha256(token.encode()).hexdigest()
       
       # Store in database with expiration (1 hour)
       expires_at = datetime.utcnow() + timedelta(hours=1)
       reset_record = PasswordResetToken(
           user_id=user_id,
           token_hash=token_hash,
           expires_at=expires_at
       )
       
       return token
   ```

3. **Email Delivery**: Similar to verification email process, sending unique link with token

4. **Token Validation & Password Reset**:
   ```python
   def verify_and_reset_password(token, new_password, db):
       # Hash token for lookup
       token_hash = hashlib.sha256(token.encode()).hexdigest()
       
       # Find valid reset record
       reset_record = db.query(PasswordResetToken).filter(
           PasswordResetToken.token_hash == token_hash,
           PasswordResetToken.expires_at > datetime.utcnow()
       ).first()
       
       if not reset_record:
           return False, "Invalid or expired token"
       
       # Validate new password
       if not validate_password_strength(new_password):
           return False, "Password does not meet complexity requirements"
       
       # Get user and update password
       user = db.query(User).filter(User.id == reset_record.user_id).first()
       if not user:
           return False, "User not found"
           
       # Hash and set new password
       user.hashed_password = hash_password(new_password)
       user.password_last_changed = datetime.utcnow()
       
       # Remove all reset tokens for this user
       db.query(PasswordResetToken).filter(
           PasswordResetToken.user_id == user.id
       ).delete()
       
       # Log the password change event
       security_event = SecurityEvent(
           user_id=user.id,
           event_type="password_reset",
           description="Password reset via email recovery",
           severity="medium"
       )
       db.add(security_event)
       db.commit()
       
       return True, "Password reset successfully"
   ```

5. **Security Measures**:
   * Single-use tokens (deleted after use)
   * SHA-256 hashing of tokens in database
   * 1-hour expiration window
   * All existing sessions invalidated after password reset

## 3. Security Subsystem - Detailed Implementation

### 3.1. Brute Force Protection Mechanisms

#### 3.1.1. Rate Limiting Implementation
* **Algorithm**: Token Bucket algorithm with Redis backend
* **Library**: `slowapi` extension for FastAPI, backed by Redis
* **Configuration Parameters**:
  * Login endpoint: 5 requests per minute per IP address
  * Registration endpoint: 3 requests per 10 minutes per IP address
  * Password reset request: 3 requests per hour per email address
  * MFA verification: 5 attempts per 10 minutes per user

* **Implementation Details**:
  ```python
  from slowapi import Limiter, _rate_limit_exceeded_handler
  from slowapi.util import get_remote_address
  from slowapi.errors import RateLimitExceeded
  
  limiter = Limiter(key_func=get_remote_address, storage_uri="redis://localhost:6379")
  
  app.state.limiter = limiter
  app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
  
  @app.post("/login")
  @limiter.limit("5/minute")
  async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
      # Login logic...
  ```

* **Progressive Backoff Implementation**:
  ```python
  def calculate_login_delay(user_id=None, ip_address=None, db_session=None):
      """Calculate delay time for login attempts based on failure history"""
      base_delay = 0  # seconds
      
      if user_id:
          # Get user failed attempt count
          user = db_session.query(User).filter(User.id == user_id).first()
          if user and user.failed_login_attempts > 0:
              # Exponential backoff formula: 2^(attempts-1) seconds, max 30 minutes
              user_delay = min(2 ** (user.failed_login_attempts - 1), 1800)
              base_delay = max(base_delay, user_delay)
      
      if ip_address:
          # Count recent failed attempts from this IP (last hour)
          one_hour_ago = datetime.utcnow() - timedelta(hours=1)
          ip_failures = db_session.query(LoginAttempt).filter(
              LoginAttempt.ip_address == ip_address,
              LoginAttempt.success == False,
              LoginAttempt.timestamp > one_hour_ago
          ).count()
          
          if ip_failures > 3:
              # Exponential backoff for IP-based attempts
              ip_delay = min(2 ** (ip_failures - 3), 1800)
              base_delay = max(base_delay, ip_delay)
      
      return base_delay
  ```

#### 3.1.2. CAPTCHA Integration
* **Service**: Google reCAPTCHA v2
* **Implementation**:
  * Client-side: reCAPTCHA JavaScript API included on login and registration pages
  * Server-side: Verification of CAPTCHA token against Google's verification API
  * Trigger conditions: After failed login attempts or based on risk assessment

* **Verification Process**:
  ```python
  async def verify_recaptcha(captcha_response):
      """Verify reCAPTCHA response with Google's API"""
      secret_key = settings.RECAPTCHA_SECRET_KEY
      
      async with aiohttp.ClientSession() as session:
          async with session.post(
              'https://www.google.com/recaptcha/api/siteverify',
              data={
                  'secret': secret_key,
                  'response': captcha_response
              }
          ) as response:
              result = await response.json()
              return result.get('success', False)
  ```

### 3.2. IP-Based Access Control System

#### 3.2.1. IP Tracking & Analysis
* **Implementation**: IP address logging for all authentication-related actions
* **Data Collected**:
  * IP address (IPv4/IPv6)
  * Timestamp
  * User ID (if authenticated)
  * Action type (login attempt, registration, password reset, etc.)
  * Success/failure status
  * User-Agent string

* **Database Schema**: `LoginAttempt` table with related fields
* **Analysis Algorithm**: Aggregation queries analyzing patterns in login attempts

#### 3.2.2. IP Blocking System
* **Automatic Blocking Rules**:
  * More than 20 failed login attempts in 1 hour
  * Attempts on more than 5 different user accounts from same IP
  * Known malicious IP addresses from reputation lists (if integrated)

* **Block Implementation**:
  ```python
  def block_ip_address(ip_address, reason, duration_hours=24, automated=True, blocked_by=None, db=None):
      """Block an IP address for suspicious activity"""
      # Check if already blocked
      existing_block = db.query(BlockedIP).filter(BlockedIP.ip_address == ip_address).first()
      if existing_block:
          # Update existing block with new expiration if needed
          if existing_block.expires_at and datetime.utcnow() > existing_block.expires_at:
              existing_block.blocked_at = datetime.utcnow()
              existing_block.reason = reason
              existing_block.expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
              existing_block.blocked_by = blocked_by
              existing_block.automated = automated
              db.commit()
          return
      
      # Create new IP block
      expires_at = datetime.utcnow() + timedelta(hours=duration_hours) if duration_hours else None
      new_block = BlockedIP(
          ip_address=ip_address,
          reason=reason,
          blocked_at=datetime.utcnow(),
          expires_at=expires_at,
          blocked_by=blocked_by,
          automated=automated
      )
      db.add(new_block)
      db.commit()
      
      # Log security event
      event = SecurityEvent(
          event_type="ip_blocked",
          severity="high",
          description=f"IP address {ip_address} blocked: {reason}",
          ip_address=ip_address,
          user_id=blocked_by
      )
      db.add(event)
      db.commit()
  ```

* **Block Check Middleware**:
  ```python
  async def check_ip_block(request: Request, db: Session = Depends(get_db)):
      """Middleware to check if requesting IP is blocked"""
      ip_address = request.client.host
      
      # Check for active block
      block = db.query(BlockedIP).filter(
          BlockedIP.ip_address == ip_address,
          or_(
              BlockedIP.expires_at.is_(None),
              BlockedIP.expires_at > datetime.utcnow()
          )
      ).first()
      
      if block:
          # Log blocked attempt
          event = SecurityEvent(
              event_type="blocked_ip_attempt",
              severity="medium",
              description=f"Blocked IP attempted access: {ip_address}",
              ip_address=ip_address
          )
          db.add(event)
          db.commit()
          
          raise HTTPException(
              status_code=403,
              detail="Access denied: Your IP address has been blocked due to suspicious activity"
          )
  ```

### 3.3. Account Lockout Mechanism

#### 3.3.1. Progressive Lockout Implementation
* **Algorithm**: Threshold-based with escalating lockout durations
* **Thresholds**:
  * 5 consecutive failures: 15-minute lockout
  * 10 consecutive failures: 1-hour lockout
  * 15 consecutive failures: 24-hour lockout
  * 20+ consecutive failures: Admin intervention required

* **Implementation Details**:
  ```python
  def handle_failed_login(username, ip_address, db_session):
      """Update failed login count and potentially lock account"""
      user = db_session.query(User).filter(User.username == username).first()
      if not user:
          return
      
      # Update failed login counters
      user.failed_login_attempts += 1
      user.last_failed_login = datetime.utcnow()
      
      # Determine if account should be locked
      if user.failed_login_attempts >= 20:
          # Require admin intervention - indefinite lock
          user.account_locked_until = datetime.max
          reason = "Excessive failed login attempts (20+)"
          lockout_type = "permanent"
      elif user.failed_login_attempts >= 15:
          # 24-hour lockout
          user.account_locked_until = datetime.utcnow() + timedelta(hours=24)
          reason = "Excessive failed login attempts (15+)"
          lockout_type = "24-hour"
      elif user.failed_login_attempts >= 10:
          # 1-hour lockout
          user.account_locked_until = datetime.utcnow() + timedelta(hours=1)
          reason = "Multiple failed login attempts (10+)"
          lockout_type = "1-hour"
      elif user.failed_login_attempts >= 5:
          # 15-minute lockout
          user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
          reason = "Multiple failed login attempts"
          lockout_type = "15-minute"
      else:
          # No lockout yet
          db_session.commit()
          return
      
      # Log security event
      event = SecurityEvent(
          user_id=user.id,
          event_type="account_lockout",
          severity="high" if user.failed_login_attempts >= 10 else "medium",
          description=f"Account locked: {reason}",
          ip_address=ip_address
      )
      db_session.add(event)
      db_session.commit()
      
      # Optionally notify user via email
      if user.failed_login_attempts >= 5:
          # async call to email notification function
          background_tasks.add_task(
              send_account_lockout_notification,
              user.email,
              lockout_type,
              ip_address
          )
  ```

#### 3.3.2. Account Unlock Process
* **Automatic Unlock**: Time-based expiration of lockout period
* **Manual Unlock (Admin)**:
  ```python
  @router.post("/admin/users/{user_id}/unlock")
  async def unlock_user_account(
      user_id: int,
      current_admin: User = Depends(get_current_admin_user),
      db: Session = Depends(get_db)
  ):
      user = db.query(User).filter(User.id == user_id).first()
      if not user:
          raise HTTPException(status_code=404, detail="User not found")
      
      # Reset lockout fields
      user.account_locked_until = None
      user.failed_login_attempts = 0
      
      # Log the unlock event
      event = SecurityEvent(
          user_id=user.id,
          event_type="account_unlock",
          severity="medium",
          description=f"Account manually unlocked by admin {current_admin.username}",
          acknowledged_by=current_admin.id
      )
      db.add(event)
      db.commit()
      
      return {"detail": f"Account for user {user.username} has been unlocked"}
  ```

* **Self-service Unlock**: Limited to time-based lockouts less than 24 hours, requires email verification

### 3.4. JWT Session Management System

#### 3.4.1. JWT Configuration
* **Library**: `python-jose` with cryptographic backend `cryptography`
* **Algorithm**: RS256 (RSA Signature with SHA-256)
* **Key Generation**:
  ```python
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.backends import default_backend
  
  def generate_rsa_keys():
      # Generate RSA keypair
      private_key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048,
          backend=default_backend()
      )
      
      # Extract public key
      public_key = private_key.public_key()
      
      # Serialize private key to PEM format
      private_pem = private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.PKCS8,
          encryption_algorithm=serialization.NoEncryption()
      )
      
      # Serialize public key to PEM format
      public_pem = public_key.public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
      )
      
      return private_pem.decode('utf-8'), public_pem.decode('utf-8')
  ```

#### 3.4.2. Token Generation Process
* **Token Claims**:
  * `sub`: User ID (subject)
  * `exp`: Expiration time (default: 30 minutes)
  * `iat`: Issued at time
  * `role`: User role for authorization
  * `jti`: Unique JWT ID for potential revocation

* **Implementation**:
  ```python
  from jose import jwt
  import uuid
  
  def create_access_token(data: dict, expires_delta: timedelta = None):
      to_encode = data.copy()
      if expires_delta:
          expire = datetime.utcnow() + expires_delta
      else:
          expire = datetime.utcnow() + timedelta(minutes=30)
      
      to_encode.update({
          "exp": expire,
          "iat": datetime.utcnow(),
          "jti": str(uuid.uuid4())
      })
      
      # Sign the token with private key
      with open(settings.JWT_PRIVATE_KEY_PATH, "r") as key_file:
          private_key = key_file.read()
      
      encoded_jwt = jwt.encode(
          to_encode, 
          private_key, 
          algorithm=settings.JWT_ALGORITHM
      )
      
      # Log token creation for audit purposes
      log_token_creation(data["sub"], expire)
      
      return encoded_jwt
  ```

#### 3.4.3. Token Validation & Verification
* **Process**:
  ```python
  async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
      credentials_exception = HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail="Could not validate credentials",
          headers={"WWW-Authenticate": "Bearer"},
      )
      
      try:
          # Load the public key
          with open(settings.JWT_PUBLIC_KEY_PATH, "r") as key_file:
              public_key = key_file.read()
          
          # Decode and verify the token
          payload = jwt.decode(
              token, 
              public_key, 
              algorithms=[settings.JWT_ALGORITHM],
              options={"verify_signature": True, "verify_exp": True}
          )
          
          user_id: str = payload.get("sub")
          if user_id is None:
              raise credentials_exception
          
          # Get the user
          user = db.query(User).filter(User.id == user_id).first()
          if user is None:
              raise credentials_exception
          
          # Check if user is active
          if not user.is_active:
              raise HTTPException(
                  status_code=status.HTTP_403_FORBIDDEN,
                  detail="Inactive user"
              )
          
          # Check if account is locked
          if user.account_locked_until and user.account_locked_until > datetime.utcnow():
              raise HTTPException(
                  status_code=status.HTTP_403_FORBIDDEN,
                  detail="Account is locked"
              )
          
          return user
              
      except JWTError:
          raise credentials_exception
  ```

#### 3.4.4. Session Tracking & Management
* **Active Sessions Table**: Tracks all active user sessions
* **Session Creation**:
  ```python
  def create_session(user_id, token_jti, ip_address, user_agent, db_session):
      new_session = Session(
          user_id=user_id,
          token_id=token_jti,
          ip_address=ip_address,
          user_agent=user_agent,
          created_at=datetime.utcnow(),
          expires_at=datetime.utcnow() + timedelta(minutes=30)
      )
      db_session.add(new_session)
      db_session.commit()
      return new_session
  ```

* **Session Invalidation**:
  * **Single Session Logout**:
    ```python
    def invalidate_session(token_jti, db_session):
        session = db_session.query(Session).filter(Session.token_id == token_jti).first()
        if session:
            db_session.delete(session)
            db_session.commit()
            return True
        return False
    ```
  
  * **User-wide Session Invalidation**:
    ```python
    def invalidate_all_user_sessions(user_id, db_session):
        """Invalidate all sessions for a user (for password change, security breach, etc.)"""
        db_session.query(Session).filter(Session.user_id == user_id).delete()
        db_session.commit()
    ```

### 3.5. Geographic Anomaly Detection System

#### 3.5.1. Geolocation Service
* **Implementation**: MaxMind GeoIP2 database integration
* **Library**: `geoip2` Python package
* **Database Type**: GeoLite2 City database (updated weekly)
* **Data Retrieved**:
  * Country code and name
  * City name
  * Latitude/longitude coordinates
  * Accuracy radius
  * Time zone

* **Code Example**:
  ```python
  import geoip2.database
  
  def get_geolocation(ip_address):
      """Get geolocation data for an IP address using MaxMind GeoIP2"""
      try:
          with geoip2.database.Reader('./geoip_data/GeoLite2-City.mmdb') as reader:
              response = reader.city(ip_address)
              
              return {
                  'country_code': response.country.iso_code,
                  'country_name': response.country.name,
                  'city': response.city.name,
                  'latitude': response.location.latitude,
                  'longitude': response.location.longitude,
                  'accuracy_radius': response.location.accuracy_radius,
                  'time_zone': response.location.time_zone
              }
      except Exception as e:
          # Log error but don't fail
          logger.error(f"GeoIP lookup failed for {ip_address}: {str(e)}")
          return None
  ```

#### 3.5.2. Distance Calculation Algorithm
* **Implementation**: Haversine formula for calculating great-circle distance between coordinates
* **Formula**:
  ```
  a = sin²(Δφ/2) + cos φ1 ⋅ cos φ2 ⋅ sin²(Δλ/2)
  c = 2 ⋅ atan2(√a, √(1−a))
  d = R ⋅ c
  ```
  where φ is latitude, λ is longitude, and R is Earth's radius (6,371 km)

* **Code Implementation**:
  ```python
  from math import radians, cos, sin, asin, sqrt
  
  def haversine_distance(lat1, lon1, lat2, lon2):
      """
      Calculate the great circle distance between two points 
      on the earth specified in decimal degrees
      """
      # Convert decimal degrees to radians
      lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
      
      # Haversine formula
      dlon = lon2 - lon1
      dlat = lat2 - lat1
      a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
      c = 2 * asin(sqrt(a))
      r = 6371  # Radius of earth in kilometers
      
      return c * r
  ```

#### 3.5.3. Location Anomaly Detection Algorithm
* **Process Flow**:
  1. Retrieve user's previous login locations from database
  2. Calculate geolocation of current login IP
  3. For each previous location, calculate distance to current location
  4. Find minimum distance (closest previous location)
  5. Apply threshold-based scoring:
     * Distance < 50km: Low risk (score 0-10)
     * Distance 50-500km: Medium risk (score 10-40)
     * Distance 500-3000km: High risk (score 40-70)
     * Distance > 3000km: Very high risk (score 70-90)
     * First-time login from a country: Very high risk (score 80-90)
  6. Factor in time since last login from current location's country
  7. Check for "impossible travel" (logins from distant locations in short time frame)

* **Impossible Travel Detection**:
  ```python
  def detect_impossible_travel(user_id, current_latitude, current_longitude, current_time, db):
      """
      Detect physically impossible travel based on recent login locations and timestamps
      Returns a risk score boost if suspicious travel detected
      """
      # Get user's most recent login location
      most_recent_login = db.query(LoginLocation).filter(
          LoginLocation.user_id == user_id
      ).order_by(LoginLocation.timestamp.desc()).first()
      
      if not most_recent_login:
          return 0  # No previous logins
          
      # Calculate distance in kilometers
      distance = haversine_distance(
          most_recent_login.latitude, 
          most_recent_login.longitude,
          current_latitude, 
          current_longitude
      )
      
      # Skip if distance is small
      if distance < 100:
          return 0
          
      # Calculate time difference in hours
      time_diff = (current_time - most_recent_login.timestamp).total_seconds() / 3600
      
      # Assume average flight speed of 800 km/h plus 3 hours for airport procedures
      minimum_travel_time = (distance / 800) + 3
      
      if time_diff < minimum_travel_time and distance > 500:
          # Physically impossible travel detected
          risk_score_boost = min(100, int(50 + (distance / 100)))
          
          # Log impossible travel event
          event = SecurityEvent(
              user_id=user_id,
              event_type="impossible_travel",
              severity="high",
              description=f"Impossible travel detected: {distance:.0f}km in {time_diff:.1f} hours"
          )
          db.add(event)
          
          return risk_score_boost
          
      return 0
  ```

## 4. Administrative Dashboard - Technical Implementation

### 4.1. Real-time Monitoring Dashboard

#### 4.1.1. Dashboard Architecture
* **Implementation**: Server-side rendering with Jinja2 templates and AJAX for real-time updates
* **Data Flow**:
  1. Initial page load renders dashboard with Jinja2 template
  2. Client-side JavaScript makes periodic AJAX calls to refresh data
  3. Backend API endpoints provide JSON data for dashboard components
  4. Chart.js visualizes the data in interactive charts

* **Endpoint Implementation**:
  ```python
  @router.get("/admin/dashboard/stats")
  async def dashboard_stats(
      current_admin: User = Depends(get_current_admin_user),
      db: Session = Depends(get_db)
  ):
      """Return current statistics for admin dashboard"""
      now = datetime.utcnow()
      one_day_ago = now - timedelta(days=1)
      
      # Active sessions count
      active_sessions = db.query(Session).filter(
          Session.expires_at > now
      ).count()
      
      # Current locked accounts
      locked_accounts = db.query(User).filter(
          User.account_locked_until.isnot(None),
          User.account_locked_until > now
      ).count()
      
      # Recent login attempts (24h)
      recent_login_attempts = db.query(LoginAttempt).filter(
          LoginAttempt.timestamp > one_day_ago
      ).count()
      
      # Recent login failures (24h)
      recent_login_failures = db.query(LoginAttempt).filter(
          LoginAttempt.timestamp > one_day_ago,
          LoginAttempt.success == False
      ).count()
      
      # High severity security events (24h)
      high_severity_events = db.query(SecurityEvent).filter(
          SecurityEvent.timestamp > one_day_ago,
          SecurityEvent.severity == "high"
      ).count()
      
      # Blocked IPs count
      blocked_ips = db.query(BlockedIP).filter(
          or_(
              BlockedIP.expires_at.is_(None),
              BlockedIP.expires_at > now
          )
      ).count()
      
      return {
          "active_sessions": active_sessions,
          "locked_accounts": locked_accounts,
          "recent_login_attempts": recent_login_attempts,
          "recent_login_failures": recent_login_failures,
          "login_success_rate": (
              (recent_login_attempts - recent_login_failures) / recent_login_attempts * 100
              if recent_login_attempts > 0 else 100
          ),
          "high_severity_events": high_severity_events,
          "blocked_ips": blocked_ips,
          "last_updated": now.isoformat()
      }
  ```

#### 4.1.2. Real-time Updates Implementation
* **Polling Mechanism**: JavaScript `setInterval` for periodic updates (default: 30 seconds)
* **WebSocket Integration** (if implemented): Socket.IO or native WebSockets for push-based updates
* **Client-side Code Example**:
  ```javascript
  // Dashboard real-time updates
  function updateDashboardStats() {
      fetch('/api/admin/dashboard/stats')
          .then(response => response.json())
          .then(data => {
              // Update DOM elements with new data
              document.getElementById('active-sessions').textContent = data.active_sessions;
              document.getElementById('locked-accounts').textContent = data.locked_accounts;
              document.getElementById('login-success-rate').textContent = data.login_success_rate.toFixed(1) + '%';
              document.getElementById('high-severity-events').textContent = data.high_severity_events;
              document.getElementById('blocked-ips').textContent = data.blocked_ips;
              document.getElementById('last-updated').textContent = new Date(data.last_updated).toLocaleTimeString();
              
              // Update status indicators
              updateStatusIndicators(data);
          })
          .catch(error => console.error('Error updating dashboard stats:', error));
  }
  
  // Initial update
  updateDashboardStats();
  
  // Set up periodic updates
  setInterval(updateDashboardStats, 30000);
  ```

### 4.2. Security Analytics & Visualization

#### 4.2.1. Chart.js Integration
* **Chart Types Implemented**:
  * Line charts: Login attempts over time
  * Bar charts: Security events by type/severity
  * Pie/Doughnut charts: Login success vs. failure distribution
  * Radar charts: Risk score component breakdown
  * Geo charts: Login location distribution (using Chart.js plus additional plugins)

* **Responsive Chart Configuration**:
  ```javascript
  // Example of Chart.js implementation for login attempts over time
  function createLoginAttemptsChart(canvasId, data) {
      const ctx = document.getElementById(canvasId).getContext('2d');
      
      return new Chart(ctx, {
          type: 'line',
          data: {
              labels: data.labels, // Timestamps
              datasets: [
                  {
                      label: 'Successful Logins',
                      data: data.success_counts,
                      backgroundColor: 'rgba(75, 192, 192, 0.2)',
                      borderColor: 'rgba(75, 192, 192, 1)',
                      borderWidth: 2,
                      tension: 0.1
                  },
                  {
                      label: 'Failed Logins',
                      data: data.failure_counts,
                      backgroundColor: 'rgba(255, 99, 132, 0.2)',
                      borderColor: 'rgba(255, 99, 132, 1)',
                      borderWidth: 2,
                      tension: 0.1
                  }
              ]
          },
          options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                  x: {
                      grid: {
                          display: false
                      }
                  },
                  y: {
                      beginAtZero: true,
                      ticks: {
                          precision: 0
                      }
                  }
              },
              plugins: {
                  tooltip: {
                      mode: 'index',
                      intersect: false
                  },
                  legend: {
                      position: 'top'
                  }
              }
          }
      });
  }
  ```

#### 4.2.2. Geographic Visualization
* **Implementation**: Integration of Leaflet.js with Chart.js
* **Data Preparation**:
  ```python
  @router.get("/admin/analytics/geo-distribution")
  async def login_geo_distribution(
      days: int = 30,
      current_admin: User = Depends(get_current_admin_user),
      db: Session = Depends(get_db)
  ):
      """Get geographic distribution of login attempts for visualization"""
      start_date = datetime.utcnow() - timedelta(days=days)
      
      # Query for login locations
      login_locations = db.query(
          LoginLocation.country,
          LoginLocation.city,
          LoginLocation.latitude,
          LoginLocation.longitude,
          func.count(LoginLocation.id).label("count")
      ).filter(
          LoginLocation.timestamp > start_date
      ).group_by(
          LoginLocation.country,
          LoginLocation.city,
          LoginLocation.latitude,
          LoginLocation.longitude
      ).all()
      
      # Format result for frontend visualization
      result = []
      for loc in login_locations:
          if loc.latitude and loc.longitude:
              result.append({
                  "country": loc.country or "Unknown",
                  "city": loc.city or "Unknown",
                  "coordinates": [loc.latitude, loc.longitude],
                  "count": loc.count
              })
      
      return result
  ```

* **Map Visualization**:
  ```javascript
  function initializeLoginMap(containerId, locationData) {
      // Initialize Leaflet map
      const map = L.map(containerId).setView([20, 0], 2);
      
      // Add tile layer (OpenStreetMap)
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          attribution: '&copy; OpenStreetMap contributors'
      }).addTo(map);
      
      // Process data points
      locationData.forEach(location => {
          const [lat, lng] = location.coordinates;
          const count = location.count;
          const radius = Math.max(5, Math.min(20, Math.log(count) * 5));
          
          // Create circle marker
          L.circleMarker([lat, lng], {
              radius: radius,
              fillColor: '#3388ff',
              color: '#3388ff',
              weight: 1,
              opacity: 0.8,
              fillOpacity: 0.6
          })
          .bindPopup(`
              <strong>${location.city}, ${location.country}</strong><br>
              ${count} login ${count === 1 ? 'attempt' : 'attempts'}
          `)
          .addTo(map);
      });
      
      return map;
  }
  ```

#### 4.2.3. Frontend HTML & CSS Implementation

* **Responsive Layout Structure**:
  * **Implementation**: Custom HTML5 structure with responsive CSS Grid and Flexbox
  * **Viewport Handling**: Responsive meta tag and media queries for different device sizes
  * **HTML Structure**:
    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Dashboard - Adaptive Login Security System</title>
        <link rel="stylesheet" href="/static/css/normalize.css">
        <link rel="stylesheet" href="/static/css/dashboard.css">
    </head>
    <body>
        <div class="dashboard-container">
            <header class="dashboard-header">
                <div class="logo">
                    <img src="/static/img/logo.svg" alt="Security System Logo">
                    <h1>Adaptive Security</h1>
                </div>
                <div class="user-info">
                    <span>{{ current_user.username }}</span>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </header>
            
            <nav class="sidebar">
                <ul class="nav-menu">
                    <li class="nav-item active"><a href="/admin/dashboard">Dashboard</a></li>
                    <li class="nav-item"><a href="/admin/users">User Management</a></li>
                    <li class="nav-item"><a href="/admin/security">Security Events</a></li>
                    <li class="nav-item"><a href="/admin/analytics">Analytics</a></li>
                    <li class="nav-item"><a href="/admin/settings">Settings</a></li>
                </ul>
            </nav>
            
            <main class="main-content">
                <!-- Dashboard panels rendered here -->
                <div class="dashboard-panels">
                    <div class="panel" id="active-sessions-panel">
                        <!-- Panel content -->
                    </div>
                    <!-- Additional panels -->
                </div>
                
                <!-- Charts section -->
                <div class="charts-container">
                    <div class="chart-card">
                        <h3>Login Attempts (Last 7 Days)</h3>
                        <canvas id="login-attempts-chart"></canvas>
                    </div>
                    <!-- Additional charts -->
                </div>
            </main>
            
            <footer class="dashboard-footer">
                <p>&copy; {{ current_year }} Adaptive Login Security System</p>
            </footer>
        </div>
        
        <!-- JavaScript includes -->
        <script src="/static/js/chart.min.js"></script>
        <script src="/static/js/dashboard.js"></script>
    </body>
    </html>
    ```
    
* **CSS Architecture**:
  * **Implementation**: Custom CSS with BEM (Block, Element, Modifier) naming convention
  * **Responsive Breakpoints**: 
    * Mobile: < 768px
    * Tablet: 768px - 1024px
    * Desktop: > 1024px
  * **Key CSS Techniques**:
    * CSS Grid for overall page layout
    * Flexbox for component alignment
    * CSS Variables for consistent theming
    * Media queries for responsive adaptations
  
  * **Example CSS Implementation**:
    ```css
    /* CSS Variables for theming */
    :root {
        --primary-color: #3f51b5;
        --secondary-color: #f50057;
        --success-color: #4caf50;
        --warning-color: #ff9800;
        --danger-color: #f44336;
        --light-bg: #f5f5f5;
        --dark-bg: #333;
        --text-light: #fff;
        --text-dark: #333;
        --border-radius: 4px;
        --shadow: 0 2px 5px rgba(0,0,0,0.1);
    }
    
    /* Base Layout */
    .dashboard-container {
        display: grid;
        height: 100vh;
        grid-template-rows: auto 1fr auto;
        grid-template-columns: 250px 1fr;
        grid-template-areas:
            "header header"
            "sidebar main"
            "footer footer";
    }
    
    .dashboard-header {
        grid-area: header;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem 1rem;
        background-color: var(--primary-color);
        color: var(--text-light);
        box-shadow: var(--shadow);
    }
    
    .sidebar {
        grid-area: sidebar;
        background-color: var(--dark-bg);
        color: var(--text-light);
        padding: 1rem 0;
        height: 100%;
        overflow-y: auto;
    }
    
    .main-content {
        grid-area: main;
        background-color: var(--light-bg);
        padding: 1rem;
        overflow-y: auto;
    }
    
    .dashboard-footer {
        grid-area: footer;
        text-align: center;
        padding: 0.5rem;
        background-color: var(--dark-bg);
        color: var(--text-light);
    }
    
    /* Component Styles */
    .panel {
        background-color: white;
        border-radius: var(--border-radius);
        box-shadow: var(--shadow);
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    .chart-card {
        background-color: white;
        border-radius: var(--border-radius);
        box-shadow: var(--shadow);
        padding: 1rem;
        margin: 1rem 0;
        height: 300px;
    }
    
    /* Responsive Adaptations */
    @media (max-width: 768px) {
        .dashboard-container {
            grid-template-columns: 1fr;
            grid-template-areas:
                "header"
                "main"
                "footer";
        }
        
        .sidebar {
            display: none;
            position: fixed;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            z-index: 1000;
        }
        
        .sidebar.active {
            display: block;
        }
        
        .mobile-menu-toggle {
            display: block;
        }
    }
    ```

* **Frontend Component Architecture**:
  * **Security Dashboard Widgets**: Self-contained components with dedicated styling and JS functionality
  * **Dynamic Content Loading**: AJAX-based content loading with loading state indicators
  * **Notifications System**: Toast/snackbar notifications for system alerts and events
  * **Form Validation**: Client-side form validation with error highlighting and custom error messages
  * **Accessibility Considerations**: ARIA attributes, keyboard navigation support, and sufficient color contrast

* **Frontend Security Measures**:
  * **XSS Prevention**: Context-appropriate output escaping in Jinja2 templates
  * **CSRF Protection**: CSRF tokens embedded in forms
  * **Sanitization**: Input sanitization for user-provided content
  * **Safe JavaScript**: Proper DOM API usage to avoid JS injection vulnerabilities

### 4.3. User Management Interface

#### 4.3.1. User CRUD Operations
* **Implementation**: RESTful API endpoints with admin-only access
* **API Endpoints**:
  * `GET /api/admin/users`: List all users with pagination and filtering
  * `GET /api/admin/users/{user_id}`: Get detailed user information
  * `PUT /api/admin/users/{user_id}`: Update user details
  * `DELETE /api/admin/users/{user_id}`: Deactivate or delete user account
  * `POST /api/admin/users`: Create new user account (admin-created)
  * `POST /api/admin/users/{user_id}/reset-password`: Admin-initiated password reset
  * `POST /api/admin/users/{user_id}/lock`: Manually lock user account
  * `POST /api/admin/users/{user_id}/unlock`: Manually unlock user account

* **User Listing Implementation**:
  ```python
  @router.get("/admin/users", response_model=PaginatedUsers)
  async def list_users(
      page: int = Query(1, gt=0),
      page_size: int = Query(20, gt=0, le=100),
      search: Optional[str] = None,
      role_id: Optional[int] = None,
      is_active: Optional[bool] = None,
      is_locked: Optional[bool] = None,
      current_admin: User = Depends(get_current_admin_user),
      db: Session = Depends(get_db)
  ):
      """List users with pagination and filtering"""
      # Base query
      query = db.query(User)
      
      # Apply filters
      if search:
          search_term = f"%{search}%"
          query = query.filter(
              or_(
                  User.username.ilike(search_term),
                  User.email.ilike(search_term),
                  User.first_name.ilike(search_term),
                  User.last_name.ilike(search_term)
              )
          )
      
      if role_id is not None:
          query = query.filter(User.role_id == role_id)
          
      if is_active is not None:
          query = query.filter(User.is_active == is_active)
          
      if is_locked is not None:
          now = datetime.utcnow()
          if is_locked:
              query = query.filter(
                  User.account_locked_until.isnot(None),
                  User.account_locked_until > now
              )
          else:
              query = query.filter(
                  or_(
                      User.account_locked_until.is_(None),
                      User.account_locked_until <= now
                  )
              )
      
      # Get total count for pagination
      total_count = query.count()
      
      # Apply pagination
      offset = (page - 1) * page_size
      users = query.order_by(User.username).offset(offset).limit(page_size).all()
      
      # Format response
      return {
          "items": users,
          "total": total_count,
          "page": page,
          "page_size": page_size,
          "pages": (total_count + page_size - 1) // page_size
      }
  ```

## 5. Risk Assessment Engine - Technical Implementation

### 5.1. Dynamic Risk Scoring Algorithm

#### 5.1.1. Risk Factor Calculation
* **Implementation**: Weighted scoring algorithm with normalized factors
* **Risk Factors**:

| Factor | Weight | Description | Implementation |
|--------|--------|-------------|----------------|
| IP Newness | 15 | How new this IP is to the user | Checks login history for this IP |
| Geographic Location | 10-25 | Distance from common locations | Haversine distance calculation |
| Time Pattern | 5-20 | Deviation from typical login times | Standard deviation from historical pattern |
| Login Velocity | 10-30 | Rate of login attempts | Count of attempts in recent timeframe |
| Failed Attempts | 15-25 | Recent failures from user/IP | Count of failed attempts |
| Device Fingerprint | 15 | New device/browser for user | User-agent and other browser attributes |
| IP Reputation | 20-40 | Known malicious activity | Integration with reputation services or internal scoring |
| Time Anomaly | 5-15 | Unusual day/time for this user | Historical pattern analysis |

* **Implementation Details**:
  ```python
  def calculate_comprehensive_risk_score(user_id, ip_address, user_agent, timestamp, db):
      """
      Calculate a comprehensive risk score based on multiple weighted factors
      """
      risk_factors = []
      weights = []
      
      # 1. IP Newness Factor
      ip_newness_score = calculate_ip_newness_factor(user_id, ip_address, db)
      risk_factors.append(ip_newness_score)
      weights.append(15)
      
      # 2. Geographic Location Factor
      geo_score, geo_weight = calculate_geographic_factor(user_id, ip_address, db)
      risk_factors.append(geo_score)
      weights.append(geo_weight)  # Dynamic weight 10-25
      
      # 3. Time Pattern Factor
      time_pattern_score, time_pattern_weight = calculate_time_pattern_factor(user_id, timestamp, db)
      risk_factors.append(time_pattern_score)
      weights.append(time_pattern_weight)  # Dynamic weight 5-20
      
      # 4. Login Velocity Factor
      velocity_score, velocity_weight = calculate_login_velocity(user_id, ip_address, timestamp, db)
      risk_factors.append(velocity_score)
      weights.append(velocity_weight)  # Dynamic weight 10-30
      
      # 5. Failed Attempts Factor
      failures_score, failures_weight = calculate_failed_attempts_factor(user_id, ip_address, db)
      risk_factors.append(failures_score)
      weights.append(failures_weight)  # Dynamic weight 15-25
      
      # 6. Device Fingerprint Factor
      device_score = calculate_device_factor(user_id, user_agent, db)
      risk_factors.append(device_score)
      weights.append(15)
      
      # 7. IP Reputation Factor (if available)
      ip_rep_score, ip_rep_weight = get_ip_reputation_score(ip_address)
      if ip_rep_score is not None:
          risk_factors.append(ip_rep_score)
          weights.append(ip_rep_weight)  # Dynamic weight 20-40
      
      # 8. Time Anomaly Factor
      time_anomaly_score = calculate_time_anomaly(user_id, timestamp, db)
      risk_factors.append(time_anomaly_score)
      weights.append(10)  # Fixed weight
      
      # Calculate weighted average
      if sum(weights) > 0:
          final_score = sum(f * w for f, w in zip(risk_factors, weights)) / sum(weights)
          return min(100, max(0, round(final_score)))  # Ensure within 0-100 range
      
      # Default risk score if no factors calculated
      return 20  # Moderate default risk
  ```

#### 5.1.2. Individual Factor Algorithms

* **Geographic Factor Calculation**:
  ```python
  def calculate_geographic_factor(user_id, ip_address, db):
      """Calculate risk based on geographic location of IP address"""
      # Get geolocation for current IP
      geo_data = get_geolocation(ip_address)
      if not geo_data or not geo_data.get('latitude') or not geo_data.get('longitude'):
          return 50, 15  # Default moderate risk if geolocation fails
          
      current_lat = geo_data['latitude']
      current_lng = geo_data['longitude']
      current_country = geo_data['country_code']
      
      # Get user's login history
      user_locations = db.query(LoginLocation).filter(
          LoginLocation.user_id == user_id
      ).all()
      
      if not user_locations:
          # First login for this user
          return 75, 20  # High risk for first login, higher weight
          
      # Check if user has logged in from this country before
      country_logins = [loc for loc in user_locations if loc.country == current_country]
      if not country_logins:
          # First login from this country
          return 85, 25  # Very high risk, maximum weight
          
      # Find closest previous login location
      min_distance = float('inf')
      for loc in user_locations:
          if loc.latitude and loc.longitude:
              distance = haversine_distance(
                  loc.latitude, loc.longitude, current_lat, current_lng
              )
              min_distance = min(min_distance, distance)
      
      # Normalize distance to risk score
      if min_distance == float('inf'):
          risk_score = 60  # Moderate-high default
      elif min_distance < 50:
          # Within 50km - low risk
          risk_score = min_distance / 5  # 0-10 score
      elif min_distance < 500:
          # Within 500km - moderate risk
          risk_score = 10 + ((min_distance - 50) / 450 * 30)  # 10-40 score
      elif min_distance < 3000:
          # Within 3000km - high risk
          risk_score = 40 + ((min_distance - 500) / 2500 * 30)  # 40-70 score
      else:
          # Beyond 3000km - very high risk
          risk_score = 70 + min(20, (min_distance - 3000) / 5000 * 20)  # 70-90 score
      
      # Dynamic weight based on distance
      weight = min(25, max(10, 10 + (risk_score / 5)))
      
      # Check for impossible travel
      impossible_travel_boost = detect_impossible_travel(
          user_id, current_lat, current_lng, datetime.utcnow(), db
      )
      if impossible_travel_boost > 0:
          risk_score = max(risk_score, impossible_travel_boost)
          weight = 25  # Maximum weight for impossible travel
      
      return risk_score, weight
  ```

* **Time Pattern Factor**:
  ```python
  def calculate_time_pattern_factor(user_id, timestamp, db):
      """
      Calculate risk based on deviation from user's typical login times
      """
      current_hour = timestamp.hour
      current_day = timestamp.weekday()  # 0 = Monday, 6 = Sunday
      
      # Get user's login history timestamps
      one_month_ago = timestamp - timedelta(days=30)
      login_history = db.query(LoginAttempt).filter(
          LoginAttempt.user_id == user_id,
          LoginAttempt.success == True,
          LoginAttempt.timestamp > one_month_ago
      ).all()
      
      if len(login_history) < 5:
          # Not enough history to establish pattern
          return 40, 8  # Moderate risk, lower weight
      
      # Analyze hour pattern
      hour_counts = [0] * 24
      for login in login_history:
          hour_counts[login.timestamp.hour] += 1
          
      total_logins = len(login_history)
      hour_probabilities = [count / total_logins for count in hour_counts]
      
      # Calculate current hour probability
      current_hour_prob = hour_probabilities[current_hour]
      
      # Analyze day pattern
      day_counts = [0] * 7
      for login in login_history:
          day_counts[login.timestamp.weekday()] += 1
          
      day_probabilities = [count / total_logins for count in day_counts]
      
      # Calculate current day probability
      current_day_prob = day_probabilities[current_day]
      
      # Calculate risk based on probabilities
      hour_risk = 0
      if current_hour_prob == 0:
          # Never logged in during this hour
          hour_risk = 80
      elif current_hour_prob < 0.05:
          # Rarely logs in during this hour
          hour_risk = 60
      elif current_hour_prob < 0.1:
          # Occasionally logs in during this hour
          hour_risk = 40
      elif current_hour_prob < 0.2:
          # Regularly logs in during this hour
          hour_risk = 20
      else:
          # Commonly logs in during this hour
          hour_risk = 10
          
      # Similar for day risk
      day_risk = 0
      if current_day_prob == 0:
          day_risk = 70
      elif current_day_prob < 0.05:
          day_risk = 50
      elif current_day_prob < 0.1:
          day_risk = 30
      elif current_day_prob < 0.2:
          day_risk = 15
      else:
          day_risk = 5
          
      # Combined time risk (weighted more toward hour)
      combined_risk = (hour_risk * 0.7) + (day_risk * 0.3)
      
      # Dynamic weight based on pattern strength
      pattern_strength = max(hour_probabilities) - min(hour_probabilities)
      weight = 5 + (pattern_strength * 15)
      weight = min(20, max(5, weight))
      
      return combined_risk, weight
  ```

### 5.2. Risk Score Utilization

#### 5.2.1. Authentication Step Determination
* **Implementation**: Risk score thresholds determine required authentication steps
* **Code Example**:
  ```python
  @router.post("/login")
  async def login(
      form_data: OAuth2PasswordRequestForm = Depends(),
      request: Request = None,
      db: Session = Depends(get_db)
  ):
      # Get user from database
      user = authenticate_user(form_data.username, form_data.password, db)
      
      if not user:
          # Log failed login attempt
          log_failed_login(form_data.username, request.client.host, db)
          raise HTTPException(
              status_code=status.HTTP_401_UNAUTHORIZED,
              detail="Incorrect username or password",
              headers={"WWW-Authenticate": "Bearer"},
          )
      
      # Calculate risk score for this login attempt
      ip_address = request.client.host
      user_agent = request.headers.get("user-agent", "")
      risk_score = calculate_comprehensive_risk_score(
          user.id, ip_address, user_agent, datetime.utcnow(), db
      )
      
      # Determine required security level based on risk score
      security_level = determine_security_level(risk_score, user)
      
      if security_level == SecurityLevel.BLOCK:
          # High risk - block login
          handle_failed_login(user.username, ip_address, db)
          raise HTTPException(
              status_code=status.HTTP_403_FORBIDDEN,
              detail="Login blocked due to security concerns"
          )
      
      elif security_level == SecurityLevel.MFA_REQUIRED:
          # High risk - require MFA
          if user.mfa_enabled:
              # Generate challenge token for MFA step
              challenge_token = generate_mfa_challenge(user.id, db)
              return {
                  "status": "mfa_required",
                  "challenge_token": challenge_token,
                  "message": "MFA verification required"
              }
          else:
              # Fallback to email verification if MFA not set up
              email_token = generate_email_verification(user.id, user.email, db)
              return {
                  "status": "email_verification_required",
                  "verification_token": email_token,
                  "message": "Additional verification required"
              }
      
      elif security_level == SecurityLevel.EMAIL_VERIFICATION:
          # Medium-high risk - require email verification
          email_token = generate_email_verification(user.id, user.email, db)
          return {
              "status": "email_verification_required",
              "verification_token": email_token,
              "message": "Email verification required"
          }
      
      elif security_level == SecurityLevel.CAPTCHA:
          # Medium risk - require CAPTCHA
          if not form_data.captcha_token:
              return {
                  "status": "captcha_required",
                  "message": "CAPTCHA verification required"
              }
          
          # Verify CAPTCHA token
          captcha_valid = await verify_recaptcha(form_data.captcha_token)
          if not captcha_valid:
              raise HTTPException(
                  status_code=status.HTTP_400_BAD_REQUEST,
                  detail="Invalid CAPTCHA"
              )
      
      # If we reach here, authentication is complete
      # Create access token and log successful login
      access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
      access_token = create_access_token(
          data={"sub": str(user.id)},
          expires_delta=access_token_expires
      )
      
      # Log successful login and reset counters
      log_successful_login(user.id, ip_address, user_agent, risk_score, db)
      
      return {
          "access_token": access_token,
          "token_type": "bearer",
          "user_id": user.id,
          "username": user.username
      }
  ```

## 6. Deployment & Security Configuration

### 6.1. Environment-Specific Configuration

#### 6.1.1. Configuration Management
* **Implementation**: Environment variables with `.env` file support
* **Library**: `python-dotenv` for loading environment variables from file
* **Parameters**:
  * Database connection settings
  * JWT secret keys and configuration
  * Security settings (password policy, lockout parameters)
  * Email server configuration
  * External service API keys (GeoIP, reCAPTCHA)

* **Configuration Loading**:
  ```python
  from pydantic import BaseSettings, Field
  from typing import Optional
  
  class Settings(BaseSettings):
      # Database settings
      DATABASE_URL: str = "sqlite:///./app.db"
      
      # JWT settings
      JWT_ALGORITHM: str = "RS256"
      JWT_PRIVATE_KEY_PATH: str = "./keys/jwt-private.pem"
      JWT_PUBLIC_KEY_PATH: str = "./keys/jwt-public.pem"
      ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
      
      # Security settings
      PASSWORD_MIN_LENGTH: int = 8
      ACCOUNT_LOCKOUT_THRESHOLD: int = 5
      ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 15
      REQUIRE_EMAIL_VERIFICATION: bool = True
      
      # Email settings
      MAIL_SERVER: str
      MAIL_PORT: int = 587
      MAIL_USERNAME: str
      MAIL_PASSWORD: str
      MAIL_FROM: str
      MAIL_TLS: bool = True
      MAIL_SSL: bool = False
      
      # External services
      RECAPTCHA_SITE_KEY: Optional[str] = None
      RECAPTCHA_SECRET_KEY: Optional[str] = None
      
      # Application settings
      APP_NAME: str = "Adaptive Login Security System"
      DEBUG: bool = False
      
      class Config:
          env_file = ".env"
          env_file_encoding = "utf-8"
  
  # Create settings instance
  settings = Settings()
  ```

#### 6.1.2. Secure Deployment Recommendations
* **HTTPS Configuration**: Required for production deployment
  * TLS 1.2+ with strong cipher suites
  * HTTP Strict Transport Security (HSTS) headers
  * Redirect all HTTP traffic to HTTPS

* **Content Security Policy (CSP)** Implementation:
  ```python
  from fastapi.middleware.trustedhost import TrustedHostMiddleware
  from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
  
  # In production
  if not settings.DEBUG:
      app.add_middleware(HTTPSRedirectMiddleware)
      app.add_middleware(TrustedHostMiddleware, allowed_hosts=["yourdomain.com"])
      
      @app.middleware("http")
      async def add_security_headers(request, call_next):
          response = await call_next(request)
          
          # Content Security Policy
          response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; frame-src 'self' https://www.google.com/recaptcha/; style-src 'self' 'unsafe-inline';"
          
          # Other security headers
          response.headers["X-Content-Type-Options"] = "nosniff"
          response.headers["X-Frame-Options"] = "DENY"
          response.headers["X-XSS-Protection"] = "1; mode=block"
          response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
          response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
          
          return response
  ```

### 6.2. Logging & Monitoring

#### 6.2.1. Comprehensive Logging System
* **Library**: Python's built-in `logging` module with structured logging
* **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
* **Log Handlers**:
  * Console logging (development)
  * File logging with rotation (production)
  * Potential database logging for critical security events

* **Implementation**:
  ```python
  import logging
  import logging.handlers
  import json
  from datetime import datetime
  
  class SecurityLogFormatter(logging.Formatter):
      """Custom formatter for security logs with JSON output"""
      
      def format(self, record):
          log_data = {
              "timestamp": datetime.utcnow().isoformat(),
              "level": record.levelname,
              "message": record.getMessage(),
              "module": record.module,
              "function": record.funcName,
          }
          
          # Add extra attributes if present
          if hasattr(record, "user_id"):
              log_data["user_id"] = record.user_id
              
          if hasattr(record, "ip_address"):
              log_data["ip_address"] = record.ip_address
              
          if hasattr(record, "event_type"):
              log_data["event_type"] = record.event_type
          
          return json.dumps(log_data)
  
  def setup_logging():
      # Create logger
      logger = logging.getLogger("security")
      logger.setLevel(logging.INFO)
      
      # Create handlers
      console_handler = logging.StreamHandler()
      file_handler = logging.handlers.RotatingFileHandler(
          "security.log", maxBytes=10485760, backupCount=10
      )
      
      # Create formatter
      formatter = SecurityLogFormatter()
      
      # Set formatter for handlers
      console_handler.setFormatter(formatter)
      file_handler.setFormatter(formatter)
      
      # Add handlers to logger
      logger.addHandler(console_handler)
      logger.addHandler(file_handler)
      
      return logger
  
  security_logger = setup_logging()
  ```

* **Security Event Logging**:
  ```python
  def log_security_event(event_type, message, user_id=None, ip_address=None, severity="info"):
      """
      Log security event with consistent format
      """
      extra = {
          "event_type": event_type
      }
      
      if user_id:
          extra["user_id"] = user_id
          
      if ip_address:
          extra["ip_address"] = ip_address
      
      if severity == "critical":
          security_logger.critical(message, extra=extra)
      elif severity == "error":
          security_logger.error(message, extra=extra)
      elif severity == "warning":
          security_logger.warning(message, extra=extra)
      else:
          security_logger.info(message, extra=extra)
      
      # For critical events, also log to database
      if severity in ("critical", "error", "warning"):
          try:
              with get_db_context() as db:
                  event = SecurityEvent(
                      event_type=event_type,
                      severity=severity,
                      description=message,
                      user_id=user_id,
                      ip_address=ip_address
                  )
                  db.add(event)
                  db.commit()
          except Exception as e:
              security_logger.error(f"Failed to log security event to database: {str(e)}")
  ```

## 7. Conclusion & Future Directions

Error during registration: (sqlite3.IntegrityError) NOT NULL constraint failed: users.username
[SQL: INSERT INTO users (email, username, hashed_password, is_active, is_superuser, failed_login_attempts, last_failed_login, account_locked_until, mfa_enabled, mfa_secret, password_last_changed, last_login, risk_score, first_name, last_name, created_at, updated_at, role_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)]
[parameters: ('vkharikrishnan45@gmail.com', None, '$2b$12$j4jOeig6rC0IbBPedFkOxuzeY3RSIlliY5Hh5VKcxt6gRRtNychrK', 1, 0, 0, None, None, 0, None, '2025-03-30 14:02:24.344590', None, 0, 'savi', 'savi', '2025-03-30 14:02:24.344590', '2025-03-30 14:02:24.344590', None)]
(Background on this error at: https://sqlalche.me/e/20/gkpj)
The technical implementation leverages modern tools and best practices:
- FastAPI and SQLAlchemy provide a high-performance, type-safe backend framework
- Cryptographic libraries ensure secure password storage and token handling
- Chart.js delivers interactive data visualization for monitoring and analytics
- Comprehensive geolocation analysis detects login anomalies
- A flexible risk assessment engine adapts security requirements to the current threat level

Future development could extend the system with:
1. **Machine Learning Integration**: Using supervised or unsupervised learning models to improve anomaly detection and risk scoring based on historical data
2. **WebAuthn/FIDO2 Support**: Adding support for hardware security keys and platform authenticators
3. **Behavioral Biometrics**: Incorporating typing patterns, mouse movements, or other behavioral characteristics into the risk assessment
4. **Advanced Threat Intelligence**: Integrating with external threat feeds for enhanced IP and domain reputation scoring
5. **Zero Trust Architecture**: Evolving toward continuous verification rather than one-time authentication

With its robust foundation and extensible architecture, the system provides a solid platform for continuous security improvement in the face of evolving threats.