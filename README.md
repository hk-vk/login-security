# Adaptive Login Security System

A secure authentication system with adaptive security features, built with FastAPI, SQLite, and HTML/CSS.

## Features

- Secure user registration and login
- Multi-factor authentication
- Adaptive security based on user behavior
- Admin dashboard for system monitoring
- Comprehensive security logging
- Brute force attack prevention

## Setup

1. Clone the repository
2. Install dependencies:
   ```
   pnpm install
   ```
3. Set up environment variables (copy .env.example to .env and configure)
4. Run database migrations:
   ```
   python -m app.database.init_db
   ```
5. Start the application:
   ```
   uvicorn app.main:app --reload
   ```

## Project Structure

- `app/`: Main application package
  - `routers/`: API routes
  - `models/`: SQLAlchemy models
  - `schemas/`: Pydantic schemas
  - `database/`: Database configuration
  - `core/`: Core application functionality
  - `utils/`: Utility functions
  - `templates/`: HTML templates
  - `static/`: Static files (CSS, JS)

## Security Features

See [plan.md](plan.md) for a complete list of security features and requirements. 