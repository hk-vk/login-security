# Adaptive Login Security System

A comprehensive security system featuring adaptive login mechanisms, risk assessment, and real-time security monitoring for web applications.

## Features

- **Adaptive Authentication**: Adjusts security based on risk factors
- **Risk Assessment Engine**: Calculates risk scores from multiple security factors
- **Admin Dashboard**: Real-time monitoring of security metrics and system health
- **Brute Force Protection**: Automatically detects and blocks suspicious login attempts
- **Multi-factor Authentication (MFA)**: Email and time-based authenticator options
- **Geographic Analysis**: Detects and flags logins from unusual locations
- **Session Monitoring**: Identifies suspicious session activities and potential hijacking

## Getting Started

### Prerequisites

- Python 3.8+
- pip or pnpm

### Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/adaptive-login-security.git
cd adaptive-login-security
```

2. Install dependencies:
```
pip install -r requirements.txt
```

### Running the Application

Use the built-in run script to automatically initialize the database and start the application:

```
python run.py
```

This script will:
- Check if all requirements are installed
- Initialize the database if it doesn't exist or is empty
- Create default roles and admin user if needed
- Start the application with hot-reloading enabled

### Default Admin Credentials

After initialization, you can log in with:
- Email: admin@example.com
- Password: Admin123!

## Project Structure

- `app/`: Main application code
  - `database/`: Database configuration and connection management
  - `models/`: SQLAlchemy data models
  - `routes/`: API routes and endpoints
  - `static/`: Static assets (CSS, JS)
  - `templates/`: HTML templates
  - `utils/`: Utility functions including security and risk assessment
- `requirements.txt`: Project dependencies
- `run.py`: Application initialization and startup script

## Security Features

### Risk Assessment

The system calculates risk scores based on multiple factors:
- Brute force attempts
- Account takeover indicators 
- Session anomalies
- Geographic anomalies
- Data breach indicators
- System health metrics

### Adaptive Security Response

Based on the calculated risk score, the system can:
- Trigger additional authentication factors
- Apply rate limiting
- Log suspicious activities
- Block suspicious IPs
- Alert administrators

## License

This project is licensed under the MIT License - see the LICENSE file for details. 