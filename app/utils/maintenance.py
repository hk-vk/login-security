import os
import shutil
import zipfile
import json
import io
import tempfile
import logging
import datetime
from typing import Dict, Any, Tuple, List
from sqlalchemy.orm import Session
from fastapi.responses import StreamingResponse

from app.models.user import User
from app.models.login_history import LoginHistory
from app.models.session import Session as DbSession

logger = logging.getLogger(__name__)

def create_database_backup(db: Session) -> StreamingResponse:
    """
    Create a backup of the database by exporting essential data to JSON files
    and packaging them in a zip archive.
    
    This implementation only exports user data and login history for simplicity.
    In a production environment, you would want to use database-specific tools
    for proper backup.
    
    Returns a StreamingResponse with the zip file.
    """
    try:
        backup_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"backup_{backup_time}.zip"
        
        # Create a temporary directory to store the backup files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Export users (excluding sensitive information)
            users = db.query(User).all()
            user_data = []
            for user in users:
                user_data.append({
                    "id": user.id,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "is_active": user.is_active,
                    "is_superuser": user.is_superuser,
                    "created_at": user.created_at.isoformat() if user.created_at else None,
                    "last_login": user.last_login.isoformat() if user.last_login else None,
                    "failed_login_attempts": user.failed_login_attempts,
                    "account_locked_until": user.account_locked_until.isoformat() if user.account_locked_until else None,
                    "mfa_enabled": user.mfa_enabled,
                    # Excluding hashed_password and other sensitive fields
                })
            
            with open(os.path.join(temp_dir, "users.json"), "w") as f:
                json.dump(user_data, f, indent=2)
            
            # Export login history
            login_history = db.query(LoginHistory).all()
            history_data = []
            for entry in login_history:
                history_data.append({
                    "id": entry.id,
                    "user_id": entry.user_id,
                    "timestamp": entry.timestamp.isoformat(),
                    "ip_address": entry.ip_address,
                    "user_agent": entry.user_agent,
                    "success": entry.success,
                    "failure_reason": entry.failure_reason,
                    "risk_score": entry.risk_score,
                    "event_type": entry.event_type,
                    # Exclude full additional_data to avoid potentially sensitive information
                })
            
            with open(os.path.join(temp_dir, "login_history.json"), "w") as f:
                json.dump(history_data, f, indent=2)
            
            # Create metadata file
            metadata = {
                "backup_date": datetime.datetime.now().isoformat(),
                "user_count": len(users),
                "login_history_count": len(login_history),
                "version": "1.0"
            }
            
            with open(os.path.join(temp_dir, "metadata.json"), "w") as f:
                json.dump(metadata, f, indent=2)
            
            # Create a zip file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                # Add all files from the temp directory to the zip
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zip_file.write(file_path, arcname=arcname)
            
            # Reset buffer position
            zip_buffer.seek(0)
            
            # Return the zip file as a streaming response
            return StreamingResponse(
                zip_buffer,
                media_type="application/zip",
                headers={"Content-Disposition": f"attachment; filename={zip_filename}"}
            )
    
    except Exception as e:
        logger.error(f"Error creating database backup: {str(e)}")
        raise

def perform_log_cleanup(db: Session, retention_days: int = 90) -> Dict[str, Any]:
    """
    Delete old log entries and expired sessions based on retention period.
    Returns a summary of deleted items.
    """
    try:
        # Calculate cutoff date
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
        
        # Delete old login history entries
        deleted_logs = db.query(LoginHistory).filter(
            LoginHistory.timestamp < cutoff_date
        ).delete()
        
        # Delete expired sessions
        deleted_sessions = db.query(DbSession).filter(
            DbSession.expires_at < datetime.datetime.utcnow()
        ).delete()
        
        # Commit the changes
        db.commit()
        
        return {
            "success": True,
            "deleted_logs": deleted_logs,
            "deleted_sessions": deleted_sessions,
            "retention_days": retention_days,
            "cutoff_date": cutoff_date.isoformat()
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error during log cleanup: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

def optimize_database(db: Session) -> Dict[str, Any]:
    """
    Perform database optimization tasks.
    
    Note: This is a simplified implementation. In a production environment,
    you would use database-specific tools and commands.
    
    Returns a summary of optimization results.
    """
    try:
        # For SQLite, we can use VACUUM
        # For other databases, you would use different commands:
        # - PostgreSQL: VACUUM ANALYZE
        # - MySQL: OPTIMIZE TABLE
        
        # Execute a VACUUM command for SQLite
        # This assumes you're using SQLite; adjust accordingly for other databases
        db.execute("VACUUM")
        db.commit()
        
        return {
            "success": True,
            "message": "Database optimization completed successfully.",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        db.rollback()
        logger.error(f"Error during database optimization: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }

def get_system_health() -> Dict[str, Any]:
    """
    Get basic system health metrics.
    Returns a dictionary with health information.
    
    Note: This is a simplified implementation that only includes
    disk usage statistics. In a production environment, you would
    include more comprehensive health checks.
    """
    try:
        # Get disk usage statistics
        if os.name == 'posix':
            # Unix/Linux/MacOS
            disk_stats = shutil.disk_usage('/')
        else:
            # Windows or other
            disk_stats = shutil.disk_usage('C:')
        
        total_gb = disk_stats.total / (1024 ** 3)
        used_gb = disk_stats.used / (1024 ** 3)
        free_gb = disk_stats.free / (1024 ** 3)
        usage_percent = (disk_stats.used / disk_stats.total) * 100
        
        return {
            "disk_usage": {
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "usage_percent": round(usage_percent, 2)
            },
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting system health: {str(e)}")
        return {
            "error": str(e),
            "timestamp": datetime.datetime.utcnow().isoformat()
        } 