from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, Query, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from app.database.database import get_db
from app.models.user import User
from app.models.role import Role
from app.models.login_history import LoginHistory
from app.models.session import Session as DbSession
from app.models.device import Device
from app.models.security_settings import SecuritySettings
from app.schemas.admin import SecuritySettingsUpdate
from app.routers.auth import get_current_user
from app.core.security import get_password_hash
from app.utils.export import export_logs_to_csv, export_logs_to_json, generate_security_report, fetch_filter_logs
from app.utils.maintenance import create_database_backup, perform_log_cleanup, optimize_database, get_system_health
# Import psutil if available for system stats, handle gracefully if not
try:
    import psutil
except ImportError:
    psutil = None

router = APIRouter(tags=["admin"])

templates = Jinja2Templates(directory="app/templates")

# --- Pydantic Schema for User Update ---
class UserUpdateAdmin(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool
    is_superuser: bool

# REVISED Admin-only dependency
async def get_admin_user(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Dependency that checks if the user identified by the token is an active admin.
    Relies on get_current_user to handle token decoding and initial user identification.
    Returns the validated admin user object.
    """
    print(f"DEBUG (Dependency): Admin access check starting for user ID from token: {current_user.id if current_user else 'None'}")
    
    if not current_user:
         # This case should ideally be handled by get_current_user raising an exception
         print("DEBUG (Dependency): No current_user from get_current_user dependency.")
         raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, # Use 401 if token is invalid/missing
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
         )

    # Verify admin status from the database using the user from the token
    user = db.query(User).filter(User.id == current_user.id).first()
    
    if not user:
        print(f"DEBUG (Dependency): User ID {current_user.id} from token not found in DB.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, # Use 403 as token was valid but user lacks permission/exists
            detail="User not found in database."
        )

    if not user.is_active:
        print(f"DEBUG (Dependency): User {user.email} is inactive.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive."
        )

    if not user.is_superuser:
        print(f"DEBUG (Dependency): Access denied - user {user.email} is NOT an admin.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access admin area."
        )
    
    print(f"DEBUG (Dependency): Admin access GRANTED to {user.email}.")
    
    # OPTIONAL: Attach the validated admin user to the request state for potential use elsewhere
    # request.state.user = user 
    
    return user # Return the validated admin user object

# Admin dashboard
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db), # Keep DB session for dashboard data
    admin_user: User = Depends(get_admin_user) # Apply the dependency
):
    """Display the main admin dashboard with REAL statistics and metrics"""
    try:
        print("\n===== ADMIN DASHBOARD ROUTE (Fetching Real Data) =====")
        print(f"DEBUG: Admin user confirmed: {admin_user.email}")

        # --- Data Gathering ---
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(weeks=1)

        # User Stats
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.is_active == True).count()
        new_users_today = db.query(User).filter(User.created_at >= day_ago).count()

        # Login Stats (using LoginHistory)
        total_logins_day = db.query(LoginHistory).filter(LoginHistory.timestamp >= day_ago).count()
        failed_logins_day = db.query(LoginHistory).filter(LoginHistory.timestamp >= day_ago, LoginHistory.success == False).count()
        successful_logins_day = total_logins_day - failed_logins_day
        failed_logins_hour = db.query(LoginHistory).filter(LoginHistory.timestamp >= hour_ago, LoginHistory.success == False).count()
        unique_failed_ips_day = db.query(LoginHistory.ip_address).filter(LoginHistory.timestamp >= day_ago, LoginHistory.success == False).distinct().count()
        login_failure_rate_day = (failed_logins_day / total_logins_day * 100) if total_logins_day > 0 else 0

        # Session Stats (using DbSession)
        active_sessions = db.query(DbSession).filter(DbSession.is_active == True, DbSession.expires_at > now).count()
        total_sessions_day = db.query(DbSession).filter(DbSession.created_at >= day_ago).count()

        # Security Metrics
        mfa_enabled_users = db.query(User).filter(User.mfa_enabled == True, User.is_active == True).count()
        mfa_adoption_rate = (mfa_enabled_users / active_users * 100) if active_users > 0 else 0
        # NOTE: Compliance score and blocked IPs require more complex logic/models
        # compliance_score = calculate_compliance() # Placeholder
        # blocked_ips_count = db.query(BlockedIP).count() # Placeholder

        # Recent Activity (Mix of logins and potential admin actions)
        recent_logins = db.query(LoginHistory).order_by(LoginHistory.timestamp.desc()).limit(5).all()
        recent_activity = []
        for log in recent_logins:
            user_email = db.query(User.email).filter(User.id == log.user_id).scalar() or "Unknown User"
            status_text = "Success" if log.success else f"Failed ({log.failure_reason or '-'})"
            recent_activity.append({
                "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "user": user_email,
                "action": f"Login Attempt ({status_text})",
                "ip_address": log.ip_address
            })
        # Add placeholder admin actions if needed, ideally fetch from an audit log
        # recent_activity.append({"timestamp": ..., "user": admin_user.email, "action": "...", "ip_address": ...})
        recent_activity = sorted(recent_activity, key=lambda x: x["timestamp"], reverse=True)[:7]

        # Critical Alerts (Example: High-risk failed logins)
        critical_alerts = []
        high_risk_logins = db.query(LoginHistory).filter(
            LoginHistory.timestamp >= hour_ago,
            LoginHistory.success == False,
            LoginHistory.risk_score > 70 # Example threshold
        ).order_by(LoginHistory.timestamp.desc()).limit(3).all()

        for alert_log in high_risk_logins:
             user_email = db.query(User.email).filter(User.id == alert_log.user_id).scalar() or "Unknown User"
             critical_alerts.append({
                 "id": alert_log.id,
                 "severity": "High",
                 "message": f"High-risk failed login detected for {user_email}",
                 "details": f"IP: {alert_log.ip_address}, Reason: {alert_log.failure_reason or 'N/A'}, Score: {alert_log.risk_score}",
                 "timestamp": alert_log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                 "acknowledged": False # Example status
             })
        if not critical_alerts:
             critical_alerts.append({"id": 0, "severity": "Info", "message": "No critical security events in the last hour.", "details": "System normal.", "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"), "acknowledged": True})

        # System Status (Fetch real data if psutil is available)
        # Initialize with defaults
        system_status = {
            "cpu_usage": "N/A",
            "memory_usage": "N/A",
            "disk_usage": {"error": "Could not retrieve disk usage"},
            "last_checked": now.strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            # Attempt to get disk health
            disk_health = get_system_health() # REMOVED db argument
            if "error" not in disk_health:
                system_status["disk_usage"] = disk_health.get("disk_usage", {"error": "Disk usage data missing"})
                system_status["last_checked"] = disk_health.get("timestamp", system_status["last_checked"]) # Update timestamp if available
            else:
                print(f"Warning: get_system_health failed: {disk_health.get('error')}")
                # Keep default disk_usage error message

        except Exception as health_err:
             print(f"Warning: Error calling get_system_health: {health_err}")
             # Keep default disk_usage error message

        # Get CPU/Memory usage if psutil is available
        if psutil:
            try:
                system_status["cpu_usage"] = psutil.cpu_percent(interval=None) # Current CPU usage
                mem = psutil.virtual_memory()
                system_status["memory_usage"] = mem.percent # Current Memory usage
                # Update last checked time after successful psutil calls
                system_status["last_checked"] = now.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as ps_err:
                print(f"Warning: Could not fetch CPU/Memory usage with psutil: {ps_err}")
                # Keep N/A values set during initialization
        else:
            print("Warning: psutil library not found. CPU/Memory usage not available.")
            # Keep N/A values set during initialization


        # --- Chart Data (Fetch real data where possible) ---
        chart_labels_7_days = [(now - timedelta(days=i)).strftime("%a") for i in range(6, -1, -1)] # Last 7 days labels (e.g., Mon, Tue...)

        # User Activity (Logins/Registrations last 7 days)
        user_activity_logins = []
        user_activity_regs = []
        for i in range(6, -1, -1):
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
            end_date = start_date + timedelta(days=1)
            logins_count = db.query(LoginHistory).filter(LoginHistory.timestamp >= start_date, LoginHistory.timestamp < end_date).count()
            regs_count = db.query(User).filter(User.created_at >= start_date, User.created_at < end_date).count()
            user_activity_logins.append(logins_count)
            user_activity_regs.append(regs_count)

        # Security Incidents (Failed Logins last 7 days)
        security_failed_logins = []
        # Blocked IPs require a separate table/logic, using placeholder
        security_blocked_ips = [0] * 7 # Placeholder
        for i in range(6, -1, -1):
             start_date = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=i)
             end_date = start_date + timedelta(days=1)
             failed_count = db.query(LoginHistory).filter(LoginHistory.timestamp >= start_date, LoginHistory.timestamp < end_date, LoginHistory.success == False).count()
             security_failed_logins.append(failed_count)

        # Geographic Logins (Placeholder - requires GeoIP lookup)
        geographic_logins = {"labels": ["N/A"], "counts": [db.query(LoginHistory).count()]}

        # System Resources (Placeholder - needs time-series monitoring)
        system_resources = {
             "labels": ["Now"],
             "cpu": [system_status["cpu_usage"] if system_status["cpu_usage"] != "N/A" else 0],
             "memory": [system_status["memory_usage"] if system_status["memory_usage"] != "N/A" else 0]
        }

        chart_data = {
            "userActivity": {
                "labels": chart_labels_7_days,
                "logins": user_activity_logins,
                "registrations": user_activity_regs
            },
            "securityIncidents": {
                "labels": chart_labels_7_days,
                "failedLogins": security_failed_logins,
                "blockedIPs": security_blocked_ips # Placeholder data
            },
            "geographicLogins": geographic_logins, # Placeholder data
            "systemResources": system_resources # Placeholder data (shows current only)
        }

        # Construct the context for the template
        context = {
            "request": request,
            "admin_user": admin_user,
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "new_users_today": new_users_today,
                "active_sessions": active_sessions,
                "total_sessions_day": total_sessions_day,
                "total_logins_day": total_logins_day,
                "successful_logins_day": successful_logins_day,
                "failed_logins_day": failed_logins_day,
                "failed_logins_hour": failed_logins_hour,
            },
            "security_metrics": {
                "login_failure_rate_day": round(login_failure_rate_day, 2),
                "unique_failed_ips_day": unique_failed_ips_day,
                "mfa_adoption_rate": round(mfa_adoption_rate, 2),
                # "compliance_score": "N/A", # Removed placeholder or set to N/A
                # "blocked_ips_count": "N/A", # Removed placeholder or set to N/A
            },
            "system_status": system_status,
            "recent_activity": recent_activity,
            "critical_alerts": critical_alerts,
            "chart_data": chart_data,
            "title": "Admin Dashboard"
        }

        print("DEBUG: Rendering admin/dashboard.html template with REAL context")
        return templates.TemplateResponse("admin/dashboard.html", context)

    except HTTPException as http_exc:
        print(f"ERROR: HTTPException during dashboard rendering: {http_exc.detail}")
        raise http_exc
    except Exception as e:
        print(f"ERROR: Unexpected exception in admin_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        return templates.TemplateResponse(
            "errors/500.html",
            {"request": request, "detail": "An internal error occurred while loading the dashboard."},
            status_code=500
        )

@router.get("/dashboard/minimal", response_class=HTMLResponse)
async def admin_dashboard_minimal(
    request: Request,
    db: Session = Depends(get_db)
):
    """Display a minimal version of the admin dashboard for debugging"""
    print("DEBUG: Redirecting to minimal dashboard")
    return RedirectResponse(url="/admin/dashboard?minimal=true", status_code=status.HTTP_302_FOUND)

# User management
@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    page: int = Query(1, ge=1),
    search: str = Query(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Display the users management page with pagination and search"""
    items_per_page = 10
    query = db.query(User)
    
    # Apply search filter if provided
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (User.email.ilike(search_term)) |
            (User.first_name.ilike(search_term)) |
            (User.last_name.ilike(search_term))
        )
    
    # Get total count for pagination
    total_items = query.count()
    total_pages = (total_items + items_per_page - 1) // items_per_page
    
    # Ensure current page is valid
    current_page = min(max(1, page), max(1, total_pages))
    
    # Get users for current page
    offset = (current_page - 1) * items_per_page
    users = query.order_by(User.id).offset(offset).limit(items_per_page).all() # Added order_by
    
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "users": users,
            "current_page": current_page,
            "total_pages": total_pages,
            "total_items": total_items,
            "search": search,
            "admin_user": admin_user
        }
    )

@router.get("/users/{user_id}", response_model=UserUpdateAdmin) # Use the schema for response
async def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Get details for a specific user (for editing)"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user # FastAPI handles serialization based on response_model

@router.put("/users/{user_id}")
async def update_user_details(
    user_id: int,
    user_data: UserUpdateAdmin,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Update details for a specific user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from deactivating or removing admin status from themselves
    if user.id == admin_user.id:
        if not user_data.is_active:
            raise HTTPException(status_code=400, detail="Admin cannot deactivate their own account.")
        if not user_data.is_superuser:
            raise HTTPException(status_code=400, detail="Admin cannot remove their own admin status.")

    # Update fields
    user.email = user_data.email
    user.first_name = user_data.first_name
    user.last_name = user_data.last_name
    user.is_active = user_data.is_active
    user.is_superuser = user_data.is_superuser

    try:
        db.commit()
        db.refresh(user)
        return {"success": True, "message": "User updated successfully"}
    except Exception as e:
        db.rollback()
        print(f"Error updating user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update user")

@router.delete("/users/{user_id}")
async def delete_user_account(
    user_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Delete a specific user account"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from deleting themselves
    if user.id == admin_user.id:
        raise HTTPException(status_code=400, detail="Admin cannot delete their own account.")

    try:
        db.delete(user)
        db.commit()
        return {"success": True, "message": "User deleted successfully"}
    except Exception as e:
        db.rollback()
        print(f"Error deleting user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete user")

# Security settings
@router.get("/settings", response_class=HTMLResponse)
async def admin_security_settings(
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Display security settings page"""
    print(f"DEBUG: Admin settings page requested by {admin_user.email}")
    
    # Get current security settings
    settings = db.query(SecuritySettings).first()
    
    # If no settings exist, create default settings
    if not settings:
        settings = SecuritySettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    
    return templates.TemplateResponse(
        "admin/settings.html",
        {
            "request": request,
            "settings": settings,
            "admin_user": admin_user
        }
    )

@router.post("/settings")
async def update_security_settings(
    request: Request,
    settings_update: SecuritySettingsUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Update security settings"""
    # Get current security settings
    settings = db.query(SecuritySettings).first()
    
    # If no settings exist, create new settings
    if not settings:
        settings = SecuritySettings()
        db.add(settings)
    
    # Update settings
    update_data = settings_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(settings, key, value)
    
    settings.updated_at = datetime.utcnow()
    settings.last_updated_by = admin_user.email
    
    try:
        db.commit()
        db.refresh(settings)
        # Instead of redirect, return JSON response for fetch request
        return JSONResponse(content={"success": True, "message": "Settings updated successfully"})
    except Exception as e:
        db.rollback()
        print(f"Error updating security settings: {e}")
        # Return JSON error response
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to update settings"}
        )

# Security logs
@router.get("/logs", response_class=HTMLResponse)
async def admin_logs(
    request: Request,
    page: int = Query(1, ge=1),
    success: Optional[bool] = Query(None),
    user_id: Optional[int] = Query(None),
    ip_address: Optional[str] = Query(None),
    start_date_str: Optional[str] = Query(None),
    end_date_str: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Display security logs"""
    items_per_page = 20
    
    # Date parsing
    start_date = None
    end_date = None
    try:
        if start_date_str:
            start_date = datetime.fromisoformat(start_date_str)
        if end_date_str:
            # Add almost a full day to make the end date inclusive
            end_date = datetime.fromisoformat(end_date_str) + timedelta(days=1, microseconds=-1)
    except ValueError:
         raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    # Fetch filtered logs
    logs_query = fetch_filter_logs(
        db=db,
        start_date=start_date,
        end_date=end_date,
        success=success,
        user_id=user_id,
        ip_address=ip_address
    ) # Returns a query object

    total_items = logs_query.count()
    total_pages = (total_items + items_per_page - 1) // items_per_page
    current_page = min(max(1, page), max(1, total_pages))
    offset = (current_page - 1) * items_per_page
    
    logs = logs_query.offset(offset).limit(items_per_page).all()
    
    # Fetch users for dropdown filter
    users = db.query(User.id, User.email).order_by(User.email).all()

    return templates.TemplateResponse("admin/logs.html", {
        "request": request,
        "logs": logs,
        "current_page": current_page,
        "total_pages": total_pages,
        "total_items": total_items,
        "users": users, # For filter dropdown
        "filters": { # Pass current filters back to template
            "success": success,
            "user_id": user_id,
            "ip_address": ip_address,
            "start_date": start_date_str,
            "end_date": end_date_str
        },
         "admin_user": admin_user
    })

# Export routes
@router.get("/logs/export")
async def export_logs(
    format: str = Query("csv", enum=["csv", "json"]),
    success: Optional[bool] = Query(None),
    user_id: Optional[int] = Query(None),
    ip_address: Optional[str] = Query(None),
    start_date_str: Optional[str] = Query(None), # Default to last 30 days
    end_date_str: Optional[str] = Query(None),   # Default to now
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Export logs in CSV or JSON format"""
    # Date parsing and defaults
    try:
        end_date = datetime.utcnow() if not end_date_str else datetime.fromisoformat(end_date_str) + timedelta(days=1, microseconds=-1)
        start_date = (end_date - timedelta(days=30)) if not start_date_str else datetime.fromisoformat(start_date_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    logs = fetch_filter_logs(
        db=db,
        start_date=start_date,
        end_date=end_date,
        success=success,
        user_id=user_id,
        ip_address=ip_address
    ).all() # Fetch all matching logs for export

    if format == "csv":
        return export_logs_to_csv(logs)
    elif format == "json":
        return export_logs_to_json(logs)
    else:
        # Should be prevented by Query enum, but good practice
        raise HTTPException(status_code=400, detail="Invalid format specified.")

@router.get("/security/report")
async def security_report(
    start_date_str: Optional[str] = Query(None), # Default to last 30 days
    end_date_str: Optional[str] = Query(None),   # Default to now
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Generate a security report for the specified date range"""
    # Set default date range to last 30 days if not specified
    if not start_date_str or not end_date_str:
        start_date = datetime.now() - timedelta(days=30)
        end_date = datetime.now()
    else:
        try:
            start_date = datetime.fromisoformat(start_date_str)
            end_date = datetime.fromisoformat(end_date_str) + timedelta(days=1, microseconds=-1)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")
    
    return generate_security_report(db, start_date, end_date)

# System maintenance routes
@router.get("/maintenance", response_class=HTMLResponse)
async def maintenance_page(
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Display system maintenance page with health and stats."""
    health_data = get_system_health(db)
    
    # Add some DB stats (adjust for your DB)
    try:
        # Example for SQLite - adjust for others
        log_count = db.query(LoginHistory).count()
        user_count = db.query(User).count()
        session_count = db.query(DbSession).count()
        # db_size = os.path.getsize(DATABASE_URL.split('///')[1]) # If using file path
        db_stats = {
            "log_entries": log_count,
            "users": user_count,
            "active_sessions": db.query(DbSession).filter(DbSession.is_active == True, DbSession.expires_at > datetime.utcnow()).count(),
            "total_sessions": session_count,
            # "database_size_mb": round(db_size / (1024*1024), 2) if 'db_size' in locals() else "N/A"
             "database_size_mb": "N/A" # Requires DB specific query or file access
        }
    except Exception as e:
        print(f"Error getting DB stats: {e}")
        db_stats = {"error": "Could not retrieve database statistics."}

    return templates.TemplateResponse("admin/maintenance.html", {
        "request": request,
        "health": health_data,
        "db_stats": db_stats,
        "admin_user": admin_user
    })

@router.get("/maintenance/backup")
async def download_backup(
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Create and stream a database backup."""
    return create_database_backup(db)

# Use BackgroundTasks for potentially long operations
async def _run_cleanup(db: Session, days: int):
    print(f"Background Task: Starting log cleanup older than {days} days.")
    summary = perform_log_cleanup(db, retention_days=days)
    print(f"Background Task: Log cleanup finished. Summary: {summary}")

async def _run_optimize(db: Session):
    print("Background Task: Starting database optimization.")
    result = optimize_database(db)
    print(f"Background Task: Database optimization finished. Result: {result}")

@router.post("/maintenance/cleanup")
async def trigger_cleanup(
    background_tasks: BackgroundTasks,
    retention_days: int = Form(30), # Default 30 days
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Trigger log cleanup as a background task."""
    if retention_days < 1:
         raise HTTPException(status_code=400, detail="Retention days must be at least 1.")
         
    background_tasks.add_task(_run_cleanup, db, retention_days)
    return JSONResponse({"status": "success", "message": f"Log cleanup task scheduled (older than {retention_days} days)." })

@router.post("/maintenance/optimize")
async def trigger_optimize(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin_user: User = Depends(get_admin_user)
):
    """Trigger database optimization as a background task."""
    background_tasks.add_task(_run_optimize, db)
    return JSONResponse({"status": "success", "message": "Database optimization task scheduled."}) 