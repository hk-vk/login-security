import json
import csv
import io
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session, Query
from datetime import datetime
import pandas as pd
from fastapi.responses import StreamingResponse
from app.models.login_history import LoginHistory
from app.models.user import User

def export_logs_to_csv(logs: List[Any], user_dict: Dict[int, User]) -> StreamingResponse:
    """
    Export login history logs to CSV format
    """
    # Create a string buffer to hold the CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header row
    writer.writerow([
        'ID', 'Timestamp', 'User', 'IP Address', 'User Agent', 
        'Success', 'Failure Reason', 'Risk Score', 'Event Type',
        'Country', 'City'
    ])
    
    # Write data rows
    for log in logs:
        user_email = user_dict.get(log.user_id).email if log.user_id and log.user_id in user_dict else "Unknown"
        
        # Extract location data if available
        country = "Unknown"
        city = "Unknown"
        if log.additional_data and 'location' in log.additional_data:
            location = log.additional_data['location']
            country = location.get('country_name', 'Unknown')
            city = location.get('city', 'Unknown')
        
        writer.writerow([
            log.id,
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            user_email,
            log.ip_address,
            log.user_agent,
            'Success' if log.success else 'Failed',
            log.failure_reason or '',
            log.risk_score or 0,
            log.event_type or 'login',
            country,
            city
        ])
    
    # Return the CSV as a streaming response
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=security_logs_{datetime.now().strftime('%Y-%m-%d')}.csv"}
    )

def export_logs_to_json(logs: List[Any], user_dict: Dict[int, User]) -> StreamingResponse:
    """
    Export login history logs to JSON format
    """
    json_data = []
    
    for log in logs:
        user_email = user_dict.get(log.user_id).email if log.user_id and log.user_id in user_dict else "Unknown"
        
        log_entry = {
            'id': log.id,
            'timestamp': log.timestamp.isoformat(),
            'user_id': log.user_id,
            'user_email': user_email,
            'ip_address': log.ip_address,
            'user_agent': log.user_agent,
            'success': log.success,
            'failure_reason': log.failure_reason,
            'risk_score': log.risk_score,
            'event_type': log.event_type,
            'additional_data': log.additional_data
        }
        
        json_data.append(log_entry)
    
    # Return the JSON as a streaming response
    return StreamingResponse(
        io.BytesIO(json.dumps(json_data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=security_logs_{datetime.now().strftime('%Y-%m-%d')}.json"}
    )

def generate_security_report(db: Session, start_date: datetime, end_date: datetime) -> StreamingResponse:
    """
    Generate a comprehensive security report with statistics and metrics
    """
    # Query login history for the specified date range
    logs = db.query(LoginHistory).filter(
        LoginHistory.timestamp >= start_date,
        LoginHistory.timestamp <= end_date
    ).all()
    
    # Calculate security metrics
    total_logins = len(logs)
    successful_logins = sum(1 for log in logs if log.success)
    failed_logins = total_logins - successful_logins
    
    # Success rate
    success_rate = (successful_logins / total_logins * 100) if total_logins > 0 else 0
    
    # Count unique IPs
    unique_ips = len(set(log.ip_address for log in logs))
    
    # Count unique users
    unique_users = len(set(log.user_id for log in logs if log.user_id))
    
    # Calculate average risk score
    risk_scores = [log.risk_score for log in logs if log.risk_score is not None]
    avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    # Count high-risk logins
    high_risk_logins = sum(1 for log in logs if log.risk_score and log.risk_score >= 60)
    
    # Get failed login distribution by reason
    failure_reasons = {}
    for log in logs:
        if not log.success and log.failure_reason:
            reason = log.failure_reason
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
    
    # Create report data
    report_data = {
        'report_period': {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        },
        'summary': {
            'total_logins': total_logins,
            'successful_logins': successful_logins,
            'failed_logins': failed_logins,
            'success_rate': round(success_rate, 2),
            'unique_ips': unique_ips,
            'unique_users': unique_users,
            'avg_risk_score': round(avg_risk_score, 2),
            'high_risk_logins': high_risk_logins
        },
        'failure_analysis': failure_reasons
    }
    
    # Return the report as a JSON file
    return StreamingResponse(
        io.BytesIO(json.dumps(report_data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=security_report_{start_date.strftime('%Y-%m-%d')}_{end_date.strftime('%Y-%m-%d')}.json"}
    )

def fetch_filter_logs(db: Session, filters: Dict[str, Any]) -> Query:
    """
    Query logs with filters for export
    Returns a query object that can be further modified by the caller
    """
    query = db.query(LoginHistory)
    
    # Apply filters
    if 'start_date' in filters and filters['start_date']:
        query = query.filter(LoginHistory.timestamp >= filters['start_date'])
    
    if 'end_date' in filters and filters['end_date']:
        query = query.filter(LoginHistory.timestamp <= filters['end_date'])
    
    if 'success' in filters and filters['success'] is not None:
        query = query.filter(LoginHistory.success == filters['success'])
    
    if 'user_id' in filters and filters['user_id']:
        query = query.filter(LoginHistory.user_id == filters['user_id'])
    
    if 'ip_address' in filters and filters['ip_address']:
        query = query.filter(LoginHistory.ip_address.like(f"%{filters['ip_address']}%"))
    
    if 'min_risk_score' in filters and filters['min_risk_score'] is not None:
        query = query.filter(LoginHistory.risk_score >= filters['min_risk_score'])
    
    # Order by timestamp, newest first
    query = query.order_by(LoginHistory.timestamp.desc())
    
    return query # Return the query object instead of query.all() 