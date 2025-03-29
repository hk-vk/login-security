import requests
import ipaddress
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

class GeolocationData(BaseModel):
    """Model to store geolocation data for an IP address"""
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_vpn: Optional[bool] = False
    is_hosting: Optional[bool] = False
    is_tor: Optional[bool] = False
    risk_score: Optional[int] = 0

def is_private_ip(ip_address: str) -> bool:
    """Check if an IP address is private/internal"""
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False

def get_geolocation(ip_address: str) -> GeolocationData:
    """
    Get geolocation data for an IP address using a free IP geolocation API
    
    In production, you'd use a paid service with better reliability and features
    """
    if is_private_ip(ip_address):
        # Don't try to geolocate private IPs
        return GeolocationData(
            country_code="LOCAL",
            country_name="Local Network",
            city="Internal",
            risk_score=0
        )
    
    # For demo/development purposes we'll use a free API
    # In production use a reliable paid service like MaxMind, IPinfo, etc.
    try:
        # Free tier of ipapi.co (limited to 1000 requests/day)
        response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=3)
        
        if response.status_code == 200:
            data = response.json()
            
            # Basic risk assessment based on geolocation data
            risk_score = 0
            is_vpn = False
            is_hosting = False
            is_tor = False
            
            # Check if the IP is a hosting provider or data center
            # This is a simplified check - paid APIs provide this data directly
            hosting_keywords = ['amazon', 'google', 'microsoft', 'digital ocean', 'aws', 'azure']
            if data.get('org'):
                org = data.get('org', '').lower()
                if any(keyword in org for keyword in hosting_keywords):
                    is_hosting = True
                    risk_score += 20
            
            return GeolocationData(
                country_code=data.get('country_code'),
                country_name=data.get('country_name'),
                region=data.get('region'),
                city=data.get('city'),
                latitude=data.get('latitude'),
                longitude=data.get('longitude'),
                is_vpn=is_vpn,
                is_hosting=is_hosting,
                is_tor=is_tor,
                risk_score=risk_score
            )
        else:
            logger.warning(f"Failed to get geolocation data for {ip_address}: {response.status_code}")
            return GeolocationData()
            
    except Exception as e:
        logger.error(f"Error getting geolocation data for {ip_address}: {str(e)}")
        return GeolocationData()

def calculate_location_risk(geo_data: GeolocationData, user_id: int) -> Tuple[int, Dict[str, Any]]:
    """
    Calculate risk score based on location data and user history
    Returns: (risk_score, risk_factors)
    """
    risk_score = geo_data.risk_score or 0
    risk_factors = {}
    
    # Add risk if using VPN, hosting, or Tor
    if geo_data.is_vpn:
        risk_score += 30
        risk_factors["vpn"] = "Using VPN"
    
    if geo_data.is_hosting:
        risk_score += 20
        risk_factors["hosting"] = "Connection from hosting provider"
    
    if geo_data.is_tor:
        risk_score += 50
        risk_factors["tor"] = "Tor exit node detected"
    
    # In a real application, you would check:
    # 1. If this location is unusual for this user
    # 2. Distance from their usual login locations
    # 3. Impossible travel (logging in from two distant locations in a short time)
    # 4. Country-based risk factors
    
    # For this demo, we'll just return the basic risk score
    # In a production system, you'd query the database for user's login history
    
    return risk_score, risk_factors 