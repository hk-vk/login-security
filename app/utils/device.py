from typing import Dict, Any, Optional
import hashlib
import json
import re

def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """Parse user agent string to extract browser, OS, and device information"""
    result = {
        "browser": "Unknown",
        "browser_version": "Unknown",
        "os": "Unknown",
        "os_version": "Unknown",
        "device_type": "desktop"  # Default to desktop
    }
    
    # Browser detection
    if "Firefox/" in user_agent:
        result["browser"] = "Firefox"
        match = re.search(r"Firefox/(\d+\.\d+)", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    elif "Chrome/" in user_agent and "Edg/" not in user_agent and "OPR/" not in user_agent:
        result["browser"] = "Chrome"
        match = re.search(r"Chrome/(\d+\.\d+\.\d+\.\d+)", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    elif "Safari/" in user_agent and "Chrome/" not in user_agent:
        result["browser"] = "Safari"
        match = re.search(r"Version/(\d+\.\d+)", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    elif "Edg/" in user_agent:
        result["browser"] = "Edge"
        match = re.search(r"Edg/(\d+\.\d+\.\d+\.\d+)", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    elif "OPR/" in user_agent:
        result["browser"] = "Opera"
        match = re.search(r"OPR/(\d+\.\d+\.\d+\.\d+)", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    elif "MSIE " in user_agent or "Trident/" in user_agent:
        result["browser"] = "Internet Explorer"
        match = re.search(r"MSIE (\d+\.\d+);", user_agent)
        if match:
            result["browser_version"] = match.group(1)
    
    # OS detection
    if "Windows" in user_agent:
        result["os"] = "Windows"
        match = re.search(r"Windows NT (\d+\.\d+)", user_agent)
        if match:
            version = match.group(1)
            version_map = {
                "10.0": "10",
                "6.3": "8.1",
                "6.2": "8",
                "6.1": "7",
                "6.0": "Vista",
                "5.2": "XP x64",
                "5.1": "XP"
            }
            result["os_version"] = version_map.get(version, version)
    elif "Macintosh" in user_agent:
        result["os"] = "macOS"
        match = re.search(r"Mac OS X (\d+[._]\d+[._]\d+)", user_agent)
        if match:
            result["os_version"] = match.group(1).replace("_", ".")
        else:
            match = re.search(r"Mac OS X (\d+[._]\d+)", user_agent)
            if match:
                result["os_version"] = match.group(1).replace("_", ".")
    elif "Linux" in user_agent and "Android" not in user_agent:
        result["os"] = "Linux"
    elif "Android" in user_agent:
        result["os"] = "Android"
        match = re.search(r"Android (\d+\.\d+)", user_agent)
        if match:
            result["os_version"] = match.group(1)
        result["device_type"] = "mobile"
        if "Mobile" not in user_agent:
            result["device_type"] = "tablet"
    elif "iPhone" in user_agent:
        result["os"] = "iOS"
        match = re.search(r"OS (\d+[._]\d+)", user_agent)
        if match:
            result["os_version"] = match.group(1).replace("_", ".")
        result["device_type"] = "mobile"
    elif "iPad" in user_agent:
        result["os"] = "iOS"
        match = re.search(r"OS (\d+[._]\d+)", user_agent)
        if match:
            result["os_version"] = match.group(1).replace("_", ".")
        result["device_type"] = "tablet"
    
    return result

def generate_device_fingerprint(
    ip_address: Optional[str], 
    user_agent: Optional[str]
) -> str:
    """Generate a fingerprint for the device based on its characteristics"""
    # Create a dictionary of device attributes
    device_data = {
        "ip": ip_address or "unknown",
        "user_agent": user_agent or "unknown"
    }
    
    # Parse the user agent if available
    if user_agent:
        device_info = parse_user_agent(user_agent)
        device_data.update(device_info)
    
    # Convert the device data to a string and hash it
    device_string = json.dumps(device_data, sort_keys=True)
    fingerprint = hashlib.sha256(device_string.encode()).hexdigest()
    
    return fingerprint

def get_device_name(user_agent: Optional[str]) -> str:
    """Generate a user-friendly device name based on the user agent"""
    if not user_agent:
        return "Unknown Device"
    
    device_info = parse_user_agent(user_agent)
    
    # Create a user-friendly device name
    device_type = device_info["device_type"].capitalize()
    os_name = device_info["os"]
    browser_name = device_info["browser"]
    
    return f"{device_type} - {os_name} - {browser_name}" 