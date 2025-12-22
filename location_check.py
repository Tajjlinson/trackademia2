import math
import ipaddress

def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Simple distance calculation in meters using Haversine formula
    """
    # Earth radius in meters
    R = 6371000
    
    # Convert to radians
    lat1 = math.radians(float(lat1))
    lon1 = math.radians(float(lon1))
    lat2 = math.radians(float(lat2))
    lon2 = math.radians(float(lon2))
    
    # Differences
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    # Haversine formula
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    distance = R * c
    
    return distance

def check_attendance_location(student_lat, student_lon, session_lat, session_lon, max_distance, accuracy=None):
    """
    Check if student is within allowed distance from session
    """
    if session_lat is None or session_lon is None:
        return False, 0
    
    distance = calculate_distance(
        float(student_lat), float(student_lon),
        float(session_lat), float(session_lon)
    )
    
    # Account for GPS accuracy
    effective_max_distance = float(max_distance)
    if accuracy:
        effective_max_distance += float(accuracy)
    
    return distance <= effective_max_distance, round(distance, 2)