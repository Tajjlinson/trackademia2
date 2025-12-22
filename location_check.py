# location_check.py
from math import radians, sin, cos, sqrt, atan2

def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000.0  # meters
    lat1, lon1, lat2, lon2 = map(radians, [float(lat1), float(lon1), float(lat2), float(lon2)])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    return R * c

def check_attendance_location(student_lat, student_lon, session_lat, session_lon, allowed_distance_meters, accuracy=None):
    distance = haversine_m(student_lat, student_lon, session_lat, session_lon)
    # Optional: relax by GPS accuracy if provided
    buffer_m = float(accuracy) if accuracy else 0.0
    is_within = distance <= (float(allowed_distance_meters) + buffer_m)
    return is_within, distance
