#!/usr/bin/env python3
"""
Urban Scout MCP Server
======================
A Model Context Protocol server for urban photographers and city planners
to remotely scout locations for time-lapse video projects.

Features:
- Geocoding addresses to coordinates
- Street View static image URL generation
- Traffic flow analysis (one-way vs two-way detection)
- Nearby amenities search
"""

import os
import math
import base64
from typing import Optional

import httpx
import googlemaps
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.types import Image

# Load environment variables
load_dotenv()

# Google Maps client - lazily initialized on first use
_gmaps_client: Optional[googlemaps.Client] = None


def get_maps_api_key() -> str:
    """Return configured Google Maps API key, supporting legacy aliases."""
    return os.getenv("GOOGLE_MAPS_API_KEY") or os.getenv("URBAN_SCOUT_API_KEY") or ""


def get_gmaps_client() -> googlemaps.Client:
    """Get or initialize the Google Maps client."""
    global _gmaps_client
    if _gmaps_client is None:
        api_key = get_maps_api_key()
        if not api_key:
            raise ValueError(
                "GOOGLE_MAPS_API_KEY (or URBAN_SCOUT_API_KEY) environment variable is required. "
                "Please set it in your .env file or environment."
            )
        _gmaps_client = googlemaps.Client(key=api_key)
    return _gmaps_client

# Initialize FastMCP server
mcp = FastMCP(
    "Urban Scout",
    instructions="MCP server for scouting urban photography locations. "
    "Provides geocoding, street view imagery, traffic analysis, and amenity search."
)


def offset_coordinates(lat: float, lon: float, distance_meters: float, bearing_degrees: float) -> tuple[float, float]:
    """
    Calculate new coordinates offset from origin by distance and bearing.
    
    Args:
        lat: Origin latitude in degrees
        lon: Origin longitude in degrees  
        distance_meters: Distance to offset in meters
        bearing_degrees: Direction to offset (0=North, 90=East, 180=South, 270=West)
    
    Returns:
        Tuple of (new_lat, new_lon)
    """
    # Earth's radius in meters
    R = 6371000
    
    # Convert to radians
    lat_rad = math.radians(lat)
    lon_rad = math.radians(lon)
    bearing_rad = math.radians(bearing_degrees)
    
    # Angular distance
    angular_distance = distance_meters / R
    
    # Calculate new position
    new_lat_rad = math.asin(
        math.sin(lat_rad) * math.cos(angular_distance) +
        math.cos(lat_rad) * math.sin(angular_distance) * math.cos(bearing_rad)
    )
    
    new_lon_rad = lon_rad + math.atan2(
        math.sin(bearing_rad) * math.sin(angular_distance) * math.cos(lat_rad),
        math.cos(angular_distance) - math.sin(lat_rad) * math.sin(new_lat_rad)
    )
    
    return (math.degrees(new_lat_rad), math.degrees(new_lon_rad))


def calculate_bearing(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the bearing from point 1 to point 2.
    
    Returns:
        Bearing in degrees (0-360, where 0=North, 90=East)
    """
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lon = math.radians(lon2 - lon1)
    
    x = math.sin(delta_lon) * math.cos(lat2_rad)
    y = (math.cos(lat1_rad) * math.sin(lat2_rad) - 
         math.sin(lat1_rad) * math.cos(lat2_rad) * math.cos(delta_lon))
    
    bearing = math.degrees(math.atan2(x, y))
    return (bearing + 360) % 360


def bearing_to_direction(bearing: float) -> str:
    """Convert bearing in degrees to cardinal direction."""
    directions = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
    index = round(bearing / 45) % 8
    return directions[index]


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance between two points in meters using Haversine formula."""
    R = 6371000  # Earth's radius in meters
    
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = (math.sin(delta_lat / 2) ** 2 + 
         math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c


@mcp.tool()
def get_location_coordinates(address: str) -> dict:
    """
    Convert a street address or intersection into precise latitude/longitude coordinates.
    
    Useful for urban photographers to get exact coordinates for a shoot location,
    especially for street intersections like "Worth St & Centre St, NYC".
    
    Args:
        address: Street address or intersection to geocode
                 (e.g., "Worth St & Centre St, New York, NY")
    
    Returns:
        Dictionary containing:
        - formatted_address: The standardized address from Google
        - latitude: Decimal latitude
        - longitude: Decimal longitude
        - location_type: Accuracy level (ROOFTOP, RANGE_INTERPOLATED, etc.)
    """
    try:
        # Use Google Maps Geocoding API
        geocode_result = get_gmaps_client().geocode(address)
        
        if not geocode_result:
            return {
                "error": f"Could not find coordinates for address: {address}",
                "success": False
            }
        
        result = geocode_result[0]
        location = result["geometry"]["location"]
        
        return {
            "success": True,
            "formatted_address": result["formatted_address"],
            "latitude": location["lat"],
            "longitude": location["lng"],
            "location_type": result["geometry"].get("location_type", "UNKNOWN"),
            "place_id": result.get("place_id", "")
        }
        
    except googlemaps.exceptions.ApiError as e:
        return {"error": f"Google Maps API error: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


@mcp.tool()
def get_street_view(
    lat: float,
    lon: float,
    heading: int,
    pitch: int = 10,
    size: str = "600x400",
    fov: int = 90
):
    """
    Fetch and display a Google Street View image for a location.
    
    Perfect for photographers to preview potential camera angles and sight lines
    before arriving at a location. Adjust heading to look around intersections.
    Returns the actual image that will render inline.
    
    Args:
        lat: Latitude of the location
        lon: Longitude of the location
        heading: Camera direction in degrees (0=North, 90=East, 180=South, 270=West)
        pitch: Up/down angle in degrees (default 10 to see building facades, range -90 to 90)
        size: Image dimensions as "widthxheight" (default "600x400", max 640x640)
        fov: Field of view in degrees (default 90, range 10-120, wider = more fisheye)
    
    Returns:
        The Street View image rendered inline, or error details if unavailable.
    """
    try:
        # Validate parameters
        heading = heading % 360
        pitch = max(-90, min(90, pitch))
        fov = max(10, min(120, fov))
        
        # Parse and validate size
        try:
            width, height = map(int, size.split("x"))
            width = min(640, max(1, width))
            height = min(640, max(1, height))
            size = f"{width}x{height}"
        except ValueError:
            size = "600x400"
        
        # Get API key for URL construction
        api_key = get_maps_api_key()
        if not api_key:
            return {"error": "GOOGLE_MAPS_API_KEY (or URBAN_SCOUT_API_KEY) environment variable is required.", "success": False}
        
        # Construct the Street View Static API URL
        base_url = "https://maps.googleapis.com/maps/api/streetview"
        url = (
            f"{base_url}?"
            f"size={size}"
            f"&location={lat},{lon}"
            f"&heading={heading}"
            f"&pitch={pitch}"
            f"&fov={fov}"
            f"&key={api_key}"
        )
        
        # Fetch the image
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url)
            response.raise_for_status()
            
            # Check if we got an actual image (not an error response)
            content_type = response.headers.get("content-type", "")
            if "image" not in content_type:
                return {
                    "error": "No Street View imagery available for this location.",
                    "success": False,
                    "location": f"{lat}, {lon}"
                }
            
            # Get cardinal direction for context
            direction = bearing_to_direction(heading)
            
            # Return as MCP Image - this will render inline in Claude
            return Image(
                data=response.content,
                format="jpeg"
            )
        
    except httpx.HTTPStatusError as e:
        return {"error": f"Failed to fetch Street View image: HTTP {e.response.status_code}", "success": False}
    except httpx.RequestError as e:
        return {"error": f"Network error fetching Street View: {str(e)}", "success": False}
    except Exception as e:
        return {"error": f"Error fetching Street View: {str(e)}", "success": False}


@mcp.tool()
def analyze_traffic_flow(lat: float, lon: float, offset_meters: int = 20) -> dict:
    """
    Analyze whether a street segment is one-way or two-way traffic.
    
    Essential for photographers framing time-lapse traffic shots - knowing
    which direction vehicles flow helps plan camera placement and timing.
    
    The analysis works by:
    1. Taking two points offset East and West from the center
    2. Requesting routes in both directions via Google Routes API
    3. Comparing route distances - a massive detour indicates one-way restriction
    
    Args:
        lat: Latitude of the street location to analyze
        lon: Longitude of the street location to analyze
        offset_meters: Distance in meters to offset test points (default 20)
    
    Returns:
        Dictionary containing:
        - traffic_pattern: "one-way" or "two-way" or "undetermined"
        - flow_direction: Direction of traffic flow if one-way (e.g., "Eastbound")
        - analysis_details: Detailed route comparison data
    """
    
    def compute_route(origin: tuple[float, float], destination: tuple[float, float], api_key: str) -> int | None:
        """Call Google Routes API and return distance in meters, or None on failure."""
        url = "https://routes.googleapis.com/directions/v2:computeRoutes"
        headers = {
            "Content-Type": "application/json",
            "X-Goog-Api-Key": api_key,
            "X-Goog-FieldMask": "routes.distanceMeters"
        }
        body = {
            "origin": {
                "location": {
                    "latLng": {"latitude": origin[0], "longitude": origin[1]}
                }
            },
            "destination": {
                "location": {
                    "latLng": {"latitude": destination[0], "longitude": destination[1]}
                }
            },
            "travelMode": "DRIVE",
            "routingPreference": "TRAFFIC_UNAWARE"
        }
        
        with httpx.Client(timeout=15.0) as client:
            response = client.post(url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            if "routes" in data and len(data["routes"]) > 0:
                return data["routes"][0].get("distanceMeters", 0)
            return None
    
    try:
        api_key = get_maps_api_key()
        if not api_key:
            return {"error": "GOOGLE_MAPS_API_KEY (or URBAN_SCOUT_API_KEY) environment variable is required.", "success": False}
        
        # Calculate offset points (East and West of center)
        point_east = offset_coordinates(lat, lon, offset_meters, 90)  # 90° = East
        point_west = offset_coordinates(lat, lon, offset_meters, 270)  # 270° = West
        
        # Also check North-South for cross streets
        point_north = offset_coordinates(lat, lon, offset_meters, 0)
        point_south = offset_coordinates(lat, lon, offset_meters, 180)
        
        results = {
            "east_west": None,
            "north_south": None
        }
        errors = []
        
        # Analyze East-West traffic
        try:
            dist_e_to_w = compute_route(point_east, point_west, api_key)
            dist_w_to_e = compute_route(point_west, point_east, api_key)
            
            if dist_e_to_w is not None and dist_w_to_e is not None:
                # Direct route should be roughly 2x offset_meters
                expected_direct = offset_meters * 2
                threshold = expected_direct * 3  # 3x expected = likely detour
                
                e_to_w_direct = dist_e_to_w < threshold
                w_to_e_direct = dist_w_to_e < threshold
                
                results["east_west"] = {
                    "e_to_w_distance_m": dist_e_to_w,
                    "w_to_e_distance_m": dist_w_to_e,
                    "e_to_w_is_direct": e_to_w_direct,
                    "w_to_e_is_direct": w_to_e_direct
                }
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text[:200] if e.response else str(e)
            errors.append(f"East-West analysis failed: HTTP {e.response.status_code} - {error_detail}")
        except Exception as e:
            errors.append(f"East-West analysis failed: {str(e)}")
        
        # Analyze North-South traffic
        try:
            dist_n_to_s = compute_route(point_north, point_south, api_key)
            dist_s_to_n = compute_route(point_south, point_north, api_key)
            
            if dist_n_to_s is not None and dist_s_to_n is not None:
                expected_direct = offset_meters * 2
                threshold = expected_direct * 3
                
                n_to_s_direct = dist_n_to_s < threshold
                s_to_n_direct = dist_s_to_n < threshold
                
                results["north_south"] = {
                    "n_to_s_distance_m": dist_n_to_s,
                    "s_to_n_distance_m": dist_s_to_n,
                    "n_to_s_is_direct": n_to_s_direct,
                    "s_to_n_is_direct": s_to_n_direct
                }
        except httpx.HTTPStatusError as e:
            error_detail = e.response.text[:200] if e.response else str(e)
            errors.append(f"North-South analysis failed: HTTP {e.response.status_code} - {error_detail}")
        except Exception as e:
            errors.append(f"North-South analysis failed: {str(e)}")
        
        # Interpret results
        interpretations = []
        
        if results["east_west"]:
            ew = results["east_west"]
            if ew["e_to_w_is_direct"] and ew["w_to_e_is_direct"]:
                interpretations.append("East-West street: **Two-way traffic**")
            elif ew["e_to_w_is_direct"] and not ew["w_to_e_is_direct"]:
                interpretations.append("East-West street: **One-way Westbound** (traffic flows West)")
            elif not ew["e_to_w_is_direct"] and ew["w_to_e_is_direct"]:
                interpretations.append("East-West street: **One-way Eastbound** (traffic flows East)")
            else:
                interpretations.append("East-West street: Unable to determine (possible pedestrian zone)")
        
        if results["north_south"]:
            ns = results["north_south"]
            if ns["n_to_s_is_direct"] and ns["s_to_n_is_direct"]:
                interpretations.append("North-South street: **Two-way traffic**")
            elif ns["n_to_s_is_direct"] and not ns["s_to_n_is_direct"]:
                interpretations.append("North-South street: **One-way Southbound** (traffic flows South)")
            elif not ns["n_to_s_is_direct"] and ns["s_to_n_is_direct"]:
                interpretations.append("North-South street: **One-way Northbound** (traffic flows North)")
            else:
                interpretations.append("North-South street: Unable to determine (possible pedestrian zone)")
        
        if not interpretations:
            return {
                "success": False,
                "error": "Could not analyze traffic flow - no valid routes found",
                "details": errors if errors else ["No routes returned from Routes API"],
                "location": {"lat": lat, "lon": lon}
            }
        
        return {
            "success": True,
            "location": {"lat": lat, "lon": lon},
            "analysis": interpretations,
            "raw_data": results,
            "tip": "For time-lapse: Position camera facing the direction traffic is coming FROM for best headlight trails."
        }
        
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


@mcp.tool()
def find_nearby_amenities(
    lat: float,
    lon: float,
    keyword: str = "coffee",
    radius: int = 100
) -> dict:
    """
    Find nearby amenities like coffee shops, parks, or restrooms for shoot logistics.
    
    Long time-lapse shoots require rest spots and facilities nearby. This tool
    helps photographers find logistics bases within walking distance.
    
    Args:
        lat: Latitude of the shoot location
        lon: Longitude of the shoot location
        keyword: What to search for (e.g., "coffee", "restroom", "park", "food")
        radius: Search radius in meters (default 100, max 50000)
    
    Returns:
        Dictionary containing:
        - count: Number of places found
        - places: List of nearby amenities with name, distance, and direction
    """
    try:
        api_key = get_maps_api_key()
        if not api_key:
            return {"error": "GOOGLE_MAPS_API_KEY (or URBAN_SCOUT_API_KEY) environment variable is required.", "success": False}
        
        # Validate radius
        radius = max(1, min(50000, radius))
        
        # Use the new Places API (v1)
        url = "https://places.googleapis.com/v1/places:searchNearby"
        headers = {
            "Content-Type": "application/json",
            "X-Goog-Api-Key": api_key,
            "X-Goog-FieldMask": "places.displayName,places.location,places.types,places.rating,places.currentOpeningHours,places.formattedAddress"
        }
        body = {
            "locationRestriction": {
                "circle": {
                    "center": {"latitude": lat, "longitude": lon},
                    "radius": float(radius)
                }
            },
            "maxResultCount": 10
        }
        
        # Add text query for keyword-based search
        if keyword:
            body["includedTypes"] = []  # Will use text query instead
            # Map common keywords to place types
            keyword_type_map = {
                "coffee": ["cafe", "coffee_shop"],
                "food": ["restaurant", "food"],
                "restroom": ["public_restroom"],
                "park": ["park"],
                "parking": ["parking"],
                "gas": ["gas_station"],
                "pharmacy": ["pharmacy"],
                "atm": ["atm"],
                "hotel": ["hotel", "lodging"]
            }
            
            matched_types = keyword_type_map.get(keyword.lower(), [])
            if matched_types:
                body["includedTypes"] = matched_types
            else:
                # For other keywords, use text search instead
                body["textQuery"] = keyword
        
        with httpx.Client(timeout=15.0) as client:
            response = client.post(url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
        
        if not data.get("places"):
            return {
                "success": True,
                "count": 0,
                "places": [],
                "message": f"No '{keyword}' found within {radius}m of this location.",
                "suggestion": "Try increasing the radius or using a different keyword."
            }
        
        places = []
        for place in data["places"][:10]:
            place_location = place.get("location", {})
            place_lat = place_location.get("latitude", 0)
            place_lon = place_location.get("longitude", 0)
            
            # Calculate distance and bearing from shoot location
            distance = haversine_distance(lat, lon, place_lat, place_lon)
            bearing = calculate_bearing(lat, lon, place_lat, place_lon)
            direction = bearing_to_direction(bearing)
            
            # Get opening hours
            opening_hours = place.get("currentOpeningHours", {})
            open_now = opening_hours.get("openNow")
            
            place_info = {
                "name": place.get("displayName", {}).get("text", "Unknown"),
                "distance_meters": round(distance),
                "direction": direction,
                "types": place.get("types", [])[:3],
                "rating": place.get("rating"),
                "open_now": open_now,
                "address": place.get("formattedAddress", ""),
                "location": {"lat": place_lat, "lon": place_lon}
            }
            places.append(place_info)
        
        # Sort by distance
        places.sort(key=lambda x: x["distance_meters"])
        
        return {
            "success": True,
            "search_keyword": keyword,
            "search_radius_m": radius,
            "count": len(places),
            "places": places,
            "origin": {"lat": lat, "lon": lon}
        }
        
    except httpx.HTTPStatusError as e:
        error_detail = e.response.text[:300] if e.response else str(e)
        return {"error": f"Places API error: HTTP {e.response.status_code} - {error_detail}", "success": False}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}", "success": False}


@mcp.tool()
def generate_scout_map(
    center_lat: float,
    center_lon: float,
    markers: list[dict],
    zoom: int = 17,
    size: str = "640x480",
    map_type: str = "roadmap"
):
    """
    Generate a static map image with markers showing scouted locations.
    
    Creates a visual map that displays the main shoot location and all
    points of interest (amenities, camera positions, etc.) as markers.
    Perfect for planning sheets and location briefs.
    
    Args:
        center_lat: Center latitude of the map
        center_lon: Center longitude of the map
        markers: List of marker dicts with keys:
                 - lat: Latitude
                 - lon: Longitude  
                 - label: Single character label (A-Z) or empty
                 - color: Marker color (red, blue, green, yellow, purple, orange)
        zoom: Map zoom level (1=world, 20=buildings). Default 17 for street level.
        size: Image dimensions as "widthxheight" (max 640x640)
        map_type: Map style - "roadmap", "satellite", "terrain", or "hybrid"
    
    Returns:
        The map image rendered inline showing all marked locations.
    
    Example markers:
        [
            {"lat": 40.715, "lon": -74.002, "label": "X", "color": "red"},
            {"lat": 40.716, "lon": -74.001, "label": "C", "color": "blue"}
        ]
    """
    try:
        api_key = get_maps_api_key()
        if not api_key:
            return {"error": "GOOGLE_MAPS_API_KEY (or URBAN_SCOUT_API_KEY) environment variable is required.", "success": False}
        
        # Validate parameters
        zoom = max(1, min(20, zoom))
        map_type = map_type if map_type in ["roadmap", "satellite", "terrain", "hybrid"] else "roadmap"
        
        # Parse size
        try:
            width, height = map(int, size.split("x"))
            width = min(640, max(1, width))
            height = min(640, max(1, height))
            size = f"{width}x{height}"
        except ValueError:
            size = "640x480"
        
        # Build Static Maps API URL
        base_url = "https://maps.googleapis.com/maps/api/staticmap"
        params = [
            f"center={center_lat},{center_lon}",
            f"zoom={zoom}",
            f"size={size}",
            f"maptype={map_type}",
            f"key={api_key}"
        ]
        
        # Add markers
        color_map = {
            "red": "red", "blue": "blue", "green": "green",
            "yellow": "yellow", "purple": "purple", "orange": "orange",
            "white": "white", "black": "black"
        }
        
        for marker in markers[:10]:  # Limit to 10 markers
            m_lat = marker.get("lat", center_lat)
            m_lon = marker.get("lon", center_lon)
            m_label = marker.get("label", "")[:1].upper()  # Single char
            m_color = color_map.get(marker.get("color", "red"), "red")
            
            marker_str = f"color:{m_color}"
            if m_label:
                marker_str += f"|label:{m_label}"
            marker_str += f"|{m_lat},{m_lon}"
            
            params.append(f"markers={marker_str}")
        
        url = f"{base_url}?{'&'.join(params)}"
        
        # Fetch the map image
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url)
            response.raise_for_status()
            
            content_type = response.headers.get("content-type", "")
            if "image" not in content_type:
                return {
                    "error": "Failed to generate map image.",
                    "success": False
                }
            
            # Return as MCP Image
            return Image(
                data=response.content,
                format="png"
            )
        
    except httpx.HTTPStatusError as e:
        return {"error": f"Static Maps API error: HTTP {e.response.status_code}", "success": False}
    except Exception as e:
        return {"error": f"Error generating map: {str(e)}", "success": False}


# Run the server
if __name__ == "__main__":
    mcp.run()
