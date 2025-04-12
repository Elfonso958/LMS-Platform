import requests
from datetime import datetime, timedelta
from flask_login import current_user
from app import db
from app.models import RosterChange

# API Endpoint
ENVISION_API_URL = "https://envision.airchathams.co.nz:8790/v1/Flights"

def get_auth_token():
    """Retrieve the auth token from the session for the currently logged-in user."""
    return session.get("auth_token")  # Retrieve token from session


def fetch_roster_from_api():
    """Fetch roster data for all employees for the next 7 days from Envision API."""
    
    auth_token = get_auth_token()
    if not auth_token:
        print("No valid auth token found.")
        return None

    date_from = datetime.utcnow().strftime("%Y-%m-%d")
    date_to = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d")

    params = {
        "dateFrom": date_from,
        "dateTo": date_to,
        "offset": 0,
        "limit": 500  # Adjust if necessary
    }

    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}

    try:
        response = requests.get(ENVISION_API_URL, headers=headers, params=params)
        response.raise_for_status()  # Raise error if the request fails
        return response.json()  # Return parsed JSON
    except requests.RequestException as e:
        print(f"Error fetching roster from API: {e}")
        return None

def sync_roster_data():
    """Fetch roster from API, compare with stored data, and record changes."""
    
    api_data = fetch_roster_from_api()
    if not api_data:
        return "Failed to fetch roster data"

    for flight in api_data:
        crew_id = flight.get("crewMemberId")  # Match Envision API field
        new_duty = {
            "flightNumber": flight.get("flightNumber"),
            "departure": flight.get("departurePlaceDescription"),
            "arrival": flight.get("arrivalPlaceDescription"),
            "departureTime": flight.get("departureScheduled"),
            "arrivalTime": flight.get("arrivalScheduled")
        }

        # Find the last stored duty for this crew member
        existing_duty = RosterChange.query.filter_by(crew_id=crew_id, acknowledged=False).order_by(RosterChange.published_at.desc()).first()

        if existing_duty:
            existing_duty_dict = existing_duty.updated_duty
        else:
            existing_duty_dict = {}

        # Only store if there's a change
        if existing_duty_dict != new_duty:
            roster_change = RosterChange(
                crew_id=crew_id,
                original_duty=existing_duty_dict,  # Store previous duty
                updated_duty=new_duty,  # Store new duty
                published_at=datetime.utcnow(),
                acknowledged=False
            )
            db.session.add(roster_change)

    db.session.commit()
    return "Roster sync completed"
