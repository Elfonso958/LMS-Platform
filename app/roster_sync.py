import requests
from datetime import datetime, timedelta
from flask import session  # ← needed to use session.get()
from app import db
from app.models import RosterChange

# API endpoint
ENVISION_API_URL = "https://envision.airchathams.co.nz:8790/v1/Flights"

def get_auth_token():
    """Retrieve the auth token from the session for the currently logged-in user."""
    return session.get("auth_token")


def fetch_roster_from_api():
    """Fetch roster data for all employees for the next 7 days from Envision API."""
    auth_token = get_auth_token()
    if not auth_token:
        app.logger.warning("No valid auth token found in session")
        return None

    date_from = datetime.utcnow().date().isoformat()
    date_to   = (datetime.utcnow() + timedelta(days=7)).date().isoformat()

    params = {
        "dateFrom": date_from,
        "dateTo":   date_to,
        "offset":   0,
        "limit":    500,
    }
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type":  "application/json",
    }

    try:
        resp = requests.get(ENVISION_API_URL, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        app.logger.error(f"Error fetching roster from API: {e}")
        return None


def sync_roster_data():
    """Fetch roster from API, compare with stored data, and record changes."""
    api_data = fetch_roster_from_api()
    if not api_data:
        return "Failed to fetch roster data"

    for flight in api_data:
        crew_id = flight.get("crewMemberId")
        if not crew_id:
            continue  # skip if no crewMemberId

        new_duty = {
            "flightNumber":             flight.get("flightNumber"),
            "departure":                flight.get("departurePlaceDescription"),
            "arrival":                  flight.get("arrivalPlaceDescription"),
            "departureTime":            flight.get("departureScheduled"),
            "arrivalTime":              flight.get("arrivalScheduled"),
        }

        # get the most recent unacknowledged duty
        last = (
            RosterChange.query
            .filter_by(crew_id=crew_id, acknowledged=False)
            .order_by(RosterChange.published_at.desc())
            .first()
        )
        existing = last.updated_duty if last else {}

        if existing != new_duty:
            rc = RosterChange(
                crew_id         = crew_id,
                original_duty   = existing,
                updated_duty    = new_duty,
                published_at    = datetime.utcnow(),
                acknowledged    = False
            )
            db.session.add(rc)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.exception("Failed to commit roster changes")
        return "Error syncing roster data"

    return "Roster sync completed"
