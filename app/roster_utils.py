import sys
import os
import json
import requests  # <-- Add this import
from app import create_app, db, mail
from sqlalchemy.exc import IntegrityError
import secrets
from sqlalchemy.exc import IntegrityError  # ✅ Fix missing import
from app.models import RosterChange, Flight, User # Import your models and database session
from flask import current_app
from datetime import datetime, timedelta
from collections import defaultdict

def normalize_duty(flight):
    """
    Given a flight record (a dictionary from the API), return a normalized duty dictionary.
    This dictionary should include only the fields that matter for detecting a change.
    """
    return {
        "flightDate": flight.get("flightDate"),
        "departureScheduled": flight.get("departureScheduled"),
        "arrivalScheduled": flight.get("arrivalScheduled"),
        "departurePlaceDescription": flight.get("departurePlaceDescription"),
        "arrivalPlaceDescription": flight.get("arrivalPlaceDescription"),
        "flightNumber": flight.get("flightNumberDescription"),
    }
def duty_dict(duty_list):
    """
    Convert a list of duty dictionaries into a dictionary keyed by, for example, flightDate.
    (Adjust the key as necessary; if multiple flights occur on the same day, you might key by flight id.)
    """
    return { duty["flightDate"]: duty for duty in duty_list }
def get_current_duty(crew_id):
    """
    Retrieve the current duty for a crew member.
    For example, this might return the most recently acknowledged duty or
    combine all flights for today.
    This is just a placeholder: adjust the logic as needed.
    """
    # Example: if there is a previous RosterChange that has been acknowledged,
    # use its updated_duty as the current duty.
    last_acknowledged = RosterChange.query.filter_by(crew_id=crew_id, acknowledged=True)\
                                          .order_by(RosterChange.acknowledged_at.desc())\
                                          .first()
    if last_acknowledged:
        return last_acknowledged.updated_duty
    else:
        # If no duty has been set, return an empty list (or some default)
        return []
    
def fetch_and_save_flights(date_from, date_to, auth_token):
    # Define the base URL for the API.
    base_url = "https://envision.airchathams.co.nz:8790/v1"
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Step 1: Get the list of employees.
    employees_url = f"{base_url}/Employees"
    emp_response = requests.get(employees_url, headers=headers)
    if emp_response.status_code != 200:
        current_app.logger.error(f"Error fetching employees: {emp_response.status_code}")
        return {"message": f"Error fetching employees: {emp_response.status_code}"}
    
    employees = emp_response.json()
    current_app.logger.info(f"Found {len(employees)} employees.")
    
    for emp in employees:
        # Get the employee number (for local DB lookup)
        employee_no = emp.get("employeeNo")
        if not employee_no:
            current_app.logger.warning("Employee number not found in employee data; skipping employee.")
            continue

        # Look up the local user by their crew_code (or employeeNo)
        user = User.query.filter_by(crew_code=employee_no).first()
        if not user:
            current_app.logger.warning(f"Employee with employeeNo {employee_no} not found in local DB. Skipping flights for this employee.")
            continue

        # Get the API's employee ID for making further API calls:
        emp_id = emp.get("id")
        
        # Optionally get more details about the employee:
        emp_details_url = f"{base_url}/Employees/{emp_id}"
        emp_details_response = requests.get(emp_details_url, headers=headers)
        if emp_details_response.status_code == 200:
            emp_details = emp_details_response.json()
        else:
            emp_details = emp  # fallback

        current_app.logger.info(f"Processing flights for employee {employee_no} ({emp_details.get('employeeUsername')})")
        
        # Step 2: Get flights for this employee within the date range.
        flights_url = f"{base_url}/Flights"
        params = {
            "employeeId": emp_id,
            "dateFrom": date_from,  # ISO format string, e.g. "2025-04-01T00:00:00"
            "dateTo": date_to       # ISO format string
        }
        flights_response = requests.get(flights_url, headers=headers, params=params)
        if flights_response.status_code != 200:
            current_app.logger.error(f"Error fetching flights for employee {employee_no}: {flights_response.status_code}")
            continue
        flights = flights_response.json()
        current_app.logger.info(f"Found {len(flights)} flights for employee {employee_no} in the given date range.")
        
    # Proceed to fetch and save flights for this employee...

        
        # Now fetch flights for this employee and process them...

        
        # Step 2: Get flights for this employee within the date range.
        flights_url = f"{base_url}/Flights"
        params = {
            "employeeId": emp_id,
            "dateFrom": date_from,  # ISO format string e.g., "2025-04-01T00:00:00"
            "dateTo": date_to       # ISO format string
        }
        flights_response = requests.get(flights_url, headers=headers, params=params)
        if flights_response.status_code != 200:
            current_app.logger.error(f"Error fetching flights for employee {emp_id}: {flights_response.status_code}")
            continue
        flights = flights_response.json()
        current_app.logger.info(f"Found {len(flights)} flights for employee {emp_id} in the given date range.")
        
        # Step 3: Loop through each flight and store in the local DB.
        for flight in flights:
            flight_id = flight.get("id")
            try:
                flight_date = datetime.fromisoformat(flight.get("flightDate"))
                departure_scheduled = datetime.fromisoformat(flight.get("departureScheduled"))
                arrival_scheduled = datetime.fromisoformat(flight.get("arrivalScheduled"))
            except Exception as e:
                current_app.logger.error(f"Date conversion error for flight {flight_id}: {e}")
                continue
            
            flight_record = Flight.query.filter_by(id=flight_id).first()
            if not flight_record:
                flight_record = Flight(
                    id = flight_id,
                    employee_id = user.id,  # associate the flight with this employee
                    flightStatusId = flight.get("flightStatusId"),
                    flightStatusDescription = flight.get("flightStatusDescription"),
                    flightDate = flight_date,
                    departureScheduled = departure_scheduled,
                    arrivalScheduled = arrival_scheduled,
                    departurePlaceDescription = flight.get("departurePlaceDescription"),
                    arrivalPlaceDescription = flight.get("arrivalPlaceDescription"),
                    flightNumber = flight.get("flightNumberDescription")
                )
                db.session.add(flight_record)
            else:
                flight_record.flightStatusDescription = flight.get("flightStatusDescription")
                flight_record.flightDate = flight_date
                flight_record.departureScheduled = departure_scheduled
                flight_record.arrivalScheduled = arrival_scheduled
                flight_record.departurePlaceDescription = flight.get("departurePlaceDescription")
                flight_record.arrivalPlaceDescription = flight.get("arrivalPlaceDescription")
                flight_record.flightNumber = flight.get("flightNumberDescription")
        
        db.session.commit()
    
    return {"message": "Flights fetched and saved successfully."}

def check_for_flight_changes(date_from, date_to, auth_token):
    """
    Fetch flights from the external API for each employee,
    compare them with the flights in the local DB,
    and record any differences as new RosterChange records.
    """
    base_url = "https://envision.airchathams.co.nz:8790/v1"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Fetch employees from the external API
    employees_url = f"{base_url}/Employees"
    emp_response = requests.get(employees_url, headers=headers)
    if emp_response.status_code != 200:
        current_app.logger.error(f"Error fetching employees: {emp_response.status_code}")
        return {"message": f"Error fetching employees: {emp_response.status_code}"}
    
    employees = emp_response.json()
    current_app.logger.info(f"Found {len(employees)} employees.")
    
    changes_detected = 0
    
    for emp in employees:
        employee_no = emp.get("employeeNo")
        if not employee_no:
            current_app.logger.warning("Employee number missing; skipping employee.")
            continue

        user = User.query.filter_by(crew_code=employee_no).first()
        if not user:
            current_app.logger.warning(f"Employee with employeeNo {employee_no} not found in local DB. Skipping flights for this employee.")
            continue

        emp_id = emp.get("id")
        current_app.logger.info(f"Processing flights for employee {employee_no} ({emp.get('employeeUsername')}).")

        flights_url = f"{base_url}/Flights"
        params = {
            "employeeId": emp_id,
            "dateFrom": date_from,
            "dateTo": date_to
        }
        flights_response = requests.get(flights_url, headers=headers, params=params)
        if flights_response.status_code != 200:
            current_app.logger.error(f"Error fetching flights for employee {employee_no}: {flights_response.status_code}")
            continue
        api_flights = flights_response.json()
        current_app.logger.info(f"Found {len(api_flights)} flights for employee {employee_no} in the given date range.")

        # Group the API flights by day
        api_duties_by_day = group_duties_by_date(api_flights, date_key="flightDate")
        
        for day, new_duties in api_duties_by_day.items():
            # Retrieve the current duty for that day
            # (Implement your own logic here; for example, if there's an acknowledged change for that day, that is the current duty.)
            current_duty = get_current_duty_for_day(user.id, day)  # should return a list or [] if none
            
            # If there is no current duty, then simply create a new change
            # and set both original and updated duty to the new duties.
            if not current_duty or len(current_duty) == 0:
                current_app.logger.info(f"No current duty for employee {employee_no} on {day}. Promoting new duty.")
                change_record = RosterChange(
                    crew_id=user.id,
                    original_duty=new_duties,  # push new duty directly into original
                    updated_duty=new_duties,
                    published_at=datetime.utcnow(),  # consider it published automatically
                    acknowledged=True,
                    acknowledged_at=datetime.utcnow()
                )
                db.session.add(change_record)
                changes_detected += 1
            else:
                # Otherwise, compare the current duty to the new duty.
                if compare_duties(new_duties, current_duty):
                    current_app.logger.info(f"Change detected for employee {employee_no} on {day}.")
                    change_record = RosterChange(
                        crew_id=user.id,
                        original_duty=current_duty,
                        updated_duty=new_duties,
                        published_at=None,
                        acknowledged=False,
                        acknowledged_at=None
                    )
                    db.session.add(change_record)
                    changes_detected += 1

        db.session.commit()
    
    return {"message": f"Daily flight changes processed for {changes_detected} changes."}

def group_duties_by_date(flights, date_key="flightDate"):
    """
    Given a list of flight dictionaries (from the API),
    group them by the date portion of the given key.
    Returns a dict mapping a date string (YYYY-MM-DD) to a list of normalized flight dicts.
    """
    groups = defaultdict(list)
    for flight in flights:
        dt_str = flight.get(date_key)
        if not dt_str:
            continue
        try:
            dt = datetime.fromisoformat(dt_str)
        except Exception as e:
            current_app.logger.error(f"Date conversion error for {dt_str}: {e}")
            continue
        # Use the date portion as key
        day_key = dt.date().isoformat()
        groups[day_key].append(normalize_flight(flight))
    return groups

def normalize_flight(flight):
    """
    Normalize the flight dictionary to only include the key fields that constitute a duty.
    """
    return {
        "flightDate": flight.get("flightDate"),  # full ISO string
        "flightNumber": flight.get("flightNumberDescription"),
        "departureScheduled": flight.get("departureScheduled"),
        "arrivalScheduled": flight.get("arrivalScheduled"),
        "departurePlaceDescription": flight.get("departurePlaceDescription"),
        "arrivalPlaceDescription": flight.get("arrivalPlaceDescription"),
        "flightStatusDescription": flight.get("flightStatusDescription")
    }

def get_current_duty_for_day(user_id, day):
    """
    Retrieve the most recent acknowledged duty for the user.
    For simplicity, we assume that the latest acknowledged RosterChange (for that user)
    holds the current duty. If you want per-day granularity, you may want to store
    the duty with the day key inside the JSON.
    Here, we assume that if no acknowledged duty exists, the current duty is [].
    """
    change = (RosterChange.query
              .filter_by(crew_id=user_id, acknowledged=True)
              .order_by(RosterChange.acknowledged_at.desc())
              .first())
    if change:
        # Expect change.updated_duty to be a list or dict representing the duty.
        return change.updated_duty
    return []  # default if nothing exists

def compare_duties(new_duty, current_duty):
    """
    Compare two duty structures.
    In this simple example, we assume both are lists of normalized flight dicts.
    We sort them by flightNumber and then compare.
    """
    def sort_key(f):
        return f.get("flightNumber", "")
    new_sorted = sorted(new_duty, key=sort_key)
    current_sorted = sorted(current_duty, key=sort_key)
    return new_sorted != current_sorted

def check_for_daily_changes(date_from, date_to, auth_token):
    base_url = "https://envision.airchathams.co.nz:8790/v1"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # Fetch employees from the API.
    employees_url = f"{base_url}/Employees"
    emp_response = requests.get(employees_url, headers=headers)
    if emp_response.status_code != 200:
        current_app.logger.error(f"Error fetching employees: {emp_response.status_code}")
        return {"message": f"Error fetching employees: {emp_response.status_code}"}
    employees = emp_response.json()
    current_app.logger.info(f"Found {len(employees)} employees.")
    
    changes_detected = 0
    
    for emp in employees:
        employee_no = emp.get("employeeNo")
        if not employee_no:
            current_app.logger.warning("Employee number missing; skipping employee.")
            continue
        
        # Lookup local user by employee number (crew_code)
        user = User.query.filter_by(crew_code=employee_no).first()
        if not user:
            current_app.logger.warning(f"Employee with employeeNo {employee_no} not found in local DB. Skipping flights for this employee.")
            continue
        
        emp_id = emp.get("id")
        current_app.logger.info(f"Processing flights for employee {employee_no} ({emp.get('employeeUsername')}).")
        
        # Fetch flights for this employee in the date range.
        flights_url = f"{base_url}/Flights"
        params = {
            "employeeId": emp_id,
            "dateFrom": date_from,
            "dateTo": date_to
        }
        flights_response = requests.get(flights_url, headers=headers, params=params)
        if flights_response.status_code != 200:
            current_app.logger.error(f"Error fetching flights for employee {employee_no}: {flights_response.status_code}")
            continue
        api_flights = flights_response.json()
        current_app.logger.info(f"Found {len(api_flights)} flights for employee {employee_no} in the given date range.")
        
        # Group flights by day (using a helper function)
        api_duties_by_day = group_duties_by_date(api_flights, date_key="flightDate")
        
        for day, new_duties in api_duties_by_day.items():
            # Retrieve current duty for this user on that day.
            current_duty = get_current_duty_for_day(user.id, day)
            if not current_duty or len(current_duty) == 0:
                # No current duty exists. Promote new duty.
                current_app.logger.info(f"No current duty for employee {employee_no} on {day}. Promoting new duty.")
                change_record = RosterChange(
                    crew_id=user.id,
                    original_duty=new_duties,  # copy new duty into original
                    updated_duty=new_duties,
                    published_at=datetime.utcnow(),  # mark as published automatically
                    acknowledged=True,
                    acknowledged_at=datetime.utcnow()
                )
                db.session.add(change_record)
                changes_detected += 1
            else:
                # Compare current duty and new duties; if different, record a change.
                if compare_duties(new_duties, current_duty):
                    current_app.logger.info(f"Change detected for employee {employee_no} on {day}.")
                    change_record = RosterChange(
                        crew_id=user.id,
                        original_duty=current_duty,
                        updated_duty=new_duties,
                        published_at=None,
                        acknowledged=False,
                        acknowledged_at=None
                    )
                    db.session.add(change_record)
                    changes_detected += 1
        
        db.session.commit()
    
    return {"message": f"Daily flight changes processed for {changes_detected} changes."}


def publish_roster_change(change_id):
    change = RosterChange.query.get(change_id)
    if change and not change.published_at:
        change.published_at = datetime.utcnow()
        change.acknowledged = True
        change.acknowledged_at = datetime.utcnow()
        # If there is no original duty, copy the updated duty over.
        if not change.original_duty or len(change.original_duty) == 0:
            change.original_duty = change.updated_duty
        db.session.commit()
    return change