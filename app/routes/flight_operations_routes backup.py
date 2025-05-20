import sys
import os
import json
from sqlalchemy.exc import IntegrityError  # ✅ Fix missing import
import secrets
import requests
import io
import pdfkit
import random, string
import pytz
import random
from zoneinfo import ZoneInfo

nz_tz = ZoneInfo("Pacific/Auckland")

# Add the parent directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import render_template, redirect, url_for, flash, request, current_app, send_from_directory, g, jsonify, session,Response, send_file, Blueprint
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required,current_user,UserMixin
from app import create_app, db, mail
from app.models import Course, RoleType, UserSlideProgress, UserExamAttempt, Questions, Answers, UserAnswer, course_role, User, db, PayrollInformation, CrewCheck, CrewCheckMeta, CheckItem, user_role,CheckItemGrade, LineTrainingForm, Location, Port, HandlerFlightMap, GroundHandler, CrewAcknowledgement
from app.models import Task,TaskCompletion,Topic, LineTrainingItem,UserLineTrainingForm, Sector, RosterChange, Flight, FormTemplate,RoutePermission,Qualification,EmployeeSkill, EmailConfig, JobTitle, Timesheet, Location, PayrollPeriod,PayrollInformation, NavItem, NavItemPermission # Import your models and database session
from app.utils import extract_slides_to_png, calculate_exam_score, get_slide_count, admin_required, natural_sort_key, roles_required, generate_certificate
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.sql.expression import extract  # ✅ Import `extract`
from pptx import Presentation
from PIL import Image
import shutil, logging
from datetime import datetime, timedelta
from app.forms import LoginForm, LineTrainingFormEditForm, LineTrainingEmailConfigForm, CourseReminderEmailConfigForm, TimesheetForm  # Import your LoginForm
from flask_mail import Message
from app.email_utils import send_email_to_training_team, Send_Release_To_Supervisor_Email, send_course_reminders, send_qualification_reminders, send_qualification_expiry_email, send_timesheet_response
from sqlalchemy.orm import joinedload
from flask_apscheduler import APScheduler
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import SecureCookieSessionInterface
from app.roster_utils import normalize_duty, duty_dict, get_current_duty, fetch_and_save_flights, check_for_flight_changes, check_for_daily_changes
from fpdf import FPDF
from sqlalchemy import func
from sqlalchemy import text, bindparam
from cachetools import TTLCache
from app.forms import CREW_CHECK_FIELDS
from collections import defaultdict
from services.envision_api import fetch_all_employees, fetch_flights_from_envision,fetch_crew_from_envision  # Import the envision_api module
EMPLOYEE_CACHE = TTLCache(maxsize=1000, ttl=3600)  # Stores up to 1000 employees, expires in 1 hour
flightops_bp = Blueprint("FlightOps", __name__)


@flightops_bp.route('/update_flights', methods=['POST'])
@login_required
def update_flights():
    data = request.get_json()
    flights = data.get('flights')
    if not flights:
        return jsonify({"message": "No flight data provided."}), 400

    new_duty_list = [normalize_duty(f) for f in flights]
    current_duty_list = get_current_duty(current_user.id)  # returns a list of duty dicts

    changes_made = False
    for duty in new_duty_list:
        if duty not in current_duty_list:
            roster_change = RosterChange(
                crew_id=current_user.id,
                original_duty=[],   # if there's no previous duty
                updated_duty=duty,  # single duty dict for this flight
                published_at=None,
                acknowledged=False,
                acknowledged_at=None
            )
            db.session.add(roster_change)
            changes_made = True

    db.session.commit()
    if changes_made:
        return jsonify({"message": "Roster changes detected and recorded."}), 201
    else:
        return jsonify({"message": "No changes detected in the roster."}), 200

@flightops_bp.route('/fetch_save_flights', methods=['POST'])
@login_required
def fetch_save_flights_route():
    data = request.get_json()
    date_from = data.get("dateFrom")
    date_to = data.get("dateTo")
    auth_token = data.get("authToken")
    
    if not date_from or not date_to:
        return jsonify({"message": "Missing date range parameters."}), 400
    if not auth_token:
        current_app.logger.error("AUTH_TOKEN missing from payload.")
        return jsonify({"message": "Server configuration error: AUTH_TOKEN missing."}), 500

    result = check_for_daily_changes(date_from, date_to, auth_token)
    return jsonify(result), 200


@flightops_bp.route('/flight_operations')
@login_required
def flight_operations_dashboard():
    # Query roster changes as usual:
    changes = RosterChange.query.order_by(RosterChange.id.desc()).all()
    
    # Precompute a 'duty_day' attribute on each change for grouping purposes.
    # It extracts the date (YYYY-MM-DD) from the first flight's 'flightDate' in updated_duty,
    # or falls back to original_duty if updated_duty is empty.
    for change in changes:
        if change.updated_duty and len(change.updated_duty) > 0:
            change.duty_day = change.updated_duty[0]['flightDate'][:10]
        elif change.original_duty and len(change.original_duty) > 0:
            change.duty_day = change.original_duty[0]['flightDate'][:10]
        else:
            change.duty_day = "unknown"
    
    # We are no longer querying the Flights table, so current_duties is not needed.
    return render_template("flight_operations/flight_operations.html", 
                           user=current_user, 
                           changes=changes)

@flightops_bp.route("/fetch_all_flight_data", methods=["POST"])
def fetch_all_data():
    """Fetch Flights, Crew, and Employee Data in one call and track changes."""
    data = request.get_json()
    date_from = data.get("dateFrom")
    date_to = data.get("dateTo")
    auth_token = data.get("authToken")

    if not date_from or not date_to or not auth_token:
        return jsonify({"message": "Missing required parameters."}), 400

    # ✅ Fetch Employees once and cache them (if not already cached)
    if not EMPLOYEE_CACHE:
        print("🔄 Fetching employees from API...")
        fetch_all_employees(auth_token)

    flights = fetch_flights_from_envision(date_from, date_to, auth_token)
    stored_flights = []

    for flight_data in flights:
        flight_id = flight_data["id"]

        # ✅ Fetch and process crew data
        crew_list = []
        raw_crew_data = fetch_crew_from_envision(flight_id, auth_token)

        for crew_data in raw_crew_data:
            emp_id = crew_data.get("employeeId")

            # Try and find our local User record (this will be None if emp_id is null or not in your DB)
            user = None
            if emp_id is not None:
                user = User.query.filter_by(employee_id=emp_id).first()

            # Build the exact 4-element list you persist in Flight.crew:
            # [employeeId, username,  (you can still drop surname or firstName if you're not using them),
            #   position]
            crew_list.append([
                emp_id,
                user.username if user else None,   # <-- now your username instead of ""
                None,                               # <-- placeholder if you don’t need a 3rd field
                crew_data["crewPositionId"]
            ])

        # ✅ Normalize Crew JSON for comparison
        sorted_new_crew = normalize_crew_list(crew_list)

        # ✅ Retrieve Existing Flight (Check if already stored)
        existing_flight = Flight.query.filter_by(flightid=flight_id, is_update=False).first()
        existing_update = Flight.query.filter_by(flightid=flight_id, is_update=True).first()  # ✅ Fetch Existing Update

        if existing_update:
            # ✅ Remove the existing update before inserting the new one
            print(f"🗑️ Deleting old update for Flight {flight_id}...")
            db.session.delete(existing_update)
            db.session.commit()  # Commit before adding the new one

        if existing_flight:
            sorted_existing_crew = normalize_crew_list(existing_flight.crew if existing_flight.crew else [])

            # ✅ Normalize dates for comparison
            stored_departure_scheduled = normalize_datetime(existing_flight.departureScheduled)
            stored_arrival_scheduled = normalize_datetime(existing_flight.arrivalScheduled)
            new_departure_scheduled = normalize_datetime(flight_data.get("departureScheduled"))
            new_arrival_scheduled = normalize_datetime(flight_data.get("arrivalScheduled"))

            new_departure_estimate = normalize_datetime(flight_data.get("departureEstimate")) if flight_data.get("departureEstimate") else None
            new_arrival_estimate = normalize_datetime(flight_data.get("arrivalEstimate")) if flight_data.get("arrivalEstimate") else None

            # ✅ Ensure estimated times are only used if different from scheduled
            departure_changed = new_departure_estimate and new_departure_estimate != stored_departure_scheduled
            arrival_changed = new_arrival_estimate and new_arrival_estimate != stored_arrival_scheduled

            # ✅ Strict Comparison Check (Avoid unnecessary updates)
            field_changes = {
                "departureScheduled": stored_departure_scheduled != new_departure_scheduled,
                "arrivalScheduled": stored_arrival_scheduled != new_arrival_scheduled,
                "departureEstimate": departure_changed,
                "arrivalEstimate": arrival_changed,
                "flightNumberDescription": safe_strip(existing_flight.flightNumberDescription) != safe_strip(flight_data.get("flightNumberDescription")),
                "flightDate": normalize_datetime(existing_flight.flightDate) != normalize_datetime(flight_data.get("flightDate")),
                "departurePlaceDescription": safe_strip(existing_flight.departurePlaceDescription) != safe_strip(flight_data.get("departurePlaceDescription")),
                "arrivalPlaceDescription": safe_strip(existing_flight.arrivalPlaceDescription) != safe_strip(flight_data.get("arrivalPlaceDescription")),
                "flightLineDescription": safe_strip(existing_flight.flightLineDescription) != safe_strip(flight_data.get("flightLineDescription")),
                "crewListChanged": sorted_existing_crew != sorted_new_crew
            }

            has_real_changes = any(field_changes.values())

            if not has_real_changes:
                print(f"✅ No real changes detected for Flight {flight_id}. Skipping update.\n")
                continue

            print(f"🔄 Change detected for Flight {flight_id}, creating new update...\n")

            updated_flight = Flight(
                flightid=flight_id,
                update_id=f"{flight_id}_update",
                parent_id=existing_flight.id,
                is_update=True,
                flightNumberDescription=safe_strip(flight_data.get("flightNumberDescription")),
                flightDate=normalize_datetime(flight_data.get("flightDate")),
                departureScheduled=new_departure_scheduled,
                arrivalScheduled=new_arrival_scheduled,
                departureEstimate=new_departure_estimate if departure_changed else None,
                arrivalEstimate=new_arrival_estimate if arrival_changed else None,
                departurePlaceDescription=safe_strip(flight_data.get("departurePlaceDescription")),
                arrivalPlaceDescription=safe_strip(flight_data.get("arrivalPlaceDescription")),
                flightLineDescription=safe_strip(flight_data.get("flightLineDescription")),
                crew=sorted_new_crew
            )
            db.session.add(updated_flight)

        else:
            print(f"🆕 No existing flight found for ID {flight_id}. Saving as new original flight...")
            new_flight = Flight(
                flightid=flight_id,
                is_update=False,
                flightNumberDescription=safe_strip(flight_data.get("flightNumberDescription")),
                flightDate=normalize_datetime(flight_data.get("flightDate")),
                departureScheduled=normalize_datetime(flight_data.get("departureScheduled")),
                arrivalScheduled=normalize_datetime(flight_data.get("arrivalScheduled")),
                departureEstimate=normalize_datetime(flight_data.get("departureEstimate")),
                arrivalEstimate=normalize_datetime(flight_data.get("arrivalEstimate")),
                departurePlaceDescription=safe_strip(flight_data.get("departurePlaceDescription")),
                arrivalPlaceDescription=safe_strip(flight_data.get("arrivalPlaceDescription")),
                flightLineDescription=safe_strip(flight_data.get("flightLineDescription")),
                crew=sorted_new_crew
            )
            db.session.add(new_flight)
            db.session.commit()
            print(f"✅ New flight {flight_id} inserted.")

        stored_flights.append(flight_data)

    db.session.commit()
    return jsonify({
        "message": "Flights, Crew, and Employee Data stored successfully!",
        "flights": stored_flights
    }), 200


@flightops_bp.route('/publish_flights', methods=['POST'])
@login_required
@admin_required
def publish_flights():
    print("📬 Hit /publish_flights route")
    try:
        data = request.get_json()

        print("========== DEBUG: Received Data ==========")
        print(data)
        print("==========================================")

        selected_flight_ids = data.get("flights", [])
        global_remark = data.get("globalRemark", "")
        local_remarks = {k.strip(): v.strip() for k, v in data.get("localRemarks", {}).items()}
        send_to_crew = data.get("sendToCrew", False)
        send_to_default = data.get("sendToDefault", False)
        send_to_delay_system = data.get("sendToDelaySystem", False)
        additional_airport = data.get("additionalAirport", "")
        selected_handler_emails = data.get("selectedHandlerEmails", [])

        additional_airports = [code.strip().upper() for code in additional_airport.split(',') if code.strip()]

        if not selected_flight_ids:
            return jsonify({"error": "No flights selected"}), 400

        flights = Flight.query.filter(Flight.id.in_(selected_flight_ids)).all()
        flights.sort(key=lambda f: (f.departureEstimate or f.departureScheduled or datetime.max))
        if not flights:
            return jsonify({"error": "No valid flights found"}), 400

        # Group by aircraft
        grouped_by_aircraft = defaultdict(list)
        all_ports = set()
        for flight in flights:
            label = f"{flight.flightLineDescription or 'Unknown'} {flight.flightRegistrationDescription or ''}".strip()
            grouped_by_aircraft[label].append(flight)
            all_ports.add(flight.departurePlaceDescription)
            all_ports.add(flight.arrivalPlaceDescription)

        # Build handler -> ports mapping
        all_handlers = {}
        handler_selection_required = {}
        for port in all_ports.union(additional_airports):
            handlers = get_handler_emails_for_port(port)
            print(f"🔍 Port {port} has {len(handlers)} handlers")
            if handlers:
                for handler in handlers:
                    for email in handler['emails']:
                        all_handlers.setdefault(email, set()).add(port)
                if len(handlers) > 1 and send_to_default and not selected_handler_emails:
                    handler_selection_required[port] = handlers

        print("=== DEBUG: Pre-Modal Condition Check ===")
        print("send_to_default:", send_to_default)
        print("selected_handler_emails (empty?):", not selected_handler_emails)
        print("handler_selection_required (present?):", bool(handler_selection_required))
        print("========================================")

        if send_to_default and not selected_handler_emails and handler_selection_required:
            print("✅ Entering handler selection modal trigger")
            return jsonify({
                "success": False,
                "handler_selection_required": handler_selection_required,
                "message": "Multiple handler options found. Please select which contacts to use."
            })

        # Decide final recipients
        recipient_emails = set(selected_handler_emails) if selected_handler_emails else all_handlers.keys()

        handler_email_bodies = defaultdict(str)
        email_subject = f"Flight Schedule Revision - {datetime.now().strftime('%d %B %Y')}"

        for email in recipient_emails:
            body = """Dear Handling Team,

Please find below the revised flight schedule.

"""
            email_ports = all_handlers.get(email, set())

            for aircraft_label, aircraft_flights in grouped_by_aircraft.items():
                if not any(f.departurePlaceDescription in email_ports or f.arrivalPlaceDescription in email_ports for f in aircraft_flights):
                    continue

                body += f"\n{aircraft_label}\n"
                body += "Flight Number | Dep Location | ETD | Arr Location | ETA | Crew\n"
                body += "---------------------------------------------------------------------\n"

                ack_lookup = {
                    (ack.crew_member_id, ack.flight_id): ack
                    for ack in db.session.query(CrewAcknowledgement).filter(
                        CrewAcknowledgement.flight_id.in_([f.id for f in aircraft_flights])
                    ).all()
                }

                for flight in aircraft_flights:
                    dep_time = flight.departureEstimate or flight.departureScheduled
                    arr_time = flight.arrivalEstimate or flight.arrivalScheduled
                    etd = dep_time.astimezone(nz_tz).strftime("E%H%M") if dep_time else "N/A"
                    eta = arr_time.astimezone(nz_tz).strftime("E%H%M") if arr_time else "N/A"

                    crew_lines = []
                    if isinstance(flight.crew, list):
                        for member in flight.crew:
                            if isinstance(member, dict) and 'firstName' in member and 'surname' in member and 'employeeId' in member:
                                name = f"{member['firstName']} {member['surname']}"
                                emp_id = member['employeeId']
                                ack = ack_lookup.get((emp_id, flight.id))
                                status = "✅" if ack and ack.acknowledged else "❌"
                                crew_lines.append(f"{name} ({status})")
                            elif isinstance(member, list) and len(member) >= 3:
                                crew_lines.append(f"{member[1]} {member[2]} (❓)")
                            else:
                                crew_lines.append("Unknown Crew (❓)")
                    else:
                        crew_lines = ["Invalid Crew Format"]

                    line = f"{flight.flightNumberDescription} | {flight.departurePlaceDescription} | {etd} | {flight.arrivalPlaceDescription} | {eta} | {', '.join(crew_lines)}"
                    body += line + "\n"

                if local_remarks.get(aircraft_label):
                    body += f"Remark: {local_remarks[aircraft_label]}\n"
                body += "\n"

            handler_email_bodies[email] = body

        # Add crew acknowledgement records if flagged
        if send_to_crew:
            print("✍️ Creating CrewAcknowledgement entries...")
            for flight in flights:
                if isinstance(flight.crew, list):
                    for member in flight.crew:
                        emp_id = None
                        if isinstance(member, dict) and "employeeId" in member:
                            emp_id = member["employeeId"]
                        elif isinstance(member, list) and len(member) > 0:
                            try:
                                emp_id = int(member[0])
                            except:
                                pass
                        if emp_id:
                            exists = CrewAcknowledgement.query.filter_by(
                                flight_id=flight.id,
                                crew_member_id=emp_id
                            ).first()
                            if not exists:
                                db.session.add(CrewAcknowledgement(
                                    flight_id=flight.id,
                                    crew_member_id=emp_id,
                                    acknowledged=False
                                ))
            db.session.commit()
            print("✅ Acknowledgements created.")

        for email, body in handler_email_bodies.items():
            print("========== EMAIL PREVIEW FOR", email, "===========")
            print(f"Subject: {email_subject}\n")
            print(body)
            print("===================================")

        return jsonify({"success": True, "message": "Schedule published successfully (email not sent, only logged)."})

    except Exception as e:
        print("❌ Error in /publish_flights:", str(e))
        return jsonify({"error": str(e)}), 500
        
@flightops_bp.route('/publish_flights_preview', methods=['POST'])
@login_required
@admin_required
def publish_flights_preview():
    print("📬 Hit /publish_flights_preview route")

    data = request.get_json()
    selected_flight_ids = data.get("flights", [])
    send_to_default = data.get("sendToDefault", False)
    send_to_delay_system = data.get("sendToDelaySystem", False)
    additional_airports = [code.strip().upper() for code in data.get("additionalAirport", "").split(",") if code.strip()]
    handler_selection_required = {}

    if not selected_flight_ids:
        return jsonify({"success": False, "message": "No flights selected"}), 400

    flights = Flight.query.filter(Flight.id.in_(selected_flight_ids)).all()

    # Collect all relevant ports (from flights and delay system)
    port_set = set()
    for flight in flights:
        if flight.departurePlaceDescription:
            port_set.add(flight.departurePlaceDescription)
        if flight.arrivalPlaceDescription:
            port_set.add(flight.arrivalPlaceDescription)

    if send_to_delay_system:
        port_set.update(additional_airports)

    # Check for multiple handlers per port
    for port_code in port_set:
        handlers = get_handler_emails_for_port(port_code)
        if handlers and len(handlers) > 1 and send_to_default:
            handler_selection_required[port_code] = handlers

    if handler_selection_required:
        print("⚠️ Handler selection required for these ports:")
        for port, options in handler_selection_required.items():
            print(f"  - {port}: {len(options)} handler(s)")
        return jsonify({
            "success": False,
            "handler_selection_required": handler_selection_required,
            "message": "Multiple handler options found. Please select which contacts to use."
        })

    print("✅ All ports have 1 or 0 handlers — no modal needed.")
    return jsonify({"success": True})

@flightops_bp.route('/get_airport_codes')
@login_required
def get_airport_codes():
    ports = Port.query.with_entities(Port.iata_code).filter(
        Port.iata_code.isnot(None),
        Port.iata_code != ''
    ).all()
    
    # Flatten and uppercase
    codes = [p[0].upper() for p in ports if p[0]]
    
    return jsonify({"airports": sorted(codes)})


@flightops_bp.route("/fetch_all_employees", methods=["POST"])
def fetch_all_employees_route():
    """Fetch all employees and store them in cache."""
    data = request.get_json()
    auth_token = data.get("authToken")

    if not auth_token:
        return jsonify({"message": "Missing auth token"}), 400

    fetch_all_employees(auth_token)
    return jsonify({"message": "Employees cached successfully!"}), 200

def convert_to_nz_time(utc_time, only_time=False, return_date_obj=False):
    """Converts UTC time to New Zealand local time, with optional format choices."""
    if not utc_time:
        return None
    nz_timezone = pytz.timezone("Pacific/Auckland")
    nz_time = utc_time.astimezone(nz_timezone)

    if return_date_obj:
        return nz_time.date()  # ✅ Return as a Date Object for Filtering
    if only_time:
        return nz_time.strftime("%H:%M:%S")  # ✅ Time Only (HH:MM:SS)
    return nz_time.strftime("%Y-%m-%d")  # ✅ Full Date (YYYY-MM-DD)

@flightops_bp.route("/get_flights", methods=["GET"])
def get_flights():
    """Fetch flights filtered by the selected date (now using NZ local date)."""
    try:
        selected_date = request.args.get("date")  # Get date from frontend

        if selected_date:
            try:
                selected_date_obj = datetime.strptime(selected_date, "%Y-%m-%d").date()

                # ✅ Convert Departure Time to NZ Local Before Filtering
                flights = Flight.query.all()
                flights = [flight for flight in flights if convert_to_nz_time(flight.departureScheduled, return_date_obj=True) == selected_date_obj]

            except ValueError:
                return jsonify({"message": "Invalid date format"}), 400
        else:
            flights = Flight.query.all()  # Return all flights if no date is provided

        if not flights:
            return jsonify({"flights": []}), 200  # ✅ Return an empty list if no flights exist on that date

        flight_data = []
        for flight in flights:
            updated_flight = Flight.query.filter_by(parent_id=flight.id).first()

            flight_data.append({
                "original": {
                    "id": flight.id,
                    "is_update": flight.is_update,  # ✅ Include is_update flag
                    "flightNumberDescription": flight.flightNumberDescription,
                    "departureScheduled": convert_to_nz_time(flight.departureScheduled, only_time=True),  # ✅ Time Only
                    "arrivalScheduled": convert_to_nz_time(flight.arrivalScheduled, only_time=True),  # ✅ Time Only
                    "departureDate": convert_to_nz_time(flight.departureScheduled),  # ✅ Get the Date Separately
                    "departurePlaceDescription": flight.departurePlaceDescription,  
                    "arrivalPlaceDescription": flight.arrivalPlaceDescription,  
                    "flightLineDescription": flight.flightLineDescription or "Unknown Aircraft",
                    "crew": flight.crew or "No Crew Assigned"
                },
                "updated": {
                    "id": updated_flight.id if updated_flight else None,
                    "is_update": updated_flight.is_update if updated_flight else None,  # ✅ Include is_update flag
                    "flightNumberDescription": updated_flight.flightNumberDescription if updated_flight else None,

                    # ✅ Use Estimated Departure/Arrival if available, else fall back to Scheduled
                    "departureScheduled": convert_to_nz_time(updated_flight.departureEstimate, only_time=True) if updated_flight and updated_flight.departureEstimate else convert_to_nz_time(updated_flight.departureScheduled, only_time=True) if updated_flight else None,
                    "arrivalScheduled": convert_to_nz_time(updated_flight.arrivalEstimate, only_time=True) if updated_flight and updated_flight.arrivalEstimate else convert_to_nz_time(updated_flight.arrivalScheduled, only_time=True) if updated_flight else None,

                    "departurePlaceDescription": updated_flight.departurePlaceDescription if updated_flight else None,
                    "arrivalPlaceDescription": updated_flight.arrivalPlaceDescription if updated_flight else None,
                    "flightLineDescription": updated_flight.flightLineDescription if updated_flight else None,
                    "crew": updated_flight.crew if updated_flight else None
                } if updated_flight else None
            })

        return jsonify({"flights": flight_data}), 200

    except Exception as e:
        print(f"❌ Error fetching flights: {e}")
        return jsonify({"message": "Failed to fetch flights"}), 500

@flightops_bp.route('/ports')
def list_ports():
    ports = Port.query.all()
    return render_template('Port_info/port_info.html', ports=ports)

@flightops_bp.route('/get_port_details/<iata_code>', methods=['GET'])
@login_required
def get_port_details(iata_code):
    iata_code = iata_code.upper()
    port = Port.query.filter_by(iata_code=iata_code).first()

    if not port:
        return jsonify({"error": "Port not found"}), 404

    return jsonify({
        "port_name": port.port_name,
        "icao_code": port.icao_code,
        "iata_code": port.iata_code,
        "country": port.country,
        "notes": port.notes or "No additional notes",
        "ground_handlers": [
            {
                "id": handler.id,  # ✅ Ensure handler ID is included
                "handling_agent": handler.handling_agent,
                "contact_person": handler.contact_person or "",
                "agent_contact": handler.agent_contact or "",
                "agent_frequency": handler.agent_frequency or "",
                "gpu_available": "Yes" if handler.gpu_available else "No",
                "fuel_details": handler.fuel_details or "No fueling information available.",
                "primary_email": handler.primary_email or "",
                "additional_contacts": handler.additional_contacts or ""
            }
            for handler in port.ground_handlers
        ]
    })

@flightops_bp.route('/add_port', methods=['POST'])
@login_required
@admin_required
def add_port():
    data = request.form
    try:
        new_port = Port(
            port_name=data.get('port_name').strip(),
            iata_code=data.get('iata_code').strip().upper(),
            icao_code=data.get('icao_code').strip().upper(),
            country=data.get('country').strip()
        )
        db.session.add(new_port)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)})


@flightops_bp.route('/add_handler', methods=['POST'])
@login_required
@admin_required
def add_handler():
    data = request.form
    iata_code = data.get('iata_code', '').upper()
    port = Port.query.filter_by(iata_code=iata_code).first()
    if not port:
        return jsonify({"error": "Invalid IATA code - port not found"}), 400

    new_handler = GroundHandler(
        port_id=port.id,
        handling_agent=data.get('handling_agent'),
        contact_person=data.get('contact_person'),
        agent_contact=data.get('agent_contact'),
        agent_frequency=data.get('agent_frequency'),
        gpu_available=data.get('gpu_available') == "true",
        primary_email=data.get('primary_email'),
        additional_contacts=data.get('additional_contacts')
    )

    db.session.add(new_handler)
    db.session.commit()
    return jsonify({"success": True})


@flightops_bp.route('/edit_handler', methods=['POST'])
@login_required
@admin_required
def edit_handler():
    data = request.form
    handler = GroundHandler.query.get(data.get("handler_id"))

    if not handler:
        return jsonify({"error": "Handler not found"}), 404

    handler.handling_agent = data.get("handling_agent")
    handler.contact_person = data.get("contact_person")
    handler.agent_contact = data.get("agent_contact")
    handler.primary_email = data.get("primary_email")
    handler.additional_contacts = data.get("additional_contacts")

    db.session.commit()
    return jsonify({"success": True})

@flightops_bp.route('/get_handler_details/<int:handler_id>', methods=['GET'])
@login_required
@admin_required
def get_handler_details(handler_id):
    handler = GroundHandler.query.get(handler_id)

    if not handler:
        return jsonify({"error": "Handler not found"}), 404

    return jsonify({
        "id": handler.id,
        "handling_agent": handler.handling_agent,
        "contact_person": handler.contact_person or "",
        "agent_contact": handler.agent_contact or "",
        "primary_email": handler.primary_email or "",
        "additional_contacts": handler.additional_contacts or ""
    })


def get_handler_emails_for_port(port_code):

    airport = Port.query.filter_by(iata_code=port_code.upper()).first()
    if not airport:
        return []

    handlers = GroundHandler.query.filter_by(port_id=airport.id).all()
    if not handlers:
        return []

    grouped_handlers = defaultdict(list)

    for handler in handlers:
        agent_name = handler.handling_agent.strip()
        if handler.primary_email:
            grouped_handlers[agent_name].append(handler.primary_email.strip().lower())

        if handler.additional_contacts:
            extras = [e.strip().lower() for e in handler.additional_contacts.split(';') if e.strip()]
            grouped_handlers[agent_name].extend(extras)

    # Format for frontend: one checkbox per agent with all emails grouped
    final_list = []
    for agent, emails in grouped_handlers.items():
        deduped = sorted(set(emails))
        final_list.append({
            "name": agent,
            "emails": deduped
        })

    return final_list

def safe_strip(value):
    """Strips a string safely, ensuring None values don't cause issues."""
    return str(value).strip() if value else ""

def normalize_datetime(dt):
    """Converts different datetime formats into a consistent datetime object."""
    if dt is None:
        return None
    if isinstance(dt, str):
        return datetime.fromisoformat(dt.replace("T", " "))  # Ensure consistent format
    return dt

def normalize_crew_list(crew_list):
    """Ensure crew_list is properly formatted and sorted before comparison."""
    if isinstance(crew_list, str):
        try:
            crew_list = json.loads(crew_list)  # Convert JSON string to a list
        except json.JSONDecodeError:
            print("❌ Error decoding crew JSON")
            return []

    if not isinstance(crew_list, list):
        return []

    # Convert to a standardized format (list of lists)
    formatted_crew = []
    for c in crew_list:
        if isinstance(c, dict):
            formatted_crew.append([
                c.get("employeeId", 0),
                safe_strip(c.get("firstName", "")),
                safe_strip(c.get("surname", "")),
                c.get("position", "")
            ])
        elif isinstance(c, (list, tuple)) and len(c) == 4:
            formatted_crew.append(list(c))  # Convert tuples to lists

    return sorted(formatted_crew, key=lambda x: x[0])  # Sort by employeeId
