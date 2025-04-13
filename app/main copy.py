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

from flask import render_template, redirect, url_for, flash, request, current_app, send_from_directory, g, jsonify, session,Response
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
from flask import send_file
import shutil, logging
from datetime import datetime, timedelta
from app.forms import LoginForm, LineTrainingFormEditForm, LineTrainingEmailConfigForm, CourseReminderEmailConfigForm, TimesheetForm  # Import your LoginForm
from flask_mail import Message
from app.email_utils import send_email_to_training_team, Send_Release_To_Supervisor_Email, send_course_reminders, send_qualification_reminders, send_qualification_expiry_email, send_timesheet_response
from sqlalchemy.orm import joinedload
from flask_apscheduler import APScheduler
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import SecureCookieSessionInterface
from roster_utils import normalize_duty, duty_dict, get_current_duty, fetch_and_save_flights, check_for_flight_changes, check_for_daily_changes
from fpdf import FPDF
from flask import send_file
from sqlalchemy import func
from sqlalchemy import text, bindparam
from cachetools import TTLCache
from forms import CREW_CHECK_FIELDS
from collections import defaultdict

# Initialize app and extensions
app = create_app()
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect unauthenticated users to the login page
scheduler = APScheduler() #Initilise reminder email scheduler.
ENVISION_AUTH_URL = "https://envision.airchathams.co.nz:8790/v1/Authenticate"
ENVISION_URL = "https://envision.airchathams.co.nz:8790/v1"
# ✅ Cache employee data (key: employeeId, value: {firstName, surname})
EMPLOYEE_CACHE = TTLCache(maxsize=1000, ttl=3600)  # Stores up to 1000 employees, expires in 1 hour

# User loader for Flask-Login

@login_manager.user_loader
def load_user(user_id):
    app.logger.debug(f"Loading user from session: {user_id}")
    user = User.query.get(int(user_id))
    if user:
        app.logger.debug(f"Found user: {user.username}")
    else:
        app.logger.debug("No user found with that ID!")
    return user

@app.before_request
def load_crew_checks():
    if current_user.is_authenticated:
        user_roles = [role.role_name for role in current_user.roles]
        g.crew_checks = CrewCheck.query.filter(
            CrewCheck.roles.any(RoleType.role_name.in_(user_roles))
        ).all()
    else:
        g.crew_checks = []
##############################
###Global Route Permissions###
##############################
##############################
### Global Route Permissions ###
##############################
@app.route('/route_permissions', methods=['GET', 'POST'])
@login_required
@admin_required  # Only admins should be able to modify route access
def route_permissions():
    from flask import current_app

    # 🔹 Get all available routes
    all_routes = []
    for rule in current_app.url_map.iter_rules():
        route_info = {
            "endpoint": rule.endpoint,
            "methods": list(rule.methods - {"OPTIONS", "HEAD"}),  # Remove unwanted methods
            "url": str(rule),
        }
        all_routes.append(route_info)

    # 🔹 Fetch all roles
    all_roles = RoleType.query.all()

    # 🔹 Fetch existing permissions
    existing_permissions = RoutePermission.query.all()
    permission_map = {p.endpoint: [r.roleID for r in p.roles] for p in existing_permissions}
    selected_date = request.args.get("date")  # Get date from frontend

    if selected_date:
        try:
            selected_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
            flights = Flight.query.filter(db.func.date(Flight.departureScheduled) == selected_date).all()
        except ValueError:
            return jsonify({"message": "Invalid date format"}), 400
    else:
        flights = Flight.query.all()  # Return all flights if no date is provided
        
    if request.method == 'POST':
        # Process role assignments
        for route in all_routes:
            selected_roles = request.form.getlist(f"roles_{route['endpoint']}")  # Get selected roles
            permission = RoutePermission.query.filter_by(endpoint=route['endpoint']).first()

            if not permission:
                permission = RoutePermission(endpoint=route['endpoint'])
                db.session.add(permission)

            # Update roles
            permission.roles = [RoleType.query.get(int(role_id)) for role_id in selected_roles]
        
        db.session.commit()
        flash("Route permissions updated successfully!", "success")
        return redirect(url_for('route_permissions'))

    return render_template('admin/route_permissions.html', all_routes=all_routes, all_roles=all_roles, permission_map=permission_map)

@app.before_request
def check_route_permissions():
    # List of routes that do not require authentication
    allowed_routes = {'login', 'logout', 'static', 'reset_password', 'verify_sign_password'}

    # If the user is not authenticated, only allow access to public routes
    if not current_user.is_authenticated:
        if request.endpoint and request.endpoint in allowed_routes:
            return  # Allow access
        return redirect(url_for('login'))  # Redirect to login

    # Admins have full access, skip permission checks
    if current_user.is_admin:
        return

    # Get the current endpoint
    endpoint = request.endpoint
    if not endpoint:
        return  # Skip checking if there's no endpoint (avoids errors)

    # Skip permission checks for public and static routes
    if endpoint in allowed_routes:
        return

    # Check if the route has assigned permissions
    route_permission = RoutePermission.query.filter_by(endpoint=endpoint).first()
    if route_permission:
        allowed_roles = {role.role_name for role in route_permission.roles}
        user_roles = {role.role_name for role in current_user.roles}

        # If user lacks access, redirect to dashboard
        if not allowed_roles.intersection(user_roles):
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('user_dashboard'))

def generate_nonce():
    """Generate a unique nonce for authentication requests."""
    return os.urandom(16).hex()

from werkzeug.security import check_password_hash

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        entered_password = request.form.get("password", "").strip()  # Store entered password

        if not username_or_email or not entered_password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter((User.crew_code == username_or_email) | (User.email == username_or_email)).first()

        if not user:
            app.logger.warning(f"Login attempt failed: User not found ({username_or_email})")
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        # Log user details for debugging
        app.logger.info(f"Login attempt: User ID={user.id}, Username={user.username}, Auth Type={user.auth_type}")

        # Determine authentication type
        if user.auth_type == "local":
            app.logger.info(f"User {user.username} is a local user. Verifying password...")

            stored_hashed_password = user.password  # Store hashed password for debugging
            is_password_correct = check_password_hash(stored_hashed_password, entered_password)

            # Log password comparison
            app.logger.info(f"Entered Password: {entered_password}")
            app.logger.info(f"Stored Hashed Password: {stored_hashed_password}")
            app.logger.info(f"Password Match: {is_password_correct}")

            if is_password_correct:
                app.logger.info(f"Password match successful for User ID={user.id}")
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("user_dashboard"))
            else:
                app.logger.warning(f"Password mismatch for User ID={user.id}")
                flash("Invalid username or password.", "danger")
                return redirect(url_for("login"))

        elif user.auth_type == "envision":
            app.logger.info(f"User {user.username} is an Envision user. Sending authentication request...")

            response = requests.post(
                ENVISION_AUTH_URL,
                json={"username": username_or_email, "password": entered_password, "nonce": "some_nonce"},
                verify=False  # ⚠️ Temporary! Use 'verify="path/to/cert.pem"' in production.
            )

            app.logger.info(f"Envision API Response: {response.status_code}, Content: {response.text}")

            if response.status_code == 200:
                data = response.json()
                token = data.get("token")

                if not token:
                    app.logger.warning(f"Envision login failed: No token received for User ID={user.id}")
                    flash("Authentication token missing from API response.", "danger")
                    return redirect(url_for("login"))

                session['auth_token'] = token
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful via Envision!", "success")
                fetch_and_assign_user_roles(user)
                return redirect(url_for("user_dashboard"))
            else:
                app.logger.warning(f"Envision login failed: Invalid credentials for User ID={user.id}")
                flash("Invalid username or password for Envision.", "danger")
                return redirect(url_for("login"))

        else:
            app.logger.error(f"Invalid authentication method for User ID={user.id}")
            flash("Invalid authentication method.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route('/switch_user', methods=['GET', 'POST'])
def switch_user():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if user:
            login_user(user)
            return redirect(url_for('crew_acknowledgements'))  # or any page you want
    users = User.query.all()
    return render_template('admin/switch_user.html', users=users)

#####################################
###Get Employee Data From Envision###
#####################################
@app.route('/v1/Employees', methods=['GET'])
@login_required
@admin_required
def get_employees():
    crew_code = request.args.get('crew_code')
    if not crew_code:
        return jsonify({"message": "Crew code is required"}), 400

    auth_token = session.get('auth_token')
    if not auth_token:
        return jsonify({"message": "Auth token is missing"}), 401

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(f'{ENVISION_URL}/Employees', headers=headers)
    if response.status_code == 200:
        data = response.json()
        return jsonify(data), 200
    else:
        return jsonify({"message": f"Failed to fetch data from API. Status code: {response.status_code}"}), 500


@app.route('/archive_user/<int:user_id>', methods=['POST'])
@login_required
def archive_user(user_id):
    """Marks a user as archived (inactive) instead of deleting them."""
    if not current_user.is_admin:
        flash("You do not have permission to archive users.", "danger")
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = False  # 🔹 Archive user
    db.session.commit()

    flash(f"User {user.username} has been archived.", "info")
    return redirect(url_for('manage_users'))

@app.route('/reinstate_user/<int:user_id>', methods=['POST'])
@login_required
def reinstate_user(user_id):
    """Restores an archived user to active status."""
    if not current_user.is_admin:
        flash("You do not have permission to reinstate users.", "danger")
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = True  # 🔹 Restore user
    db.session.commit()

    flash(f"User {user.username} has been reinstated.", "success")
    return redirect(url_for('manage_users'))

# Admin Dashboard Route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    admin_tools = [
        {"name": "User Management", "url": url_for('manage_users')},
        {"name": "Course Management", "url": url_for('manage_courses')},
        {"name": "Role Management", "url": url_for('manage_roles')},
        #{"name": "Exam Attempts", "url": url_for('view_exam_attempts')},
        # Add more admin tools as needed
    ]
    return render_template('admin/admin_dashboard.html', admin_tools=admin_tools)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        # Collect form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin', False, type=bool)  # Defaults to False
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        next_of_kin = request.form.get('next_of_kin')
        kin_phone_number = request.form.get('kin_phone_number')
        date_of_birth = request.form.get('date_of_birth') or None
        license_type = request.form.get('license_type')
        license_number = request.form.get('license_number')
        medical_expiry = request.form.get('medical_expiry') or None
        role_ids = request.form.getlist('role_ids')  # Get multiple roles
        job_title_id = request.form.get('job_title_id')
        manager_id = request.form.get('manager_id')
        location_id = request.form.get('location_id')

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('manage_users'))

        crew_code = request.form.get('crew_code')

        # Convert empty string or 'Null' (if passed as a string) to None
        if not crew_code or crew_code.lower() == 'null':
            crew_code = None 
        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create the user object
        new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        is_admin=is_admin,
        phone_number=phone_number,
        address=address,
        next_of_kin=next_of_kin,
        kin_phone_number=kin_phone_number,
        date_of_birth=date_of_birth,
        license_type=license_type,
        license_number=license_number,
        medical_expiry=medical_expiry,
        is_active=True,
        auth_type=request.form.get('auth_type'),  # for example, 'local' or 'envision'
        crew_code=crew_code,  # Use default if necessary
        job_title_id=job_title_id if job_title_id else None,
        location_id=location_id if location_id else None
    )


        # Assign roles to the user
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                new_user.roles.append(role)

        # Save to the database
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} created successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", 'danger')

        return redirect(url_for('manage_users'))

    # Retrieve filter criteria for searching users
    name_filter = request.args.get('name_filter', '').strip()
    role_filter = request.args.get('role_filter', '').strip()
    status_filter = request.args.get('status_filter', 'active')  # Default to active users

    # Query users based on filters
    users_query = User.query

    if name_filter:
        users_query = users_query.filter(User.username.ilike(f"%{name_filter}%"))

    if role_filter.isdigit():  # Ensure role_filter is numeric
        role_filter = int(role_filter)
        users_query = users_query.join(User.roles).filter(RoleType.roleID == role_filter)

    # 🔹 Filter by active or archived users
    if status_filter == 'active':
        users_query = users_query.filter(User.is_active == True)
    elif status_filter == 'archived':
        users_query = users_query.filter(User.is_active == False)

    users = users_query.all()
    roles = RoleType.query.all()
    job_titles = JobTitle.query.all()  # Fetch job titles
    locations = Location.query.order_by(Location.name).all()  # ✅ Fetch locations

    # Instead of a static list of managers, create a mapping from job_title_id to eligible managers.
    # This example assumes that managers are active users whose job titles make them eligible.
    # You might need to adjust the filtering criteria as required.
    managers_by_job_title = {}
    for job in job_titles:
        managers_for_job = User.query.filter(User.is_active == True, User.job_title_id == job.id).all()
        managers_by_job_title[job.id] = [{'id': m.id, 'username': m.username} for m in managers_for_job]

    return render_template(
        'User/manage_users.html',
        users=users,
        roles=roles,
        job_titles=job_titles,
        locations=locations,
        # Send an initial list of managers in case the page needs it (optional)
        managers=User.query.filter_by(is_active=True).all(),
        managers_by_job_title=managers_by_job_title,
        name_filter=name_filter,
        role_filter=role_filter,
        status_filter=status_filter,
    )

@app.route('/user_profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    user_id = request.form.get('user_id', default=current_user.id, type=int) if request.method == 'POST' else request.args.get('user_id', default=current_user.id, type=int)
    user = User.query.get_or_404(user_id)

    app.logger.info(f"Loading profile for: ID={user.id}, Username={user.username}, Email={user.email}")
    payroll = PayrollInformation.query.filter_by(user_id=user.id).first()
    roles = RoleType.query.all()
    job_titles = JobTitle.query.all()
    users = User.query.all()
    user_roles = [role.roleID for role in user.roles]
    user_roles_names = [role.role_name for role in user.roles]
    date_of_birth_input = request.form.get('date_of_birth', None)
    medical_expiry_input = request.form.get('medical_expiry', None)
    locations = Location.query.order_by(Location.name).all()

    if request.method == 'POST':
        try:
            # ✅ Ensure only the user or an admin can edit this profile
            if user.id != current_user.id and not current_user.is_admin:
                flash('You do not have permission to edit this profile.', 'danger')
                return redirect(url_for('user_profile', user_id=user.id))

            app.logger.info(f"🔍 Full Form Data Received: {request.form.to_dict()}")

            # ✅ Basic User Editable Fields
            user.email = request.form.get('email')
            user.username = request.form['username']
            user.phone_number = request.form.get('phone_number')
            user.address = request.form.get('address')
            user.next_of_kin = request.form.get('next_of_kin')
            user.kin_phone_number = request.form.get('kin_phone_number')
            user.date_of_birth = request.form.get('date_of_birth')

            # ✅ Admin-Only Fields
            if current_user.is_admin:
                user.license_type = request.form.get('license_type')
                user.license_number = request.form.get('license_number')
                user.date_of_birth = None if not date_of_birth_input or date_of_birth_input.strip() == "" else date_of_birth_input
                user.medical_expiry = None if not medical_expiry_input or medical_expiry_input.strip() == "" else medical_expiry_input

                selected_roles = request.form.getlist('roles')
                user.roles = [RoleType.query.get(role_id) for role_id in selected_roles]

                user.is_admin = 'is_admin' in request.form  # ✅ Convert checkbox to boolean
                location_id = request.form.get('location_id')
                user.location_id = location_id if location_id else None

                # ✅ Handle Authentication Type Change
                new_auth_type = request.form.get('auth_type')
                if new_auth_type and new_auth_type in ['local', 'envision']:
                    if user.auth_type != new_auth_type:
                        app.logger.info(f"Changing authentication type for User ID={user.id} from {user.auth_type} to {new_auth_type}")
                        user.auth_type = new_auth_type

                        # ✅ If changing to Local, allow password update
                        if new_auth_type == "local":
                            new_password = request.form.get('password', "").strip()

                            if new_password:
                                app.logger.info(f"🔍 Received new password for User ID={user.id}: {new_password}")

                                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                                app.logger.info(f"🔑 Generated hashed password for User ID={user.id}: {hashed_password}")

                                user.password = hashed_password
                            else:
                                app.logger.warning(f"⚠️ No password provided for User ID={user.id}, skipping update.")

            # ✅ Allow Local Users to Update Their Password Without Changing Auth Type
            if user.auth_type == "local":
                new_password = request.form.get('password', "").strip()
                if new_password:
                    app.logger.info(f"🔍 Received new password update for existing local user ID={user.id}: {new_password}")

                    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    app.logger.info(f"🔑 Generated new hashed password for existing local user ID={user.id}: {hashed_password}")

                    user.password = hashed_password
                else:
                    app.logger.info(f"🛑 No password update provided for existing local user ID={user.id}, skipping.")

            # ✅ Update Job Title & Reporting Structure
            job_title_id = request.form.get('job_title_id')
            manager_id = request.form.get('manager_id')

            user.job_title_id = job_title_id if job_title_id else None
            user.reports_to = manager_id if manager_id else None

            # ✅ Ensure payroll exists
            if not payroll:
                payroll = PayrollInformation(user_id=user.id)
                db.session.add(payroll)

            payroll.type_of_employment = request.form.get('type_of_employment')
            payroll.minimum_hours = request.form.get('minimum_hours') == 'True'
            payroll.hours = request.form.get('hours') if payroll.minimum_hours else None
            payroll.kiwisaver_attached = request.form.get('kiwisaver_attached') == 'True'
            payroll.kiwisaver_type = request.form.get('kiwisaver_type') if payroll.kiwisaver_attached else None
            payroll.paye_attached = request.form.get('paye_attached') == 'True'
            payroll.ir330_attached = request.form.get('ir330_attached') == 'True'
            payroll.ird_number = request.form.get('ird_number')
            payroll.bank_account_details = request.form.get('bank_account_details')

            db.session.commit()
            app.logger.info(f"✅ Password successfully updated in database for User ID={user.id}")  # Debug
            flash('Profile updated successfully.', 'success')

        except IntegrityError as e:
            db.session.rollback()
            app.logger.error(f"❌ Database IntegrityError for user {user.id} ({user.username}): {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')

        return redirect(url_for('user_profile', user_id=user.id))

    return render_template(
        'user/user_profile.html', 
        user=user, 
        payroll=payroll, 
        roles=roles, 
        job_titles=job_titles,
        users=users,
        user_roles=user_roles, 
        user_roles_names=user_roles_names,
        locations=locations
    )



######################################
### Assign Role Based from Envision###
######################################
def fetch_and_assign_user_roles(user):
    print("Starting fetch_and_assign_user_roles function")  # Debugging: Function start
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")  # Debugging: Missing auth token
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    # Ensure the employee_id is correctly set
    if not user.employee_id:
        print(f"User {user.username} does not have an employee_id set.")
        return None

    url = f'{ENVISION_URL}/Employees/{user.employee_id}/Skills'
    print(f"Sending request to URL: {url}")  # Debugging: Log the URL
    print(f"With headers: {headers}")  # Debugging: Log the headers

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"Fetched data: {data}")  # Debugging: Log the fetched data
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        print(f"Existing roles: {existing_roles.keys()}")  # Debugging: Log existing roles
        
        # Track roles fetched from Envision
        envision_roles = set()

        for skill in data:
            role_name = skill.get('skill')  # Correctly fetch the skill description
            if not role_name:
                print(f"Skipping skill with no description: {skill}")  # Debugging: Skipping skill
                continue
            
            envision_roles.add(role_name)
            
            if role_name not in existing_roles:
                # Create a new role if it doesn't exist
                role = RoleType(role_name=role_name, role_description=role_name, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
                print(f"Created new role: {role_name}")  # Debugging: Created new role
            else:
                role = existing_roles[role_name]
                print(f"Using existing role: {role_name}")  # Debugging: Using existing role
            
            # Assign role to user
            if role not in user.roles:
                user.roles.append(role)
                print(f"Assigned role {role.role_name} to user {user.username}")  # Debugging: Assigned role

        # Remove roles that are no longer present in Envision and were pulled from Envision
        for role in user.roles[:]:
            if role.pulled_from_envision and role.role_name not in envision_roles:
                user.roles.remove(role)
                print(f"Removed role {role.role_name} from user {user.username}")  # Debugging: Removed role
        
        db.session.commit()
        print(f"Committed roles to user {user.username}")  # Debugging: Committed roles
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")  # Debugging: Failed to fetch data
        print(f"Response content: {response.text}")  # Debugging: Log the response content
        return None
    
@app.route('/assign_roles_based_on_skills', methods=['GET'])
@login_required
def assign_roles_based_on_skills():
    crew_code = request.args.get('crew_code')
    user = User.query.filter_by(crew_code=crew_code).first()

    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    # Fetch and assign roles from Envision
    data = fetch_and_assign_user_roles(user)
    if data is None:
        return jsonify({"success": False, "message": "Failed to fetch roles from Envision."}), 500

    try:
        roles = [{"role_name": role.role_name} for role in user.roles]
        return jsonify({"success": True, "message": "Roles assigned based on skills successfully.", "roles": roles}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/save_employee_id', methods=['POST'])
@login_required
def save_employee_id():
    data = request.get_json()
    crew_code = data.get('crew_code')
    employee_id = data.get('employee_id')

    if not crew_code or not employee_id:
        return jsonify({"success": False, "message": "Crew code and employee ID are required."}), 400

    user = User.query.filter_by(crew_code=crew_code).first()
    if not user:
        return jsonify({"success": False, "message": "User not found."}), 404

    user.employee_id = employee_id

    try:
        db.session.commit()
        return jsonify({"success": True, "message": "Employee ID saved successfully."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500

@app.route('/user_dashboard', methods=['GET'])
@login_required
def user_dashboard():
    if not current_user.is_authenticated:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for("login"))

    user_id = current_user.id
    current_date = datetime.utcnow()

    # Fetch user roles
    user_roles = [role.roleID for role in current_user.roles]

    # Fetch all courses associated with the user's roles
    courses = (
        db.session.query(Course)
        .join(course_role, Course.id == course_role.c.course_id)
        .filter(course_role.c.role_id.in_(user_roles))
        .all()
    )

    # Fetch qualifications for the current user
    qualifications = Qualification.query.filter_by(employee_id=current_user.id).all()

    # Categorized course lists
    upcoming_courses = []
    optional_courses = []
    expired_courses = []
    all_completed_courses = []
    available_courses = []
    renewable_soon_courses = []  # ✅ Moved to top level

    for course in courses:
        progress = UserSlideProgress.query.filter_by(user_id=user_id, course_id=course.id).first()
        exam_attempt = UserExamAttempt.query.filter_by(user_id=user_id, course_id=course.id).order_by(UserExamAttempt.created_at.desc()).first()

        has_exam = course.has_exam

        if progress:
            # ✅ Handle courses with exams
            if has_exam:
                if exam_attempt:
                    if exam_attempt.passed:
                        if exam_attempt.expiry_date:
                            days_to_expiry = (exam_attempt.expiry_date - current_date).days

                            if exam_attempt.expiry_date < current_date:
                                expired_courses.append({
                                    'course': course,
                                    'expiry_date': exam_attempt.expiry_date
                                })
                            else:
                                # ✅ Always show in completed if it's still valid
                                all_completed_courses.append({
                                    'course': course,
                                    'expiry_date': exam_attempt.expiry_date,
                                    'next_due_date': exam_attempt.expiry_date
                                })

                                # ✅ Also show in renewable if within 30 days
                                if 0 <= days_to_expiry <= 30:
                                    renewable_soon_courses.append({
                                        'course': course,
                                        'expiry_date': exam_attempt.expiry_date
                                    })
                    else:
                        upcoming_courses.append(course)
                elif not progress.completed:
                    upcoming_courses.append(course)

            # ✅ Handle courses without exams
            else:
                # ✅ Handle courses without exams
                if progress.expiry_date:
                    days_to_expiry = (progress.expiry_date - current_date).days

                    if progress.expiry_date < current_date:
                        expired_courses.append({
                            'course': course,
                            'expiry_date': progress.expiry_date
                        })
                    else:
                        # ✅ Always show in completed if still valid
                        all_completed_courses.append({
                            'course': course,
                            'expiry_date': progress.expiry_date,
                            'next_due_date': progress.expiry_date
                        })

                        # ✅ Also show in renewable if within 30 days
                        if 0 <= days_to_expiry <= 30:
                            renewable_soon_courses.append({
                                'course': course,
                                'expiry_date': progress.expiry_date
                            })
                elif not progress.completed:
                    upcoming_courses.append(course)


            # ✅ Resit window (for both exam and non-exam)
            if progress.expiry_date:
                available_start_date = progress.expiry_date - timedelta(days=course.available_before_expiry_days)
                if available_start_date <= current_date <= progress.expiry_date:
                    available_courses.append({
                        'course': course,
                        'expiry_date': progress.expiry_date
                    })
        else:
            # ✅ Courses with no progress
            if course.valid_for_days:
                upcoming_courses.append(course)
            else:
                optional_courses.append(course)

    return render_template(
        'user/user_dashboard.html',
        user=current_user,
        upcoming_courses=upcoming_courses,
        optional_courses=optional_courses,
        expired_courses=expired_courses,
        all_completed_courses=all_completed_courses,
        available_courses=available_courses,
        renewable_soon_courses=renewable_soon_courses,
        qualifications=qualifications
    )


@app.route('/course/<int:course_id>/start_again', methods=['POST'])
@login_required
def start_course_again(course_id):
    # Reset slide progress for the user
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if progress:
        progress.completed = False
        progress.last_slide_viewed = 0
        db.session.commit()

    flash("Your progress has been reset. Start the course again.", "info")
    return redirect(url_for('view_course', course_id=course_id))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)

    try:
        # Explicitly delete the associated payroll information
        if user.payroll_information:
            db.session.delete(user.payroll_information)
        
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} has been deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred while deleting the user: {str(e)}", "danger")

    return redirect(url_for('manage_users'))

@app.route('/manage_courses', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_courses():
    if request.method == 'POST':
        # Fetch form data
        title = request.form['title']
        description = request.form['description']
        role_type_ids = request.form.getlist('role_type_ids')  # Multiple role IDs
        ppt_file = request.files['ppt_file']
        passing_mark = request.form.get('passing_mark', type=int)
        passing_percentage = request.form.get('passing_percentage', type=float)  # If applicable
        valid_for_days = request.form.get('valid_for_days', type=int)
        available_before_expiry_days = request.form.get('available_before_expiry_days', type=int)
        
        # Handle the boolean field `has_exam`
        has_exam = 'has_exam' in request.form  # Check if the checkbox is selected

        # Validate required fields
        if not title or not description or not role_type_ids or not ppt_file or passing_mark is None:
            flash('All fields, including Passing Mark, are required.', 'danger')
            return redirect(url_for('manage_courses'))

        # Save the uploaded PowerPoint file
        ppt_filename = secure_filename(ppt_file.filename)
        ppt_path = os.path.join(app.config['UPLOAD_FOLDER'], ppt_filename)
        ppt_file.save(ppt_path)

        # Create the course instance
        course = Course(
            title=title,
            description=description,
            ppt_file=ppt_filename,
            passing_mark=passing_mark,
            passing_percentage=passing_percentage,  # Optional, only if relevant
            valid_for_days=valid_for_days,
            available_before_expiry_days=available_before_expiry_days,
            has_exam=has_exam  # Assign the boolean value
        )

        # Assign roles to the course
        roles = RoleType.query.filter(RoleType.roleID.in_(role_type_ids)).all()
        course.roles.extend(roles)

        db.session.add(course)
        db.session.commit()

        flash(f'Course "{title}" created successfully.', 'success')
        return redirect(url_for('manage_courses'))

    # Fetch existing courses and roles for display
    courses = Course.query.all()
    roles = RoleType.query.all()
    return render_template('course/manage_courses.html', courses=courses, roles=roles)

@app.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        role_type_ids = request.form.getlist('role_type_ids')  # Fetch multiple roles
        passing_mark = request.form.get('passing_mark', type=int)
        passing_percentage = request.form.get('passing_percentage', type=float)  # Assuming percentage can be updated
        course.valid_for_days = request.form.get('valid_for_days', type=int)
        course.available_before_expiry_days = request.form.get('available_before_expiry_days', type=int)
        course.is_resit = 'is_resit' in request.form  # Checkbox input, true if checked
        course.has_exam = 'has_exam' in request.form

        if not title or not role_type_ids or passing_mark is None:
            flash('All required fields must be filled.', 'danger')
            return redirect(url_for('edit_course', course_id=course_id))

        # Update course details
        course.title = title
        course.description = description
        course.passing_mark = passing_mark
        course.passing_percentage = passing_percentage

        # Clear existing roles and assign new ones
        course.roles.clear()
        for role_id in role_type_ids:
            role = RoleType.query.get(role_id)
            if role:
                course.roles.append(role)

        db.session.commit()
        flash(f'Course "{title}" updated successfully.', 'success')
        return redirect(url_for('manage_courses'))

    # Fetch roles for the form
    roles = RoleType.query.all()
    return render_template('course/edit_course.html', course=course, roles=roles)

@app.route('/course/<int:course_id>', methods=['GET'])
@login_required
def view_course(course_id):
    course = Course.query.get_or_404(course_id)

    # Check if the user has access to the course
    user_roles = [role.roleID for role in current_user.roles]
    course_roles = [role.roleID for role in course.roles]

    if not set(user_roles).intersection(course_roles) and not current_user.is_admin:
        flash('You do not have access to this course.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Ensure progress is tracked
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if not progress:
        progress = UserSlideProgress(user_id=current_user.id, course_id=course_id, last_slide_viewed=0)
        db.session.add(progress)
        db.session.commit()

    # Extract slides
    ppt_path = os.path.join(app.config['UPLOAD_FOLDER'], course.ppt_file)
    slides_folder = os.path.join(current_app.static_folder, 'Course_Powerpoints', f'slides_{course.id}')
    os.makedirs(slides_folder, exist_ok=True)
    if not os.listdir(slides_folder):
        extract_slides_to_png(ppt_path, slides_folder)

    slide_paths = sorted(
        [os.path.join(slides_folder, f) for f in os.listdir(slides_folder) if f.endswith(".png")],
        key=natural_sort_key
    )
    slide_count = len(slide_paths)
    slide_index = int(request.args.get('slide', 0))

    # Validate the slide index
    if slide_index < 0 or slide_index >= slide_count:
        flash('Invalid slide index.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Update progress
    if slide_index >= progress.last_slide_viewed:
        progress.last_slide_viewed = slide_index

    # Handle completion logic
    is_last_slide = slide_index == slide_count - 1
    if is_last_slide and not course.has_exam:
        progress.completed = True  # Mark as completed if no exam and last slide is viewed
    db.session.commit()

    # Debugging Progress
    print(f"Slide index: {slide_index}")
    print(f"Last slide viewed: {progress.last_slide_viewed}")
    print(f"Completed: {progress.completed}")
    print(f"Total slides: {slide_count}")

    # Determine buttons to show
    show_finish = not course.has_exam and is_last_slide
    show_take_exam = course.has_exam and is_last_slide

    # Pass data to the template
    return render_template(
        'course/view_course.html',
        course=course,
        current_slide=slide_index + 1,  # 1-based slide count for display
        total_slides=slide_count,
        slide_image=url_for('static', filename=f"Course_Powerpoints/slides_{course.id}/{os.path.basename(slide_paths[slide_index])}"),
        next_slide=slide_index + 1 if slide_index + 1 < slide_count else None,
        prev_slide=slide_index - 1 if slide_index > 0 else None,
        show_finish=show_finish,
        show_take_exam=show_take_exam
    )

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    # Define the root path to the 'Course_Powerpoints' folder
    course_ppt_path = os.path.join(os.getcwd(), 'Course_Powerpoints')
    return send_from_directory(course_ppt_path, filename)

@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Correct the slides folder path
    slides_folder = os.path.join(current_app.root_path, 'static', 'Course_Powerpoints', f"slides_{course.id}")
    if os.path.exists(slides_folder):
        try:
            shutil.rmtree(slides_folder)  # Attempt to remove the directory
        except Exception as e:
            flash(f"Permission error: Unable to delete slides folder. {e}", 'danger')
            return redirect(url_for('manage_courses'))

    # Correct the PowerPoint file path
    ppt_path = os.path.join(current_app.root_path, 'static', 'Course_Powerpoints', course.ppt_file)
    if os.path.exists(ppt_path):
        try:
            os.remove(ppt_path)
        except Exception as e:
            flash(f"Permission error: Unable to delete PowerPoint file. {e}", 'danger')
            return redirect(url_for('manage_courses'))

    # Delete associated course data
    try:
        # Delete related questions and answers
        questions = Questions.query.filter_by(course_id=course_id).all()
        for question in questions:
            Answers.query.filter_by(question_id=question.id).delete()
            db.session.delete(question)

        # Delete related user progress
        UserSlideProgress.query.filter_by(course_id=course_id).delete()

        # Delete related exam attempts
        UserExamAttempt.query.filter_by(course_id=course_id).delete()

        # Delete the course itself
        db.session.delete(course)
        db.session.commit()
    except Exception as e:
        flash(f"Error deleting course data: {e}", 'danger')
        return redirect(url_for('manage_courses'))

    flash(f'Course "{course.title}" and all associated data deleted successfully.', 'success')
    return redirect(url_for('manage_courses'))
    
@app.route('/manage_roles', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_roles():
    if request.method == 'POST':
        # 🔹 Handle Adding a New Role
        if 'add_role' in request.form:
            role_name = request.form['role_name'].strip()
            role_description = request.form['role_description'].strip()  # Assuming you have a description field
            if not role_name:
                flash('Role name cannot be empty.', 'danger')
                return redirect(url_for('manage_roles'))
            
            # Check for duplicates
            existing_role = RoleType.query.filter_by(role_name=role_name).first()
            if existing_role:
                flash('Role already exists.', 'danger')
            else:
                new_role = RoleType(
                    role_name=role_name,
                    role_description=role_description,
                    pulled_from_envision=False  # Set to False for roles added through the LMS Platform
                )
                db.session.add(new_role)
                db.session.commit()
                flash(f'Role "{role_name}" added successfully.', 'success')

        # 🔹 Handle Deleting a Role
        if 'delete_role' in request.form:
            role_id = request.form.get('role_id')

            if role_id:
                role = RoleType.query.get(role_id)
                if role:
                    if role.users:
                        # If role has users assigned, remove role from users first
                        for user in role.users:
                            user.roles.remove(role)
                        db.session.commit()
                        flash(f'Role "{role.role_name}" was removed from assigned users and deleted.', 'warning')
                    db.session.delete(role)
                    db.session.commit()
                    flash(f'Role "{role.role_name}" deleted successfully.', 'success')
                else:
                    flash('Role not found.', 'danger')
            else:
                flash('Invalid role ID.', 'danger')

        return redirect(url_for('manage_roles'))

    roles = RoleType.query.all()
    return render_template('admin/manage_roles.html', roles=roles)

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('user_dashboard'))

@app.route('/course/<int:course_id>/take_exam', methods=['GET', 'POST'])
@login_required
def take_exam(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)

    # Ensure the user has viewed all slides
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    slide_count = get_slide_count(course.id)  # Function to get the total slides for the course

    if not progress or progress.last_slide_viewed < slide_count - 1:
        flash("You need to finish all the slides before taking the exam.", "danger")
        return redirect(url_for('view_course', course_id=course_id))

    if request.method == 'POST':
        # Extract submitted answers
        submitted_answers = {
            int(k.split('_')[1]): int(v)
            for k, v in request.form.items()
            if k.startswith('question_')
        }

        # Calculate the score and determine if passed
        score, passed = calculate_exam_score(course_id, submitted_answers)

        # Create a new exam attempt regardless of pass or fail
        attempt = UserExamAttempt(
            user_id=current_user.id,
            course_id=course_id,
            score=score,
            passed=passed,
            expiry_date=datetime.utcnow() + timedelta(days=course.valid_for_days) if passed else None,
            created_at=datetime.utcnow(),
            is_resit=False
        )
        db.session.add(attempt)
        db.session.flush()  # Ensure attempt.id is generated before use

        # Store the user's answers in the UserAnswers table
        for question_id, answer_id in submitted_answers.items():
            question = Questions.query.get(question_id)
            answer = Answers.query.get(answer_id)
            is_correct = answer.is_correct if answer else False

            user_answer = UserAnswer(
                attempt_id=attempt.id,
                question_id=question_id,
                answer_id=answer_id,
                is_correct=is_correct
            )
            db.session.add(user_answer)

        # Commit changes
        try:
            db.session.commit()

            if passed:
                # Mark the course progress as completed if the exam is passed
                if progress:
                    progress.completed = True
                    db.session.commit()
            
            # Redirect to the exam result page regardless of pass/fail
            return redirect(url_for('exam_result', course_id=course_id, attempt_id=attempt.id))

        except Exception as e:
            db.session.rollback()
            print(f"Error committing exam attempt: {e}")
            flash("There was an error submitting your exam. Please try again.", "danger")
            return redirect(url_for('take_exam', course_id=course_id))

    # Fetch the questions for this course
    questions = Questions.query.filter_by(course_id=course_id).all()
    random.shuffle(questions)  # Randomize the order of questions

    # For each question, shuffle its answers
    for question in questions:
        question.answers = question.answers[:]  # copy list to avoid side effects
        random.shuffle(question.answers)

    return render_template('course/exams/take_exam.html', course=course, questions=questions)

@app.route('/course/<int:course_id>/exam_result/<int:attempt_id>', methods=['GET'])
@login_required
def exam_result(course_id, attempt_id):
    # Fetch the attempt and course
    attempt = UserExamAttempt.query.get_or_404(attempt_id)
    course = Course.query.get_or_404(course_id)

    # Ensure the attempt belongs to the current user
    if attempt.user_id != current_user.id:
        flash("You are not authorized to view this result.", "danger")
        return redirect(url_for('user_dashboard'))

    if attempt.passed:
        # Ensure the certificate is generated and saved
        try:
            certificate_path = generate_certificate(current_user, attempt)
            if certificate_path:
                print(f"Certificate generated at: {certificate_path}")
            else:
                print("Certificate generation failed.")
        except Exception as e:
            print(f"Error generating certificate: {e}")
            flash("Error generating certificate. Please contact support.", "danger")

    # Pass both the attempt and course to the template
    return render_template('Course/Exams/exam_result.html', attempt=attempt, course=course)
@app.route('/course/<int:course_id>/finish', methods=['POST'])
@login_required
def finish_course(course_id):
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    course = Course.query.get_or_404(course_id)

    if not progress or progress.last_slide_viewed < get_slide_count(course_id) - 1:
        flash("You must complete all slides before finishing this course.", "danger")
        return redirect(url_for('view_course', course_id=course_id))

    # Mark course as completed
    progress.completed = True
    progress.last_completed_date = datetime.utcnow()

    # Set expiry date if the course has validity
    if course.valid_for_days:
        progress.expiry_date = datetime.utcnow() + timedelta(days=course.valid_for_days)

    db.session.commit()
    flash("Course completed successfully!", "success")
    return redirect(url_for('user_dashboard'))

@app.route('/generate_certificate_file/<int:attempt_id>', methods=['GET'])
@login_required
def generate_certificate_file(attempt_id):
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the attempt belongs to the current user
    if attempt.user_id != current_user.id:
        flash("You are not authorized to download this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Send the file to the user for download
    return send_from_directory(
        os.path.dirname(attempt.certificate_path),
        os.path.basename(attempt.certificate_path),
        as_attachment=True,
        download_name=os.path.basename(attempt.certificate_path)
    )

@app.route('/download_certificate/<int:attempt_id>', methods=['GET'])
@login_required
def download_certificate(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You do not have permission to download this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Validate certificate path
    if not attempt.certificate_path or not os.path.exists(attempt.certificate_path):
        flash("Certificate not found. It may not have been generated yet.", "danger")
        return redirect(url_for('exam_result', course_id=attempt.course_id, attempt_id=attempt.id))

    # Send the file for download
    directory = os.path.dirname(attempt.certificate_path)
    filename = os.path.basename(attempt.certificate_path)
    return send_from_directory(directory, filename, as_attachment=True)

@app.route('/view_certificate/<int:attempt_id>', methods=['GET'])
@login_required
def view_certificate(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You do not have permission to view this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Validate certificate path
    if not attempt.certificate_path or not os.path.exists(attempt.certificate_path):
        flash("Certificate not found. It may not have been generated yet.", "danger")
        return redirect(url_for('exam_result', course_id=attempt.course_id, attempt_id=attempt.id))

    # Return the certificate
    directory = os.path.dirname(attempt.certificate_path)
    filename = os.path.basename(attempt.certificate_path)
    return send_from_directory(directory, filename, as_attachment=False)


@app.route('/admin/questions/<int:course_id>/add', methods=['POST'])
@login_required
@admin_required
def add_question(course_id):
    course = Course.query.get_or_404(course_id)

    question_text = request.form.get('question_text')
    if not question_text.strip():
        flash("Question text cannot be empty.", "danger")
        return redirect(url_for('manage_questions', course_id=course_id))

    new_question = Questions(text=question_text, course_id=course_id)
    db.session.add(new_question)
    db.session.commit()
    flash("Question added successfully!", "success")

    return redirect(url_for('manage_questions', course_id=course_id))

@app.route('/admin/questions/delete/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Questions.query.get_or_404(question_id)
    course_id = question.course_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", "success")
    return redirect(url_for('manage_questions', course_id=course_id))

@app.route('/admin/questions/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_questions(course_id):
    course = Course.query.get_or_404(course_id)
    questions = Questions.query.filter_by(course_id=course_id).all()

    if request.method == 'POST':
        question_text = request.form['question_text']
        new_question = Questions(text=question_text, course_id=course_id)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('manage_questions', course_id=course_id))

    return render_template('course/exams/manage_questions.html', course=course, questions=questions)

@app.route('/admin/questions/edit/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_question(question_id):
    # Fetch the question by ID
    question = Questions.query.get_or_404(question_id)

    if request.method == 'POST':
        # Get the updated question text from the form
        question_text = request.form.get('question_text')
        if question_text and question_text.strip():
            question.text = question_text.strip()
            db.session.commit()
            flash('Question updated successfully.', 'success')
            return redirect(url_for('manage_questions', course_id=question.course_id))
        else:
            flash('Question text cannot be empty.', 'danger')
            return redirect(url_for('edit_question', question_id=question.id))

    # Render the edit question form
    return render_template('course/exams/edit_question.html', question=question)

@app.route('/manage_answers/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_answers(question_id):
    question = Questions.query.get_or_404(question_id)

    # Adding a new answer
    if request.method == 'POST' and 'text' in request.form:
        if request.form.get('text'):
            new_answer = Answers(
                text=request.form.get('text'),
                is_correct=request.form.get('is_correct') == 'on',
                question_id=question_id
            )
            db.session.add(new_answer)
            db.session.commit()
            flash("Answer added successfully.", "success")
        else:
            flash("Answer text cannot be empty.", "danger")
        return redirect(url_for('manage_answers', question_id=question_id))

    # Updating an existing answer
    if request.method == 'POST' and 'answer_id' in request.form:
        answer_id = request.form.get('answer_id')
        updated_text = request.form.get('updated_text')
        updated_is_correct = request.form.get('updated_is_correct') == 'on'

        answer = Answers.query.get_or_404(answer_id)
        if updated_text:
            answer.text = updated_text
            answer.is_correct = updated_is_correct
            db.session.commit()
            flash("Answer updated successfully.", "success")
        else:
            flash("Updated text cannot be empty.", "danger")
        return redirect(url_for('manage_answers', question_id=question_id))

    # Fetch all answers for the question
    answers = Answers.query.filter_by(question_id=question_id).all()
    return render_template('course/exams/manage_answers.html', question=question, answers=answers)

@app.route('/admin/manage_answers/<int:answer_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_answer(answer_id):
    answer = Answers.query.get_or_404(answer_id)
    question_id = answer.question_id  # Save question ID before deleting

    db.session.delete(answer)
    db.session.commit()
    flash('Answer deleted successfully.', 'success')
    return redirect(url_for('manage_answers', question_id=question_id))

@app.route('/update_answer/<int:answer_id>', methods=['POST'])
@login_required
@admin_required
def update_answer(answer_id):
    # Fetch the answer from the database
    answer = Answers.query.get_or_404(answer_id)

    # Get the submitted data
    answer_text = request.form.get('answer_text')
    is_correct = request.form.get('is_correct') == 'on'

    # Debugging: Print the received data
    print(f"Updating Answer ID: {answer_id}")
    print(f"New Text: {answer_text}")
    print(f"Is Correct: {is_correct}")

    # Update the fields
    if answer_text:
        answer.text = answer_text
    answer.is_correct = is_correct

    # Save the changes
    db.session.commit()

    # Flash a success message and redirect
    flash('Answer updated successfully.', 'success')
    return redirect(url_for('manage_answers', question_id=answer.question_id))

@app.route('/admin/answers/<int:answer_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_answer(answer_id):
    answer = Answers.query.get_or_404(answer_id)

    if request.method == 'POST':
        answertext = request.form['answer_text']
        answer.is_correct = 'is_correct' in request.form  # Checkbox for marking as correct
        db.session.commit()
        flash('Answer updated successfully!', 'success')
        return redirect(url_for('manage_answers', question_id=answer.question_id))

    return render_template('edit_answer.html', answer=answer)

#Shows all the exam attempts for a specific course.
@app.route('/course/<int:course_id>/exam_attempts', methods=['GET'])
@login_required
@admin_required
def view_exam_attempts(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)

    # Fetch all exam attempts for this course
    exam_attempts = UserExamAttempt.query.filter_by(course_id=course_id).all()

    return render_template(
        'Course/Exams/view_exam_attempts.html',
        course=course,
        exam_attempts=exam_attempts
    )

# Admin Able to Fetch the users exam attempt
@app.route('/exam_attempt/<int:attempt_id>', methods=['GET'])
@login_required
@admin_required
def view_user_exam_attempt(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Fetch all the user's answers for this attempt
    user_answers = UserAnswer.query.filter_by(attempt_id=attempt_id).all()

    # Fetch all questions and answers for the course
    course_id = attempt.course_id
    questions = Questions.query.filter_by(course_id=course_id).all()

    # Prepare data for the template
    detailed_answers = []
    for question in questions:
        answers = Answers.query.filter_by(question_id=question.id).all()
        user_answer = next((ua for ua in user_answers if ua.question_id == question.id), None)
        
        detailed_answers.append({
            "question": question,
            "answers": answers,
            "user_answer_id": user_answer.answer_id if user_answer else None,
            "is_correct": user_answer.is_correct if user_answer else False,
        })

    return render_template(
        'course/exams/view_user_exam_attempt.html',
        attempt=attempt,
        detailed_answers=detailed_answers
    )

# User able to Fetch their exam attempt
@app.route('/view_my_exam_attempt/<int:attempt_id>', methods=['GET'])
@login_required
def view_my_exam_attempt(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the logged-in user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You are not authorized to view this attempt.", "danger")
        return redirect(url_for('my_attempts'))

    # Fetch all the user's answers for this attempt
    user_answers = UserAnswer.query.filter_by(attempt_id=attempt_id).all()

    # Fetch all questions and answers for the course
    course_id = attempt.course_id
    questions = Questions.query.filter_by(course_id=course_id).all()

    # Prepare data for the template
    detailed_answers = []
    for question in questions:
        answers = Answers.query.filter_by(question_id=question.id).all()
        user_answer = next((ua for ua in user_answers if ua.question_id == question.id), None)
        
        detailed_answers.append({
            "question": question,
            "answers": answers,
            "user_answer_id": user_answer.answer_id if user_answer else None,
            "is_correct": user_answer.is_correct if user_answer else False,
        })

    return render_template(
        'user/view_my_exam_attempt.html',
        attempt=attempt,
        detailed_answers=detailed_answers
    )

@app.route('/my_exam_attempts', methods=['GET'])
@login_required
def my_exam_attempts():
    # Fetch all exam attempts for the logged-in user
    attempts = UserExamAttempt.query.filter_by(user_id=current_user.id).all()

    # Include related course data for better context
    for attempt in attempts:
        attempt.course = Course.query.get(attempt.course_id)

    return render_template(
        'user/my_exam_attempts.html',
        attempts=attempts
    )

@app.route('/delete_exam_attempt/<int:attempt_id>', methods=['POST'])
@login_required
@admin_required
def delete_exam_attempt(attempt_id):
    attempt = UserExamAttempt.query.get_or_404(attempt_id)
    user_id = attempt.user_id
    course_id = attempt.course_id

    try:
        # Remove related UserAnswers
        UserAnswer.query.filter_by(attempt_id=attempt.id).delete()

        # Remove the exam attempt
        db.session.delete(attempt)

        # Update UserSlideProgress to mark as not completed
        progress = UserSlideProgress.query.filter_by(user_id=user_id, course_id=course_id).first()
        if progress:
            progress.completed = False
            progress.last_completed_date = None
            progress.expiry_date = None
            db.session.commit()

        db.session.commit()
        flash('Exam attempt deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting exam attempt: {e}', 'danger')

    return redirect(url_for('view_exam_attempts', course_id=course_id))

@app.route('/course/<int:course_id>/completed', methods=['GET'])
@login_required
@admin_required
def view_completed_users(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)
    
    # Ensure the course doesn't have an exam
    if course.has_exam:
        flash("This course has exams. Please use the 'Attempts' button instead.", "danger")
        return redirect(url_for('manage_courses'))

    # Fetch users who have completed the course
    completions = (
        db.session.query(UserSlideProgress, User)
        .join(User, UserSlideProgress.user_id == User.id)
        .filter(UserSlideProgress.course_id == course_id, UserSlideProgress.completed == True)
        .all()
    )

    # Pass the data to the template
    return render_template(
        'Course/view_completed_users.html',
        course=course,
        completions=completions
    )

# Assuming there is some mechanism to initiate a resit, e.g., a button press.
@app.route('/initiate_resit/<int:course_id>', methods=['POST'])
@login_required
def initiate_resit(course_id):
    user_id = current_user.id

    # Fetch the latest attempt for this course by the user
    last_attempt = (
        UserExamAttempt.query
        .filter_by(user_id=user_id, course_id=course_id)
        .order_by(UserExamAttempt.created_at.desc())
        .first()
    )

    if last_attempt:
        # Calculate the start of the resit period
        resit_start_date = last_attempt.expiry_date - timedelta(days=last_attempt.course.available_before_expiry_days)

        # If within the valid resit period or expired
        if resit_start_date <= datetime.utcnow() or last_attempt.expiry_date < datetime.utcnow():
            # Create a new attempt
            new_attempt = UserExamAttempt(
                user_id=user_id,
                course_id=course_id,
                created_at=datetime.utcnow(),
                # Set a new expiry date from the current date
                expiry_date=datetime.utcnow() + timedelta(days=last_attempt.course.valid_for_days),
                passed=False  # Start with False until confirmed
            )

            # Add the new attempt to the session and commit
            db.session.add(new_attempt)
            db.session.commit()

            return jsonify({'message': 'New attempt initiated. Expiry date reset.'}), 200

    return jsonify({'error': 'Cannot initiate resit'}), 400

# Crew Check Workflow ## Crew Check Workflow ## Crew Check Workflow ## Crew Check Workflow ## Crew Check Workflow ## Crew Check Workflow #

@app.route('/crew_checks_dashboard')
@login_required
@roles_required("Training Team", "SF34 Examiner", "ATR72 Examiner")
def crew_checks_dashboard():
    # Debug: Print the current user's roles
    user_roles = [role.role_name for role in current_user.roles]
    # Fetch all crew checks from the database
    crew_checks = CrewCheck.query.order_by(CrewCheck.created_at.desc()).all()
    # Fetch all LineTrainingForm objects from the database
    line_training_forms = LineTrainingForm.query.all()
    # Create a form instance (for editing or displaying data)
    form = LineTrainingFormEditForm()  # Empty form, used for creating or editing line training forms
    roles = RoleType.query.all()
    return render_template('crew_checks/crew_checks_dashboard.html', crew_checks=crew_checks, line_training_forms=line_training_forms, form=form, roles=roles, all_fields=CREW_CHECK_FIELDS)

@app.route('/create_crew_check', methods=['GET', 'POST'])
@login_required
@admin_required
def create_crew_check():
    if request.method == 'POST':
        name = request.form.get('name')
        role_ids = request.form.getlist('roles')  # List of role IDs

        new_check = CrewCheck(name=name)
        db.session.add(new_check)
        db.session.flush()  # Ensure new_check.id is available

        # Add roles to the check
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                new_check.roles.append(role)

        db.session.commit()
        flash('Crew Check created successfully!', 'success')
        return redirect(url_for('crew_checks_dashboard'))

    roles = RoleType.query.all()  # Get all roles
    return render_template('crew_checks/create_crew_check.html', roles=roles)

@app.route('/edit_crew_check/<int:crew_check_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_crew_check(crew_check_id):
    crew_check = CrewCheck.query.get_or_404(crew_check_id)

    if request.method == 'POST':
        crew_check.name = request.form.get('name')
        role_ids = request.form.getlist('roles')  # List of role IDs

        # Update roles
        crew_check.roles = []
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                crew_check.roles.append(role)

        # ✅ Save selected headers
        selected_headers = request.form.getlist('headers')
        crew_check.visible_headers = json.dumps(selected_headers)

        db.session.commit()
        flash('Crew Check updated successfully!', 'success')
        return redirect(url_for('crew_checks_dashboard'))


    roles = RoleType.query.all()  # Get all roles
    return render_template('edit_crew_check.html', crew_check=crew_check, roles=roles)

@app.route('/delete_crew_check/<int:crew_check_id>', methods=['POST'])
@login_required
@admin_required
def delete_crew_check(crew_check_id):
    """Allows admins to delete a crew check."""
    check = CrewCheck.query.get_or_404(crew_check_id)

    try:
        db.session.delete(check)
        db.session.commit()
        flash(f'Crew check "{check.name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting crew check: {str(e)}", "danger")

    return redirect(url_for('crew_checks_dashboard'))

# Crew Check Items
@app.route('/add_check_item/<int:check_id>', methods=['GET', 'POST'])
@login_required
def add_check_item(check_id):
    crew_check = CrewCheck.query.get_or_404(check_id)
    
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        mandatory = request.form.get('mandatory') == 'on'
        manual_link = request.form.get('manual_link')
        additional_info = request.form.get('additional_info')
        # Determine the current highest version among CheckItems for this crew check.
        # If none exist, default to 0.
        highest_version = db.session.query(func.max(CheckItem.version)).filter_by(crew_check_id=check_id).scalar() or 0
        new_version = highest_version + 1

        new_item = CheckItem(
            crew_check_id=check_id,
            item_name=item_name,
            mandatory=mandatory,
            manual_link=manual_link,
            version=new_version,   # Set new version automatically
            additional_info=additional_info
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Check Item added successfully with version {}'.format(new_version), 'success')
        return redirect(url_for('add_check_item', check_id=check_id))

    # Fetch existing check items
    check_items = CheckItem.query.filter_by(crew_check_id=check_id).all()
    return render_template('crew_checks/add_check_item.html', crew_check=crew_check, check_items=check_items)

@app.route('/get_check_item/<int:item_id>', methods=['GET'])
@login_required
def get_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    return jsonify({
        'id': item.id,
        'item_name': item.item_name,
        'mandatory': item.mandatory,
        'manual_link': item.manual_link,
        'additional_info': item.additional_info
    })

@app.route('/update_check_item/<int:item_id>', methods=['POST'])
@login_required
def update_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    item.item_name = request.form.get('item_name')
    item.mandatory = request.form.get('mandatory') == 'on'
    item.manual_link = request.form.get('manual_link')
    item.additional_info = request.form.get('additional_info')
    db.session.commit()
    return jsonify({'success': True})

#################################
###Delete/Restore Crew Check Form Item###
#################################
@app.route('/delete_check_item/<int:item_id>', methods=['POST'])
@login_required
def delete_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    
    # Mark item as deleted instead of actually deleting it
    item.deleted = True
    db.session.commit()
    
    flash("Check item marked as deleted successfully.", "success")
    return jsonify({'success': True, 'message': 'Check item marked as deleted successfully.'})

@app.route('/restore_check_item/<int:item_id>', methods=['POST'])
@login_required
def restore_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    item.deleted = False  # Restore the check item
    db.session.commit()
    flash("Check item restored successfully.", "success")
    return redirect(url_for('add_check_item', check_id=item.crew_check_id))
######################################
###Add Sorting Order to Check Items###
######################################
@app.route('/update_check_item_order', methods=['POST'])
@login_required
def update_check_item_order():
    data = request.get_json()

    print("\n=== Incoming Order Update Request ===")
    print(data)  # ✅ Debugging: Log received data

    if not data or "items" not in data:
        print("❌ Error: Invalid request data")
        return jsonify({"success": False, "message": "Invalid data"}), 400

    try:
        check_item_ids = [int(item["id"]) for item in data["items"]]  # Convert IDs to int
        check_items = CheckItem.query.filter(CheckItem.id.in_(check_item_ids)).all()

        print("\n🔍 Before Update:")
        for item in check_items:
            print(f"CheckItem ID {item.id}: Order={item.order}")

        # Update orders based on received data
        for item_data in data["items"]:
            item_id = int(item_data["id"])  # Convert ID to int
            new_order = int(item_data["order"])  # Convert order to int

            check_item = next((ci for ci in check_items if ci.id == item_id), None)
            if check_item:
                print(f"🔄 Assigning: CheckItem ID {check_item.id} → New Order {new_order}")
                check_item.order = new_order

        db.session.commit()
        print("✅ Order update committed successfully!\n")

        print("\n🔍 After Update:")
        for item in CheckItem.query.filter(CheckItem.id.in_(check_item_ids)).order_by(CheckItem.order).all():
            print(f"CheckItem ID {item.id}: Order={item.order}")

        return jsonify({"success": True, "message": "Order updated successfully"})

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error updating order: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    
#########################################
### Delete Incomplete Crew Check Forms###
#########################################
@app.route('/delete_check_meta/<int:meta_id>', methods=['POST'])
@login_required
@admin_required
def delete_check_meta(meta_id):
    check_meta = CrewCheckMeta.query.get_or_404(meta_id)
    if check_meta.is_complete:
        flash("Completed checks cannot be deleted.", "danger")
        return redirect(url_for('checks'))
    try:
        # Delete all associated CheckItemGrade records first
        grades = CheckItemGrade.query.filter_by(crew_check_meta_id=check_meta.id).all()
        for grade in grades:
            db.session.delete(grade)
        # Now delete the check meta record
        db.session.delete(check_meta)
        db.session.commit()
        flash("Incomplete check deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting check: {str(e)}", "danger")
    return redirect(url_for('checks'))


@app.route('/update_template_task/<int:task_id>', methods=['POST'])
@login_required
def update_template_task(task_id):
    data = request.get_json()

    # ✅ Validate request data
    if not data or 'task_name' not in data or 'task_notes' not in data:
        return jsonify({'success': False, 'error': 'Invalid request data'}), 400

    task_name = data.get('task_name', '').strip()
    task_notes = data.get('task_notes', '').strip()

    # ✅ Find the task
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'success': False, 'error': 'Task not found'}), 404

    if not task_name:
        return jsonify({'success': False, 'error': 'Task name cannot be empty'}), 400

    try:
        # ✅ Update the task
        task.name = task_name
        task.notes = task_notes
        db.session.commit()
        return jsonify({'success': True, 'updated_name': task.name, 'updated_notes': task.notes})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_candidate_details/<int:candidate_id>', methods=['GET'])
@login_required
def get_candidate_details(candidate_id):
    """Returns candidate details for auto-filling the form"""
    candidate = User.query.get(candidate_id)
    
    if not candidate:
        return jsonify({"error": "Candidate not found"}), 404

    return jsonify({
        "license_type": candidate.license_type,
        "license_number": candidate.license_number,
        "medical_expiry": candidate.medical_expiry.strftime('%Y-%m-%d') if candidate.medical_expiry else "",
        'crew_code': candidate.crew_code
    })

@app.route('/crew_check_form/<int:crew_check_id>', methods=['GET', 'POST'])
@login_required
def crew_check_form(crew_check_id):
    today = datetime.today().strftime('%Y-%m-%d')
    crew_check = CrewCheck.query.get_or_404(crew_check_id)
    # Get the role IDs assigned to this crew check
    assigned_role_ids = [role.roleID for role in crew_check.roles]
    # Only fetch users who have at least one of the assigned roles
    all_candidates = (
    User.query
    .join(User.roles)
    .filter(RoleType.roleID.in_(assigned_role_ids))
    .filter(User.is_active == True)  # Exclude archived users
    .distinct()
    .all()
    )

    check_items = CheckItem.query.filter_by(crew_check_id=crew_check_id).order_by(CheckItem.order).all()

    draft_id = request.args.get('draft_id', type=int)
    check_meta = CrewCheckMeta.query.get(draft_id) if draft_id else None

    candidate_id = request.args.get('candidate_id', type=int)
    form_id = request.args.get('form_id', type=int)
    candidate = User.query.get(candidate_id) if candidate_id else None

    candidate_data = {
        "username": candidate.username if candidate else "",
        "license_number": candidate.license_number if candidate else "",
        "medical_expiry": candidate.medical_expiry.strftime('%Y-%m-%d') if candidate and candidate.medical_expiry else "",
        "aircraft_type": "SF34",
    }

    visible_fields = json.loads(crew_check.visible_headers or "[]")

    if request.method == 'POST':
        candidate_id_form = request.form.get('candidate_id')
        if not candidate_id_form:
            return jsonify({'success': False, 'error': 'Candidate must be selected.'}), 400
        try:
            candidate_id_form = int(candidate_id_form)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid candidate selection.'}), 400
        candidate = User.query.get(candidate_id_form)
        if not candidate:
            return jsonify({'success': False, 'error': 'Selected candidate not found.'}), 404

        if check_meta:
            updated_meta = check_meta
        else:
            updated_meta = CrewCheckMeta(crew_check_id=crew_check.id)
            db.session.add(updated_meta)

        updated_meta.candidate_id = candidate.id

        field_map = {
            "candidate_name": 'candidate_name',
            "licence_type": 'licence_type',
            "licence_number": 'licence_number',
            "medical_expiry": 'medical_expiry',
            "date_of_test": 'date_of_test',
            "aircraft_type": 'aircraft_type',
            "aircraft_registration": 'aircraft_registration',
            "type_of_check": 'type_of_check',
            "comments": 'comments',
            "flight_times": 'flight_times',
            "current_check_due": 'current_check_due',
            "test_result": 'test_result',
            "logbook_sticker_issued": 'logbook_sticker_issued',
            "next_check_due": 'next_check_due',
            "examiner_name": 'examiner_name',
            "examiner_license_number": 'examiner_license_number'
        }

        for field_key, attr in field_map.items():
            if field_key in visible_fields:
                setattr(updated_meta, attr, request.form.get(field_key))
            else:
                setattr(updated_meta, attr, None)

        if 'flight_times' in visible_fields:
            try:
                updated_meta.flight_time_day = int(request.form.get('flight_time_day', '0'))
                updated_meta.flight_time_night = int(request.form.get('flight_time_night', '0'))
                updated_meta.flight_time_if = int(request.form.get('flight_time_if', '0'))
            except ValueError:
                updated_meta.flight_time_day = updated_meta.flight_time_night = updated_meta.flight_time_if = 0
        else:
            updated_meta.flight_time_day = updated_meta.flight_time_night = updated_meta.flight_time_if = None

        if not updated_meta.is_complete:
            updated_meta.examiner_name = current_user.username
            updated_meta.examiner_license_number = current_user.license_number

        updated_meta.examiner_code = request.form.get('examiner_code')
        updated_meta.candidate_code = request.form.get('candidate_code')

        current_template_version = (
            db.session.query(func.max(CheckItem.version))
            .filter_by(crew_check_id=crew_check.id)
            .scalar()
        ) or 1
        updated_meta.template_version = current_template_version

        if 'save_draft' in request.form:
            updated_meta.is_complete = False
            flash('Crew check form saved as draft.', 'info')
        else:
            updated_meta.is_complete = True
            flash('Crew check form submitted successfully!', 'success')

        db.session.commit()

        for item in check_items:
            grade_value = request.form.get(f'grade_{item.id}')
            comment_value = request.form.get(f'comment_{item.id}', '').strip()
            comment_to_save = comment_value if comment_value else None

            existing_grade = CheckItemGrade.query.filter_by(
                crew_check_meta_id=updated_meta.id,
                check_item_id=item.id
            ).first()

            if grade_value:
                if existing_grade:
                    existing_grade.grade = grade_value
                    existing_grade.grade_comment = comment_to_save
                    existing_grade.grader_id = current_user.id
                    existing_grade.graded_at = datetime.now()
                else:
                    new_grade = CheckItemGrade(
                        crew_check_meta_id=updated_meta.id,
                        check_item_id=item.id,
                        grade=grade_value,
                        grade_comment=comment_to_save,
                        grader_id=current_user.id,
                        graded_at=datetime.now()
                    )
                    db.session.add(new_grade)

        db.session.commit()

        if updated_meta.is_complete:
            from app.email_utils import send_crew_check_email_to_training_team
            send_crew_check_email_to_training_team(current_app._get_current_object(), updated_meta.id)

        return jsonify({'success': True, 'draft_id': updated_meta.id})

    user_roles = [role.role_name for role in current_user.roles]

    return render_template(
        'crew_checks/crew_check_form.html',
        today=today,
        crew_check=crew_check,
        candidate=candidate,
        candidate_id=candidate_id,
        check_items=check_items,
        all_candidates=all_candidates,
        form_id=form_id,
        check_meta=check_meta,
        candidate_data=candidate_data,
        user_roles=user_roles,
        visible_fields=visible_fields
    )


##########################
### View My Crew Check ###
##########################
@app.route('/view_my_crew_check/<int:meta_id>')
@login_required
def view_my_crew_check(meta_id):
    """Read-only view for crew check."""
    check_meta = CrewCheckMeta.query.get_or_404(meta_id)

    # ✅ Ensure only the owner (candidate) can view the check
    if check_meta.candidate_id != current_user.id:
        print(f"❌ Unauthorized access attempt! User: {current_user.username} tried to access Check ID: {meta_id}")
        flash("You do not have permission to view this check.", "danger")
        return redirect(url_for('my_crew_checks'))

    print(f"✅ Crew Check Found: ID {check_meta.id}, Candidate: {check_meta.candidate_id}")

    # ✅ Load check template to get visible field configuration
    crew_check = CrewCheck.query.get(check_meta.crew_check_id)
    visible_fields = json.loads(crew_check.visible_headers or "[]")

    check_items = CheckItem.query.filter_by(crew_check_id=check_meta.crew_check_id).all()

    return render_template(
        'user/view_my_check.html',
        check_meta=check_meta,
        check_items=check_items,
        visible_fields=visible_fields
    )


##############################################
### Verify Examinar and Candidate Password ###
##############################################
@app.route('/verify_sign_password', methods=['POST'])
@login_required
def verify_sign_password():
    # Retrieve form data; draft_id may be empty if the form isn’t saved yet.
    user_crew_code = request.form.get("user_id", "").strip()  # Crew code
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "").strip()  # 'examiner' or 'candidate'
    draft_id = request.form.get("draft_id", "").strip()  # May be empty
    crew_check_id = request.form.get("crew_check_id", "").strip()  # Fallback if draft_id is missing

    # Validate required fields (except draft_id which is now optional)
    if not user_crew_code or not password or not role:
        app.logger.error("Missing crew code, password, or role in verify_sign_password")
        return jsonify({'success': False, 'error': 'Crew code, password, and role are required.'}), 400

    # Look up the user by crew_code
    user = User.query.filter_by(crew_code=user_crew_code).first()
    if not user:
        app.logger.error("User not found for Crew Code: %s", user_crew_code)
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    # Retrieve the appropriate CrewCheckMeta record:
    # If draft_id is provided, use it; otherwise, fall back to crew_check_id.
    if draft_id:
        crew_check_meta = CrewCheckMeta.query.get(draft_id)
        if not crew_check_meta:
            app.logger.error("Crew check meta not found for Draft ID: %s", draft_id)
            return jsonify({'success': False, 'error': 'Crew check meta not found.'}), 404
    else:
        if not crew_check_id:
            app.logger.error("Missing crew check id when draft id is not provided")
            return jsonify({'success': False, 'error': 'Crew check id is required if draft id is missing.'}), 400
        # Query for the most recent CrewCheckMeta record for the given crew_check_id.
        crew_check_meta = (CrewCheckMeta.query
                           .filter_by(crew_check_id=crew_check_id)
                           .order_by(CrewCheckMeta.id.desc())
                           .first())
        if not crew_check_meta:
            app.logger.error("No CrewCheckMeta record found for crew_check_id: %s", crew_check_id)
            return jsonify({'success': False, 'error': 'Crew check meta not found.'}), 404

    # Construct payload for external authentication
    payload = {"username": user.crew_code, "password": password, "nonce": "some_nonce"}
    app.logger.info("Sending payload to %s: %s", ENVISION_AUTH_URL, payload)

    try:
        response = requests.post(ENVISION_AUTH_URL, json=payload, verify=False)
        app.logger.info("Received response with status %s: %s", response.status_code, response.text)
    except Exception as e:
        app.logger.error("Error calling Envision API: %s", e)
        return jsonify({'success': False, 'error': str(e)}), 500

    if response.status_code == 200:
        data = response.json()
        if not data.get("token"):
            app.logger.error("API response missing token: %s", data)
            return jsonify({'success': False, 'error': 'Invalid password.'}), 400

        # Update the CrewCheckMeta record based on role
        if role == 'examiner':
            crew_check_meta.examiner_signed = True
        elif role == 'candidate':
            crew_check_meta.candidate_signed = True

        db.session.commit()
        return jsonify({'success': True})
    else:
        app.logger.error("Envision API returned error status %s: %s", response.status_code, response.text)
        return jsonify({'success': False, 'error': 'Invalid password.'}), 400

###############################################
###IFR/OCA Crew Checks (Complete/Incomplete)###
###############################################
@app.route('/checks')
@login_required
@roles_required('Training Team', 'SF34 Examiner', 'ATR72 Examiner')
def checks():
    status_filter = request.args.get('status', 'all')
    aircraft_filter = request.args.get('aircraft', 'all')
    candidate_filter = request.args.get('candidate', '')
    type_of_check_filter = request.args.get('type_of_check', 'all')
    sort_by = request.args.get('sort_by', 'date_of_test')
    order = request.args.get('order', 'asc')

    # Fetch all candidates
    all_candidates = User.query.all()

    # Fetch all distinct crew check names (for filter dropdown)
    crew_checks = CrewCheck.query.with_entities(CrewCheck.name).distinct().all()

    # Fetch all crew check meta data
    crew_checks_meta = CrewCheckMeta.query.all()

    active_filter = request.args.get('active', 'all')
    # Apply filters
    filtered_checks = []
    for check_meta in crew_checks_meta:
        completed = check_meta.is_complete
        user_active = check_meta.candidate.is_active if check_meta.candidate else False

        if (status_filter == 'all' or (status_filter == 'completed' and completed) or (status_filter == 'incomplete' and not completed)) and \
        (aircraft_filter == 'all' or check_meta.aircraft_type == aircraft_filter) and \
        (candidate_filter == '' or candidate_filter.lower() in check_meta.candidate.username.lower()) and \
        (type_of_check_filter == 'all' or check_meta.check.name == type_of_check_filter) and \
        (active_filter == 'all' or (active_filter == 'active' and user_active) or (active_filter == 'inactive' and not user_active)):
            filtered_checks.append(check_meta)

    # Apply sorting
    reverse = (order == 'desc')
    if sort_by == 'check_name':
        filtered_checks.sort(key=lambda x: x.check.name, reverse=reverse)
    elif sort_by == 'aircraft_type':
        filtered_checks.sort(key=lambda x: x.aircraft_type or '', reverse=reverse)
    elif sort_by == 'candidate':
        filtered_checks.sort(key=lambda x: x.candidate.username, reverse=reverse)
    elif sort_by == 'date_of_test':
        filtered_checks.sort(key=lambda x: x.date_of_test, reverse=reverse)
    elif sort_by == 'test_result':
        filtered_checks.sort(key=lambda x: x.test_result, reverse=reverse)
    elif sort_by == 'status':
        filtered_checks.sort(key=lambda x: x.is_complete, reverse=reverse)
    elif sort_by == 'next_check_due':
        filtered_checks.sort(key=lambda x: x.next_check_due, reverse=reverse)

    return render_template(
        'crew_checks/checks.html',
        crew_checks_meta=filtered_checks,
        all_candidates=all_candidates,
        crew_checks=[check for check, in crew_checks]  # Extract check names only
    )


######################
###User Crew Checks###
#####################
@app.route('/my_checks')
@login_required
def my_crew_checks():
    # Fetch only completed checks for the logged-in user
    completed_checks = CrewCheckMeta.query.filter_by(candidate_id=current_user.id, is_complete=True).order_by(CrewCheckMeta.date_of_test.desc()).all()

    return render_template('user/my_checks.html', crew_checks_meta=completed_checks)

###############################
###Print IFR/OCA Crew Check###
###############################

@app.route('/print_check/<int:check_meta_id>')
@login_required
def print_check(check_meta_id):
    # Retrieve the CrewCheckMeta record
    check_meta = CrewCheckMeta.query.get_or_404(check_meta_id)
    today = datetime.today().strftime('%Y-%m-%d')

    # Prepare candidate data for the template
    candidate_data = {
        'license_type': check_meta.candidate.license_type if check_meta.candidate else "Not Provided",
        'license_number': check_meta.candidate.license_number if check_meta.candidate else "Not Provided",
        'medical_expiry': (
            check_meta.candidate.medical_expiry.strftime('%Y-%m-%d')
            if check_meta.candidate and check_meta.candidate.medical_expiry else "Not Provided"
        )
    }

    # ✅ Add visible_fields extraction
    visible_fields = json.loads(check_meta.check.visible_headers or "[]")

    # Render the crew check PDF template
    rendered_html = render_template(
        "crew_checks/crew_check_form_pdf.html",
        crew_check_meta=check_meta,
        today=today,
        candidate_data=candidate_data,
        visible_fields=visible_fields  # Pass it in
    )

    # Configure pdfkit – ensure wkhtmltopdf path is correct
    path_wkhtmltopdf = r'C:\Users\Jayden\OneDrive - Air Chathams Ltd\Desktop\LMS Platform\wkhtmltopdf.exe'
    config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
    options = {
        'page-size': 'A4',
        'encoding': "UTF-8",
        'no-outline': None,
    }

    try:
        pdf_data = pdfkit.from_string(rendered_html, False, configuration=config, options=options)
    except Exception as e:
        app.logger.error(f"Error generating PDF: {e}")
        return f"Error generating PDF: {e}", 500

    # Return inline PDF response
    return Response(pdf_data,
                    mimetype='application/pdf',
                    headers={'Content-Disposition': 'inline; filename="CrewCheckForm.pdf"'})

@app.route('/create_line_training_form', methods=['GET', 'POST'])
@login_required
@admin_required
def create_line_training_form():
    if request.method == 'POST':
        form_name = request.form['name']
        selected_roles = request.form.getlist('roles')  # Get selected roles from the form

        # Create a new LineTrainingForm object
        new_form = LineTrainingForm(name=form_name)

        # Associate roles with the new line training form
        for role_id in selected_roles:
            role = RoleType.query.get(role_id)
            if role:
                new_form.roles.append(role)

        db.session.add(new_form)
        db.session.commit()

        flash('Line training form created successfully!', 'success')
        return redirect(url_for('crew_checks_dashboard'))

    roles = RoleType.query.all()  # Fetch all available roles to display in the form
    return render_template('crew_checks/create_line_training_form.html', roles=roles)



@app.route('/add_items_to_line_training_form/<int:form_id>', methods=['GET', 'POST'])
def add_items_to_line_training_form(form_id):
    form = LineTrainingForm.query.get_or_404(form_id)
    
    # Add new topic
    if request.method == 'POST' and 'add_topic' in request.form:
        topic_name = request.form['topic_name']
        new_topic = Topic(name=topic_name, line_training_form_id=form.id)
        db.session.add(new_topic)
        db.session.commit()
        flash('Topic added!', 'success')

    # Add new task to a specific topic with trainer's notes
    if request.method == 'POST' and 'add_task' in request.form:
        topic_id = request.form['topic_id']
        task_name = request.form['task_name']
        task_notes = request.form['task_notes']  # Capturing the trainer's notes
        new_task = Task(name=task_name, topic_id=topic_id, notes=task_notes)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added!', 'success')
    
    # Get all topics for this form
    topics = form.topics

    return render_template('line_training_forms/add_items_to_line_training_form.html', form=form, topics=topics)

@app.route('/create_active_line_training_form/<int:template_id>', methods=['GET', 'POST'])
def create_active_line_training_form(template_id):
    template = LineTrainingForm.query.get_or_404(template_id)

    if request.method == 'POST':
        # Get candidate details
        candidate_id = request.form.get('candidate_id')
        candidate = User.query.get_or_404(candidate_id)

        # Check if the form already exists for the candidate
        existing_form = UserLineTrainingForm.query.filter_by(user_id=candidate.id, template_id=template.id).first()
        if existing_form:
            flash(f"A Line Training Form for {candidate.username} using this template already exists!", "warning")
            return redirect(url_for('view_user_line_training_form', form_id=existing_form.id))

        # Create a new user-specific line training form
        active_form = UserLineTrainingForm(user_id=candidate.id, template_id=template.id)
        db.session.add(active_form)
        db.session.flush()  # Flush to generate the active_form ID

        # Copy topics and tasks from the template to the user-specific form
        for topic in template.topics:
            # Check if the topic already exists
            existing_topic = Topic.query.filter_by(user_line_training_form_id=active_form.id, name=topic.name).first()
            if not existing_topic:
                new_topic = Topic(name=topic.name, user_line_training_form_id=active_form.id)
                db.session.add(new_topic)
                db.session.flush()  # Get new topic ID

                for task in topic.tasks:
                    # Check if the task already exists
                    existing_task = Task.query.filter_by(topic_id=new_topic.id, name=task.name).first()
                    if not existing_task:
                        new_task = Task(name=task.name, topic_id=new_topic.id, notes=task.notes)
                        db.session.add(new_task)

        db.session.commit()

        flash(f"Line Training Form for {candidate.username} created successfully!", "success")
        return redirect(url_for('view_user_line_training_form', form_id=active_form.id))

    # Display a candidate selection form
    candidates = User.query.all()
    return render_template('Line_Training_Forms/select_candidate.html', template=template, candidates=candidates)

@app.route('/view_active_line_training_forms_for_examiners', methods=['GET'])
def view_active_line_training_forms_for_examiners():
    search = request.args.get('search', '').strip()
    user_roles = [role.role_name for role in current_user.roles]

    # If user is in Training Team, they can see all forms
    if 'Training Team' in user_roles:
        query = UserLineTrainingForm.query
    else:
        # Base query with role-based filtering
        query = UserLineTrainingForm.query

        if 'SF34 Examiner' in user_roles and 'ATR72 Examiner' not in user_roles:
            # Only SF34 forms (Customisable)
            query = query.filter(UserLineTrainingForm.template.has(name='SF34 Line Training Form'))
        elif 'ATR72 Examiner' in user_roles and 'SF34 Examiner' not in user_roles:
            # Only ATR72 forms (Customisable)
            query = query.filter(UserLineTrainingForm.template.has(name='ATR72 Line Training Form'))
        elif 'Instructor' in user_roles or ('SF34 Examiner' in user_roles and 'ATR72 Examiner' in user_roles):
            # These roles see all forms (Customisable)
            pass  # No additional filtering needed
        else:
            # Default to no forms for roles not matching criteria
            query = query.filter(False)

    # Apply search filters if provided
    if search:
        query = query.filter(
            UserLineTrainingForm.user.has(User.username.ilike(f"%{search}%")) |
            (UserLineTrainingForm.id == search)
        )

    # Eager loading for templates and users
    active_forms = query.options(
        joinedload(UserLineTrainingForm.user),
        joinedload(UserLineTrainingForm.template)
    ).all()

    return render_template('Line_Training_Forms/examiners_active_line_training_forms.html', active_forms=active_forms)

@app.route('/examiners/line_training_form/<int:form_id>', methods=['GET', 'POST'])
def view_active_line_training_form(form_id):
    form = UserLineTrainingForm.query.get_or_404(form_id)
    candidate = form.user  # Assuming the candidate is the user associated with the form

    # Candidate details
    candidate_name = candidate.username
    license_number = candidate.license_number
    medical_expiry_date = candidate.medical_expiry.strftime('%Y-%m-%d') if candidate.medical_expiry else "Not Available"

    # Dynamically calculate total flight time and sectors from the Sector table
    total_flight_time_sectors = Sector.query.filter_by(form_id=form_id).count()
    total_flight_time_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0
    total_takeoffs = db.session.query(db.func.sum(Sector.takeoff_count)).filter_by(form_id=form_id).scalar() or 0
    total_landings = db.session.query(db.func.sum(Sector.landing_count)).filter_by(form_id=form_id).scalar() or 0
    total_flight_time_hours = round(total_flight_time_hours, 1)

    # Task completion percentage
    total_tasks = sum(len(topic.tasks) for topic in form.topics)
    completed_tasks = sum(
        len([task for task in topic.tasks if TaskCompletion.query.filter_by(task_id=task.id).first()])
        for topic in form.topics
    )
    percentage_complete = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0

    if request.method == 'POST':
        # Debug: Print all incoming form data for the POST request
        print("Form Data Submitted:", request.form)

        # Parse incoming form data for new sectors
        row_count = len([key for key in request.form.keys() if key.startswith('date_')])
        print(f"Total number of sectors to process: {row_count}")

        # Get the last existing sector_number for this form
        last_sector = Sector.query.filter_by(form_id=form_id).order_by(Sector.sector_number.desc()).first()
        next_sector_number = last_sector.sector_number + 1 if last_sector else 1  # If no sectors exist, start with 1
        print(f"Next sector number: {next_sector_number}")

        for i in range(1, row_count + 1):
            # Debug: Print each sector's data from the form
            date = request.form.get(f'date_{i}')
            variant = request.form.get(f'variant_{i}')
            departure = request.form.get(f'departure_{i}')
            arrival = request.form.get(f'arrival_{i}')
            flight_time_sector = request.form.get(f'flight_time_sector_{i}', type=float)
            flight_time_total = request.form.get(f'flight_time_total_{i}', type=float)
            # if_time_sector = request.form.get(f'if_time_sector_{i}', type=float) or 0
            # if_time_total = request.form.get(f'if_time_total_{i}', type=float) or 0
            # sector_type = request.form.get(f'type_{i}')
            takeoff = request.form.get(f'takeoff_{i}', type=int) or 0
            landing = request.form.get(f'landing_{i}', type=int) or 0
            total_takeoffs=total_takeoffs,
            total_landings=total_landings,

            # Debug: Check what data was received for each sector
            print(f"Processing Data for Sector {i}:")
            print(f"Date: {date}, Variant: {variant}, Departure: {departure}, Arrival: {arrival}")
            print(f"Flight Time Sector: {flight_time_sector}, Flight Time Total: {flight_time_total}")
            print(f"Takeoff: {takeoff}, Landing: {landing}")

            # Validate required fields
            if not date or not variant or not departure or not arrival:
                print(f"Missing fields in sector {i}. Skipping this sector.")
                flash("All fields are required for a new sector.", "danger")
                return redirect(request.url)

            # Create and add new Sector with the correct sector_number
            new_sector = Sector(
                form_id=form.id,
                date=datetime.strptime(date, '%Y-%m-%d'),
                variant=variant,
                dep=departure,
                arr=arrival,
                flight_time_sector=flight_time_sector,
                flight_time_total=flight_time_total,
                #if_time_sector=if_time_sector,
                #if_time_total=if_time_total,
                #type=sector_type,
                takeoff_count=takeoff,
                landing_count=landing,
                sector_number=next_sector_number  # Assign the calculated sector_number
            )
            db.session.add(new_sector)
            next_sector_number += 1  # Increment the sector number for the next one

        try:
            db.session.commit()
            flash('Sector count updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            print(f"Error: {str(e)}")  # Debugging the error message

        return redirect(url_for('view_active_line_training_form', form_id=form_id))

    return render_template(
        'Line_Training_Forms/view_active_line_training_form.html',
        form=form,
        candidate_name=candidate_name,
        license_number=license_number,
        medical_expiry_date=medical_expiry_date,
        total_flight_time_sectors=total_flight_time_sectors,
        total_flight_time_hours=total_flight_time_hours,
        total_takeoffs=total_takeoffs,  # Add this
        total_landings=total_landings,  # Add this
        percentage_complete=percentage_complete,
        user=current_user
    )

@app.route('/get_sector_note/<int:sector_id>', methods=['GET'])
def get_sector_note(sector_id):
    sector = Sector.query.get_or_404(sector_id)
    return jsonify({
        'success': True,
        'note': sector.notes
    })

@app.route('/save_sector', methods=['POST'])
def save_sector():
    data = request.get_json()  # Get the incoming data as JSON

    # Debugging log
    app.logger.info(f"Received data: {data}")

    # Ensure all required fields are present
    required_fields = [
        'form_id', 'date', 'variant', 'departure', 'arrival',
        'flight_time_sector', 'flight_time_total', 'takeoff', 'landing'
    ]
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    try:
        # Fetch the form and validate
        form_id = int(data['form_id'])
        form = UserLineTrainingForm.query.get(form_id)
        if not form:
            return jsonify({'error': f'Form with id {form_id} not found'}), 404

        # Fetch the last sector number for the given form_id
        last_sector = Sector.query.filter_by(form_id=form_id).order_by(Sector.sector_number.desc()).first()
        next_sector_number = (last_sector.sector_number + 1) if last_sector else 1

        # Create the new sector object
        new_sector = Sector(
            form_id=form_id,  # Match the foreign key field in Sector
            date=datetime.strptime(data['date'], '%Y-%m-%d'),
            variant=data['variant'],
            dep=data['departure'],
            arr=data['arrival'],
            flight_time_sector=float(data['flight_time_sector']),
            flight_time_total=float(data['flight_time_total']),
            #if_time_sector=float(data.get('if_time_sector', 0)),
            #if_time_total=float(data.get('if_time_total', 0)),
            type=data.get('type', ''),
            takeoff_count=int(data['takeoff']),
            landing_count=int(data['landing']),
            sector_number=next_sector_number,
            saved=True,
            notes=str(data.get('notes', '')) or None,
            note_creator_id=current_user.id if data.get('notes') else None  # Log user if a note is present
        )

        # Add the new sector to the database
        db.session.add(new_sector)

        # Update the form totals
        form.total_sectors += 1
        form.total_hours = (form.total_hours or 0) + float(data['flight_time_total'])
        db.session.commit()

        app.logger.info(f"Sector saved successfully: {new_sector}")
        app.logger.info(f"Updated totals: Sectors={form.total_sectors}, Hours={form.total_hours}")

        # Return success response
        return jsonify({
            'success': True,
            'sector_id': new_sector.id,
            'sector_number': next_sector_number,
            'updated_totals': {
                'total_sectors': form.total_sectors,
                'total_hours': form.total_hours,
                'note_creator': current_user.username if data.get('notes') else None  # Return username
            }
        }), 200

    except ValueError as ve:
        app.logger.error(f"Validation error: {ve}")
        return jsonify({'error': f'Invalid data: {str(ve)}'}), 400
    except Exception as e:
        app.logger.error(f"Error saving sector: {e}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while saving the sector'}), 500

@app.route('/edit_topic/<int:topic_id>', methods=['GET', 'POST'])
def edit_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if request.method == 'POST':
        topic.name = request.form['topic_name']
        db.session.commit()
        flash('Topic updated!', 'success')
        return redirect(url_for('add_items_to_line_training_form', form_id=topic.line_training_form_id))
    return render_template('edit_topic.html', topic=topic)

@app.route('/delete_topic/<int:topic_id>', methods=['POST'])
def delete_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    db.session.delete(topic)
    db.session.commit()
    flash('Topic deleted!', 'success')
    return redirect(url_for('add_items_to_line_training_form', form_id=topic.line_training_form_id))

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        task.name = request.form['task_name']
        task.is_completed = 'is_completed' in request.form  # Handle checkbox
        task.notes = request.form['notes']
        db.session.commit()
        flash('Task updated!', 'success')
        return redirect(url_for('add_items_to_line_training_form', form_id=task.topic.line_training_form_id))
    return render_template('edit_task.html', task=task)

# In your delete_task function
@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    # Fetch the task and ensure it's part of the session
    task = Task.query.get_or_404(task_id)
    
    # Access task.topic while still within the session
    topic_id = task.topic_id  # Now task.topic should be accessible
    
    # Set the topic_id to None if you want to dissociate the task from the topic
    task.topic_id = None
    
    db.session.commit()
    
    # Now delete the task
    db.session.delete(task)
    db.session.commit()

    flash('Task deleted successfully', 'success')
    return redirect(url_for('add_items_to_line_training_form', form_id=topic_id))

@login_required
@admin_required
@app.route('/remove_sector/<int:sector_id>', methods=['DELETE'])
def remove_sector(sector_id):
    sector = Sector.query.get(sector_id)
    if sector:
        try:
            db.session.delete(sector)  # Remove the sector from the database
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 400
    else:
        return jsonify({'success': False, 'error': 'Sector not found'}), 404

@app.route('/delete_sector/<int:sector_id>', methods=['DELETE'])
def delete_sector(sector_id):
    try:
        # Fetch the sector from the database
        sector = Sector.query.get_or_404(sector_id)
        form_id = sector.form_id

        # Delete the sector
        db.session.delete(sector)
        db.session.commit()

        # Recalculate totals
        total_sectors = Sector.query.filter_by(form_id=form_id).count()
        total_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0

        # Update the form's totals
        form = UserLineTrainingForm.query.get(form_id)
        form.total_sectors = total_sectors
        form.total_hours = total_hours
        db.session.commit()

        app.logger.info(f"Sector {sector_id} deleted. Updated totals: Sectors={total_sectors}, Hours={total_hours}")

        return jsonify({'success': True, 'total_sectors': total_sectors, 'total_hours': total_hours}), 200
    except Exception as e:
        app.logger.error(f"Error deleting sector {sector_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/update_task', methods=['POST'])
def update_task():
    data = request.get_json()

    # Extract data from the received JSON
    form_id = data['form_id']
    task_id = data['task_id']
    completed = data['completed']

    # Get the task from the database
    task = Task.query.get_or_404(task_id)

    try:
        if completed:
            # Check if a completion already exists
            completion = TaskCompletion.query.filter_by(task_id=task.id, form_id=form_id).first()
            if not completion:
                # If no completion exists, create a new one
                completion = TaskCompletion(
                    task_id=task.id,
                    form_id=form_id,
                    trainer_id=current_user.id,  # Set current user as the trainer
                    completed_at=datetime.utcnow()  # Log the timestamp
                )
                db.session.add(completion)
        else:
            # If the task is being unchecked, delete the completion if it exists
            completion = TaskCompletion.query.filter_by(task_id=task.id, form_id=form_id).first()
            if completion:
                db.session.delete(completion)

        # Commit the changes to the database
        db.session.commit()

        # Return success response with updated "completed_by" information
        completed_by = None
        if completed:
            completed_by = {
                "username": current_user.username,
                "completed_at": datetime.utcnow().strftime('%d-%m-%Y-')
            }

        return jsonify({'success': True, 'completed_by': completed_by})
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/edit_line_training_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_line_training_form(form_id):
    form = LineTrainingForm.query.get_or_404(form_id)
    roles = RoleType.query.all()  # Get all roles from the RoleType table
    
    # Create the FlaskForm
    edit_form = LineTrainingFormEditForm(obj=form)
    edit_form.roles.choices = [(role.roleID, role.role_name) for role in roles]

    if request.method == 'POST' and edit_form.validate_on_submit():
        form.name = edit_form.name.data  # Update the form name
        selected_roles = edit_form.roles.data  # Get selected roles
        form.roles = [RoleType.query.get(role_id) for role_id in selected_roles]
        
        db.session.commit()
        flash('Line Training Form updated successfully!', 'success')
        return redirect(url_for('crew_checks_dashboard'))

    return render_template('Line_Training_Forms/edit_line_training_form.html', form=edit_form, roles=roles)

@app.route('/delete_line_training_form/<int:form_id>', methods=['POST'])
def delete_line_training_form(form_id):
    form = UserLineTrainingForm.query.get_or_404(form_id)

    try:
        # Delete all associated task completions first
        for topic in form.topics:
            for task in topic.tasks:
                TaskCompletion.query.filter_by(task_id=task.id).delete()

        # Delete associated tasks and topics
        for topic in form.topics:
            for task in topic.tasks:
                db.session.delete(task)
            db.session.delete(topic)

        # Delete the form itself
        db.session.delete(form)
        db.session.commit()

        flash("Line Training Form deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred while deleting the form: {str(e)}", "danger")

    return redirect(url_for('view_active_line_training_forms_for_examiners'))

@app.route('/update_totals', methods=['POST'])
def update_totals():
    try:
        # Parse the incoming request data
        data = request.get_json()
        form_id = data['form_id']

        # Validate form_id
        if not form_id:
            raise ValueError("form_id is required.")

        # Fetch the form from the database
        form = UserLineTrainingForm.query.get(form_id)
        if not form:
            return jsonify({'success': False, 'error': f"Form with id {form_id} not found."}), 404

        # Commit any pending changes to ensure the latest data is used
        db.session.commit()

        # Query the Sector table for updated totals
        total_sectors = Sector.query.filter_by(form_id=form_id).count()
        total_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0

        # Log the updated totals
        app.logger.info(f"Form ID {form_id}: Updated totals - Sectors={total_sectors}, Hours={total_hours}")

        # Send email if threshold is exceeded
        if total_sectors > 10:
            send_email_to_training_team(mail, app, form_id, total_sectors, total_hours)

        # Return updated totals to the frontend
        return jsonify({
            'success': True,
            'total_sectors': total_sectors,
            'total_hours': round(total_hours, 2)  # Round total hours for clarity
        }), 200
    except ValueError as ve:
        app.logger.error(f"Validation error: {ve}")
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        # Log and return the error response
        app.logger.error(f"Error in /update_totals: {e}")
        return jsonify({'success': False, 'error': "An unexpected error occurred."}), 500

@app.route('/release_candidate/<int:form_id>', methods=['POST'])
@login_required
def release_candidate(form_id):
    try:
        # Fetch the form and its template
        form = UserLineTrainingForm.query.get_or_404(form_id)
        candidate = form.user

        if not candidate:
            return jsonify({'success': False, 'error': 'Candidate not found.'}), 404

        # Ensure the candidate meets the release criteria
        total_takeoffs = sum(sector.takeoff_count or 0 for sector in form.sectors)
        total_landings = sum(sector.landing_count or 0 for sector in form.sectors)
        total_hours = form.total_hours or 0

        if total_hours < 20 or total_takeoffs < 10 or total_landings < 10:
            return jsonify({'success': False, 'error': 'Candidate does not meet the requirements for release.'}), 400

        # Update the released status
        form.released = True
        db.session.commit()

        # Send email notification to supervisors
        Send_Release_To_Supervisor_Email(
            app, candidate, form.template.name, form.id, total_hours, total_takeoffs, total_landings, form.template.roles
        )

        return jsonify({
            'success': True,
            'message': f"Candidate {candidate.username} has been successfully released."
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error releasing candidate: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/complete_route_check/<int:form_id>', methods=['GET'])
@login_required
def complete_route_check(form_id):
    """Redirect to the IFR/OCA Check Form with pre-filled candidate details."""
    form = UserLineTrainingForm.query.get_or_404(form_id)
    candidate = form.user

    if not candidate:
        flash("Candidate not found.", "danger")
        return redirect(url_for('view_active_line_training_form', form_id=form_id))

    # Redirect to the IFR/OCA Check Form while passing candidate details as query parameters
    return redirect(url_for('crew_check_form', crew_check_id=1, candidate_id=candidate.id))

@app.route('/roster')
@login_required
def roster():
    return render_template('roster/roster.html', user=current_user)

from pytz import timezone

from pytz import timezone

@app.route('/crew_acknowledgements')
@login_required
def crew_acknowledgements():
    user = current_user
    acks = CrewAcknowledgement.query.filter_by(crew_member_id=user.employee_id).all()
    nz_tz = timezone('Pacific/Auckland')

    for ack in acks:
        flight = ack.flight
        if flight.parent_id:
            ack.original_duty = Flight.query.get(flight.parent_id)
        else:
            ack.original_duty = None

        # NZ time conversions
        if flight.departureScheduled:
            ack.departureScheduled_nz = flight.departureScheduled.astimezone(nz_tz)
        else:
            ack.departureScheduled_nz = None

        if flight.arrivalScheduled:
            ack.arrivalScheduled_nz = flight.arrivalScheduled.astimezone(nz_tz)
        else:
            ack.arrivalScheduled_nz = None

        if ack.original_duty:
            if ack.original_duty.departureScheduled:
                ack.originalDeparture_nz = ack.original_duty.departureScheduled.astimezone(nz_tz)
            else:
                ack.originalDeparture_nz = None

            if ack.original_duty.arrivalScheduled:
                ack.originalArrival_nz = ack.original_duty.arrivalScheduled.astimezone(nz_tz)
            else:
                ack.originalArrival_nz = None

    return render_template('roster/crew_acknowledgements.html', acknowledgements=acks)


@app.route('/acknowledge_flight', methods=['POST'])
@login_required
def acknowledge_flight():
    ack_id = request.args.get("ack_id")
    if not ack_id:
        return jsonify({"success": False, "message": "Missing ack_id"}), 400

    ack = CrewAcknowledgement.query.get(ack_id)

    if not ack:
        return jsonify({"success": False, "message": "Acknowledgement not found."}), 404

    #if current_user.employee_id != ack.crew_member_id:
    #    return jsonify({"success": False, "message": "Unauthorized"}), 403

    if not ack.acknowledged:
        ack.acknowledged = True
        ack.acknowledged_at = datetime.utcnow()
        db.session.commit()

    return jsonify({"success": True, "message": "Flight acknowledged successfully."})


@app.route('/update_flights', methods=['POST'])
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

@app.route('/fetch_save_flights', methods=['POST'])
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


@app.route('/flight_operations')
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

def fetch_flights_from_envision(date_from, date_to, auth_token):
    """Fetch flights from Envision API."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    params = {"dateFrom": date_from, "dateTo": date_to}
    
    response = requests.get(f"{ENVISION_URL}/Flights", headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching flights: {response.text}")
        return []

def fetch_crew_from_envision(flight_id, auth_token):
    """Fetch crew assigned to a flight."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = requests.get(f"{ENVISION_URL}/Flights/{flight_id}/Crew", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching crew for flight {flight_id}: {response.text}")
        return []

def fetch_employee_name(employee_id, auth_token):
    """Fetch an employee's name using their ID."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = requests.get(f"{ENVISION_URL}/Employees/{employee_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching employee {employee_id}: {response.text}")
        return None

def fetch_all_employees(auth_token):
    """Fetch all employees and store in cache."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(f"{ENVISION_URL}/Employees", headers=headers)
    
    if response.status_code == 200:
        employees = response.json()
        for emp in employees:
            EMPLOYEE_CACHE[emp["id"]] = {"firstName": emp["firstName"], "surname": emp["surname"]}
        print(f"✅ Cached {len(employees)} employees")
    else:
        print(f"❌ Error fetching employees: {response.text}")

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


@app.route("/fetch_all_flight_data", methods=["POST"])
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
            employee_info = EMPLOYEE_CACHE.get(crew_data["employeeId"], None)
            if employee_info:
                crew_member = {
                    "employeeId": crew_data["employeeId"],
                    "firstName": safe_strip(employee_info["firstName"]),
                    "surname": safe_strip(employee_info["surname"]),
                    "position": crew_data["crewPositionId"]
                }
                crew_list.append(crew_member)

        # ✅ Normalize Crew JSON for comparison
        sorted_new_crew = normalize_crew_list(crew_list if crew_list else [])

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


@app.route('/publish_flights', methods=['POST'])
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
        
@app.route('/publish_flights_preview', methods=['POST'])
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

@app.route('/get_airport_codes')
@login_required
def get_airport_codes():
    ports = Port.query.with_entities(Port.iata_code).filter(
        Port.iata_code.isnot(None),
        Port.iata_code != ''
    ).all()
    
    # Flatten and uppercase
    codes = [p[0].upper() for p in ports if p[0]]
    
    return jsonify({"airports": sorted(codes)})


@app.route("/fetch_all_employees", methods=["POST"])
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

@app.route("/get_flights", methods=["GET"])
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

@app.route('/ports')
def list_ports():
    ports = Port.query.all()
    return render_template('Port_info/port_info.html', ports=ports)

@app.route('/get_port_details/<iata_code>', methods=['GET'])
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

@app.route('/add_port', methods=['POST'])
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


@app.route('/add_handler', methods=['POST'])
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


@app.route('/edit_handler', methods=['POST'])
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

@app.route('/get_handler_details/<int:handler_id>', methods=['GET'])
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




##################################
###Qualifications from Envision###
##################################


def fetch_and_update_qualifications():
    
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Employees/Qualifications', headers=headers)
    if response.status_code == 200:
        data = response.json()
        for employee in data:
            employee_no = employee['employeeNo']
            user = User.query.filter_by(crew_code=employee_no).first()
            if user:
                for qual in employee['qualifications']:
                    qualification_id = qual['qualificationId']
                    qualification = Qualification.query.filter_by(employee_id=user.id, qualification_id=qualification_id).first()
                    if not qualification:
                        qualification = Qualification(
                            employee_id=user.id,  # Store the user's ID
                            qualification_id=qualification_id,
                            qualification=qual['qualification'],
                            valid_from=datetime.strptime(qual['validFrom'], '%Y-%m-%dT%H:%M:%S'),
                            valid_to=datetime.strptime(qual['validTo'], '%Y-%m-%dT%H:%M:%S') if qual['validTo'] else None
                        )
                        db.session.add(qualification)
                    else:
                        qualification.qualification = qual['qualification']
                        qualification.valid_from = datetime.strptime(qual['validFrom'], '%Y-%m-%dT%H:%M:%S')
                        qualification.valid_to = datetime.strptime(qual['validTo'], '%Y-%m-%dT%H:%M:%S') if qual['validTo'] else None
        db.session.commit()
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None

#########################
### Email Config Page ###
#########################
from flask import render_template, redirect, url_for, flash, request
from app.forms import LineTrainingEmailConfigForm, CourseReminderEmailConfigForm
from app.models import EmailConfig, RoleType, User

@app.route('/email_config', methods=['GET', 'POST'])
@login_required
def email_config():
    config = EmailConfig.query.first()
    if not config:
        config = EmailConfig()
        db.session.add(config)
        db.session.commit()

    line_training_form = LineTrainingEmailConfigForm(obj=config)
    course_reminder_form = CourseReminderEmailConfigForm(obj=config)

    # Populate role choices
    roles = RoleType.query.all()
    role_choices = [(role.roleID, role.role_name) for role in roles]
    line_training_form.line_training_roles.choices = role_choices

    if request.method == 'POST':
        if request.form['submit'] == 'line_training' and line_training_form.validate_on_submit():
            config.line_training_thresholds = line_training_form.thresholds.data
            config.line_training_roles = ",".join(map(str, line_training_form.line_training_roles.data))
            db.session.commit()
            flash('Line Training configuration updated successfully.', 'success')
        elif request.form['submit'] == 'course_reminder' and course_reminder_form.validate_on_submit():
            config.course_reminder_days = course_reminder_form.course_reminder_days.data
            config.course_reminder_email = course_reminder_form.course_reminder_email.data
            db.session.commit()
            flash('Course Reminder configuration updated successfully.', 'success')
        return redirect(url_for('email_config'))

    # Fetch users in the training team role for display
    training_team_role = RoleType.query.filter_by(role_name="Training Team").first()
    training_team_users = training_team_role.users if training_team_role else []

    # Set the form data from the config object
    line_training_form.thresholds.data = config.line_training_thresholds
    line_training_form.line_training_roles.data = config.get_line_training_roles()
    course_reminder_form.course_reminder_days.data = config.course_reminder_days
    course_reminder_form.course_reminder_email.data = config.course_reminder_email

    return render_template('emails/email_config.html', 
                           line_training_form=line_training_form, 
                           course_reminder_form=course_reminder_form, 
                           training_team_users=training_team_users)
    

####################################
###Fetch User Roles from Envision###
####################################

def fetch_and_update_user_roles():
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Employees/Skills', headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"Fetched data: {data}")  # Log the fetched data
        
        # Clear existing employee skills
        EmployeeSkill.query.delete()
        db.session.commit()
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        
        for skill in data:
            print(f"Processing skill: {skill}")  # Log each skill item
            role_name = skill.get('skill')
            role_description = skill.get('skill')
            employee_id = skill.get('employeeId')
            skill_id = skill.get('skillId')
            valid = skill.get('valid')
            priority = skill.get('priority')
            
            if not role_name or not employee_id:
                print(f"Skipping skill due to missing role_name or employee_id: {skill}")
                continue
            
            # Store the employee skill
            employee_skill = EmployeeSkill(
                employee_id=employee_id,
                skill_id=skill_id,
                description=role_description,
                valid=valid,
                priority=priority
            )
            db.session.add(employee_skill)
            print(f"Stored employee skill: {employee_skill}")
            
            if role_name not in existing_roles:
                role = RoleType(role_name=role_name, role_description=role_description, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
                print(f"Created new role: {role}")
            else:
                role = existing_roles[role_name]
                role.role_description = role_description  # Update the description if it exists
                role.pulled_from_envision = True  # Update the flag if the role is from Envision
                print(f"Updated existing role: {role}")
            
            # Assign role to user
            user = User.query.filter_by(employee_id=employee_id).first()  # Match employee_id with User.employee_id
            if user and role not in user.roles:
                user.roles.append(role)
                print(f"Assigned role {role.role_name} to user {user.username}")
        
        db.session.commit()
        print("Data committed to the database.")
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None
    
@app.route('/fetch_and_update_roles', methods=['GET'])
@login_required
@admin_required
def fetch_and_update_roles_endpoint():
    try:
        data = fetch_and_update_user_roles()
        if data:
            return jsonify({"message": "Roles fetched and updated successfully.", "data": data}), 200
        else:
            return jsonify({"message": "Failed to fetch data from API."}), 500
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
@app.route('/assign_lms_role', methods=['POST'])
@login_required
@admin_required
def assign_lms_role():
    user_id = request.form.get('user_id')
    role_id = request.form.get('role_id')

    user = User.query.get(user_id)
    role = RoleType.query.get(role_id)

    if not user or not role:
        flash('Invalid user or role.', 'danger')
        return redirect(url_for('manage_users'))

    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        flash(f'Role "{role.role_name}" assigned to user "{user.username}".', 'success')
    else:
        flash(f'User "{user.username}" already has the role "{role.role_name}".', 'info')

    return redirect(url_for('manage_users'))

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        # Fetch employee skills for the user
        employee_skills = EmployeeSkill.query.filter_by(employee_id=user.crew_code).all()
        for skill in employee_skills:
            role = RoleType.query.filter_by(role_name=skill.description).first()
            if role and role not in user.roles:
                user.roles.append(role)
        db.session.commit()
    return user

##################################
###Roles from Envision###
##################################
def fetch_and_update_roles():
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Skills', headers=headers)
    if response.status_code == 200:
        data = response.json()
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        
        # Track roles found in the Envision API response
        roles_found_in_envision = set()
        
        for skill in data:
            role_name = skill['skill']
            role_description = skill['description']
            roles_found_in_envision.add(role_name)
            if role_name not in existing_roles:
                role = RoleType(role_name=role_name, role_description=role_description, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
            else:
                role = existing_roles[role_name]
                role.role_description = role_description  # Update the description if it exists
                role.pulled_from_envision = True  # Update the flag if the role is from Envision
        
        # Delete roles that are not found in the Envision API response and have pulled_from_envision set to True
        for role_name, role in existing_roles.items():
            if role_name not in roles_found_in_envision and role.pulled_from_envision:
                db.session.delete(role)
        
        db.session.commit()
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None
@app.route('/run_fetch_roles', methods=['GET'])
@login_required
@admin_required
def run_fetch_roles():
    try:
        data = fetch_and_update_roles()
        if data:
            flash("Roles fetched and updated successfully.", "success")
            return jsonify({"message": "Roles fetched and updated successfully."}), 200
        else:
            flash("Failed to fetch data from API.", "danger")
            return jsonify({"message": "Failed to fetch data from API."}), 500
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
@app.route('/email', methods=['GET'])
@login_required
def run_qualification_reminder_email():
    send_qualification_reminders()
    return "Email sent successfully."

#####################
###Reports Section###
#####################
@app.route('/user_qualifications_report', methods=['GET', 'POST'])
@login_required
@roles_required('Training Team')
def user_qualifications_report():
    users = User.query.all()
    selected_user_id = request.form.get('user_id')
    selected_user = User.query.get(selected_user_id) if selected_user_id else None
    qualifications = selected_user.qualifications if selected_user else []
    current_time = datetime.utcnow()

    return render_template('reports/user_qualifications_report.html', users=users, selected_user=selected_user, qualifications=qualifications, current_time=current_time)

from flask import request, render_template
from flask_login import login_required
from sqlalchemy import text, bindparam, func
# Ensure you import your models, for example:
# from app import db
# from app.models import CrewCheck, CheckItem, CheckItemGrade, CrewCheckMeta

@app.route('/Crew_Checks_Report', methods=['GET', 'POST'])
@login_required
@roles_required('Training Team')
def Crew_Checks_Report():
    # Fetch available check types
    check_types = db.session.query(CrewCheck.id, CrewCheck.name).all()

    selected_check_type_id = request.form.get('check_type_id')

    # Query including CrewCheck.name as form_name
    Crew_Checks_data = db.session.query(
        CheckItem.item_name,
        func.avg(CheckItemGrade.grade).label('average_grade'),
        CrewCheckMeta.aircraft_type,
        CrewCheckMeta.type_of_check,
        CrewCheck.name.label('form_name')  # ✅ Include form name
    ).join(CheckItemGrade, CheckItem.id == CheckItemGrade.check_item_id) \
     .join(CrewCheckMeta, CheckItemGrade.crew_check_meta_id == CrewCheckMeta.id) \
     .join(CrewCheck, CrewCheckMeta.crew_check_id == CrewCheck.id) \
     .filter(CrewCheckMeta.crew_check_id == selected_check_type_id) \
     .group_by(CheckItem.item_name, CrewCheckMeta.aircraft_type, CrewCheckMeta.type_of_check, CrewCheck.name) \
     .order_by(func.avg(CheckItemGrade.grade)) \
     .all()

    # Convert results to a list of dictionaries
    Crew_Checks_data_dict = [
        {
            'form_name': row.form_name or "Unnamed Form",
            'item_name': row.item_name,
            'average_grade': row.average_grade,
            'aircraft_type': row.aircraft_type,
            'type_of_check': row.type_of_check
        }
        for row in Crew_Checks_data
    ]

    return render_template('reports/average_check_report.html',
                           check_types=check_types,
                           selected_check_type_id=selected_check_type_id,
                           Crew_Checks_data=Crew_Checks_data_dict)


@app.route('/manage_navbar', methods=['GET', 'POST'])
@login_required
def manage_navbar():
    if request.method == 'POST':
        # Save permissions
        NavItemPermission.query.delete()
        db.session.commit()

        for nav_item in NavItem.query.all():
            selected_roles = request.form.getlist(f'permissions-{nav_item.id}')
            inherited_role_ids = set()

            for role_id in selected_roles:
                if int(role_id) == -1:
                    continue  # Skip admin
                role_id_int = int(role_id)
                db.session.add(NavItemPermission(nav_item_id=nav_item.id, role_id=role_id_int))
                inherited_role_ids.add(role_id_int)

            # Inherit roles to children only if requested
            for child in nav_item.children:
                if request.form.get(f'inherit_roles_{child.id}'):
                    for role_id in inherited_role_ids:
                        db.session.add(NavItemPermission(nav_item_id=child.id, role_id=role_id))

        # Save or update nav item
        if request.form.get('nav_action') == 'save_nav':
            item_id = request.form.get('id')
            label = request.form.get('label')
            endpoint = request.form.get('endpoint') or None
            parent_id = request.form.get('parent_id') or None
            if endpoint and not is_valid_endpoint(endpoint):
                flash(f"Invalid endpoint '{endpoint}' — it does not exist in the app routes.", "danger")
                return redirect(url_for('manage_navbar'))
            if item_id:
                item = NavItem.query.get(item_id)
                item.label = label
                item.endpoint = endpoint
                item.parent_id = parent_id
            else:
                item = NavItem(label=label, endpoint=endpoint, parent_id=parent_id)
                db.session.add(item)

            db.session.commit()
            flash("Nav item saved!", "success")
            return redirect(url_for('manage_navbar'))

        db.session.commit()
        flash("Permissions updated successfully.", "success")
        return redirect(url_for('manage_navbar'))

    # Load data for GET
    all_roles = RoleType.query.all() + [type('Role', (), {'roleID': -1, 'role_name': 'Admin'})()]

    # ✅ Sorted headers (top-level nav items)
    nav_items = NavItem.query.filter_by(parent_id=None).order_by(NavItem.order.asc()).all()

    enriched_nav_items = []
    for item in nav_items:
        allowed_role_ids = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=item.id).all()]

        # ✅ Sorted children
        sorted_children = sorted(item.children, key=lambda c: c.order or 0)
        children = []
        for child in sorted_children:
            children.append({
                "id": child.id,
                "label": child.label,
                "endpoint": child.endpoint,
                "allowed_role_ids": [
                    p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=child.id).all()
                ],
                "inherit_roles": child.inherit_roles  # ✅ THIS IS REQUIRED
            })

        enriched_nav_items.append({
            "id": item.id,
            "label": item.label,
            "endpoint": item.endpoint,
            "allowed_role_ids": allowed_role_ids,
            "children": children
        })

    return render_template(
        'admin/manage_navbar.html',
        nav_items=enriched_nav_items,
        all_roles=all_roles,
        all_headers=nav_items  # already sorted
    )

@app.route('/toggle_inherit_roles', methods=['POST'])
@login_required
def toggle_inherit_roles():
    data = request.get_json()
    child_id = int(data.get('child_id'))
    inherit = data.get('inherit', False)

    nav_item = NavItem.query.get_or_404(child_id)
    nav_item.inherit_roles = inherit
    db.session.commit()
    return jsonify(success=True)


###########################
###### Navbar Structure ###
###########################
@app.context_processor
def inject_nav_structure():
    def get_nav_for_user(user):
        if not user.is_authenticated:
            return []

        role_ids = [r.roleID for r in user.roles]
        valid_endpoints = current_app.view_functions.keys()

        # Admin sees all
        if user.is_admin:
            allowed_items = NavItem.query.all()
        else:
            allowed_items = db.session.query(NavItem).outerjoin(NavItemPermission).filter(
                (NavItemPermission.role_id.in_(role_ids)) | (NavItem.inherit_roles == True)
            ).all()

        headers = [item for item in allowed_items if item.parent_id is None]
        sorted_headers = sorted(headers, key=lambda h: h.order if h.order is not None else 9999)

        nav_structure = []
        for header in sorted_headers:
            header_roles = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=header.id)]
            show_header = user.is_admin or any(role_id in role_ids for role_id in header_roles)

            children = [c for c in allowed_items if c.parent_id == header.id]
            sorted_children = sorted(children, key=lambda c: c.order if c.order is not None else 9999)

            child_items = []
            for child in sorted_children:
                child_roles = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=child.id)]
                # ✅ Allow if user has direct access or child is set to inherit and header grants access
                allow_child = (
                    user.is_admin
                    or any(role_id in role_ids for role_id in child_roles)
                    or (child.inherit_roles and any(role_id in role_ids for role_id in header_roles))
                )
                if child.endpoint in valid_endpoints and allow_child:
                    child_items.append({
                        "label": child.label,
                        "endpoint": child.endpoint
                    })

            if show_header or child_items:
                nav_structure.append({
                    "label": header.label,
                    "endpoint": header.endpoint if header.endpoint in valid_endpoints else None,
                    "children": child_items
                })

        return nav_structure

    return dict(user_nav_items=get_nav_for_user(current_user))


def is_valid_endpoint(endpoint_name):
    if not endpoint_name:
        return True  # Allow empty endpoints (they're valid for headers without links)
    return endpoint_name.strip() in current_app.view_functions


@app.route('/delete_nav_item', methods=['POST'])
@login_required
def delete_nav_item():
    nav_item_id = request.form.get('nav_item_id')
    item = NavItem.query.get_or_404(nav_item_id)

    # Check for children
    if item.parent_id is None and item.children:
        flash("Cannot delete a header with children. Please delete child links first.", "warning")
        return redirect(url_for('manage_navbar'))

    # Delete permissions + the item
    NavItemPermission.query.filter_by(nav_item_id=item.id).delete()
    db.session.delete(item)
    db.session.commit()

    flash(f"'{item.label}' was deleted successfully.", "success")
    return redirect(url_for('manage_navbar'))

@app.route('/reorder_nav_items', methods=['POST'])
@login_required
def reorder_nav_items():
    data = request.get_json()

    # Update headers
    for item in data.get('headers', []):
        nav_item = NavItem.query.get(int(item['id']))
        nav_item.order = int(item['position'])

    # Update children
    for parent_id, children in data.get('children', {}).items():
        for child in children:
            nav_item = NavItem.query.get(int(child['id']))
            nav_item.order = int(child['position'])

    db.session.commit()
    return '', 204

@app.route('/manage_nav_items', methods=['GET', 'POST'])
@login_required
@roles_required('Admin')
def manage_nav_items():
    if request.method == 'POST':
        item_id = request.form.get('id')
        label = request.form.get('label')
        endpoint = request.form.get('endpoint') or None
        parent_id = request.form.get('parent_id') or None

        if item_id:  # Edit existing
            item = NavItem.query.get(item_id)
            item.label = label
            item.endpoint = endpoint
            item.parent_id = parent_id
        else:  # Create new
            item = NavItem(label=label, endpoint=endpoint, parent_id=parent_id)
            db.session.add(item)

        db.session.commit()
        flash("Nav item saved!", "success")
        return redirect(url_for('manage_nav_items'))

    headers = NavItem.query.filter_by(parent_id=None).all()
    items = NavItem.query.all()
    return render_template('admin/manage_nav_items.html', headers=headers, items=items)

@app.route('/update_nav_permission_ajax', methods=['POST'])
@login_required
def update_nav_permission_ajax():
    data = request.get_json()
    nav_item_id = int(data['nav_item_id'])
    role_id = int(data['role_id'])
    action = data['action']

    if action == 'add':
        existing = NavItemPermission.query.filter_by(nav_item_id=nav_item_id, role_id=role_id).first()
        if not existing:
            db.session.add(NavItemPermission(nav_item_id=nav_item_id, role_id=role_id))
    elif action == 'remove':
        NavItemPermission.query.filter_by(nav_item_id=nav_item_id, role_id=role_id).delete()

    db.session.commit()
    return '', 204

@app.route('/qualifications_report', methods=['GET', 'POST'])
@login_required
@roles_required('Training Team')
def qualifications_report():
    qualifications = Qualification.query.distinct(Qualification.qualification).all()
    selected_qualification = request.form.get('qualification')
    users_with_qualification = []

    if selected_qualification:
        users_with_qualification = User.query.join(Qualification).filter(Qualification.qualification == selected_qualification).all()

    current_time = datetime.utcnow()

    return render_template('reports/qualifications_report.html', qualifications=qualifications, selected_qualification=selected_qualification, users_with_qualification=users_with_qualification, current_time=current_time)

@app.route('/user_reports_dashboard', methods=['GET'])
@login_required
def user_reports_dashboard():
    # Define roles allowed to select multiple users.
    allowed_roles = ['Training Team', 'SF34 Examiner', 'ATR72Examiner']
    user_roles = [role.role_name for role in current_user.roles]
    show_dropdown = any(role in allowed_roles for role in user_roles)

    # If the user is not allowed to view others, force the user_ids to only their own ID.
    if not show_dropdown:
        user_ids = [current_user.id]
    else:
        # Get selected user IDs from the query string (as integers)
        user_ids = request.args.getlist('user_ids', type=int)
        # If none are provided, default to the current user's id.
        if not user_ids:
            user_ids = [current_user.id]

    print("User IDs:", user_ids)  # Debug

    # Retrieve all users for the dropdown if allowed; otherwise, just the current user.
    users = User.query.all() if show_dropdown else [current_user]
    
    # Group the check item grades by candidate then by crew check name.
    # Structure: { candidate_name: { crew_check_name: { check_item_name: { 'grades': [...], 'average_grade': ... } } } }
    check_item_grades = {}

    if user_ids:
        query = text("""
        SELECT 
            u.username AS candidate_name,
            ci.item_name AS check_item_name,
            cig.grade AS grade,
            ccm.template_version AS form_version,
            cc.name AS crew_check_name,
            cc.created_at AS crew_check_created_at
        FROM 
            user u
        JOIN 
            crew_check_meta ccm ON u.id = ccm.candidate_id
        JOIN 
            check_item_grade cig ON ccm.id = cig.crew_check_meta_id
        JOIN 
            check_items ci ON cig.check_item_id = ci.id
        JOIN 
            crew_checks cc ON ccm.crew_check_id = cc.id             
        WHERE 
            u.id IN :user_ids
        ORDER BY 
            u.username, ci.item_name;
        """).bindparams(bindparam("user_ids", expanding=True))
        
        results = db.session.execute(query, {"user_ids": user_ids}).mappings().all()
        print("Query results:", results)

        # Group results into nested dictionary structure.
        for row in results:
            candidate_name = row['candidate_name']
            crew_check_name = row['crew_check_name']
            check_item_name = row['check_item_name']
            grade = row['grade']
            
            if candidate_name not in check_item_grades:
                check_item_grades[candidate_name] = {}
            if crew_check_name not in check_item_grades[candidate_name]:
                check_item_grades[candidate_name][crew_check_name] = {}
            if check_item_name not in check_item_grades[candidate_name][crew_check_name]:
                check_item_grades[candidate_name][crew_check_name][check_item_name] = {'grades': []}
            
            check_item_grades[candidate_name][crew_check_name][check_item_name]['grades'].append(grade)

        # Calculate the average grade for each check item (ignoring non-numeric values)
        for candidate_name, crew_checks in check_item_grades.items():
            for crew_check, items in crew_checks.items():
                for check_item, data in items.items():
                    numeric_grades = []
                    for grade in data['grades']:
                        try:
                            numeric_grades.append(int(grade))
                        except ValueError:
                            continue
                    if numeric_grades:
                        average = sum(numeric_grades) / len(numeric_grades)
                        check_item_grades[candidate_name][crew_check][check_item]['average_grade'] = round(average, 2)
                    else:
                        check_item_grades[candidate_name][crew_check][check_item]['average_grade'] = "NA"
    
    return render_template('reports/user_reports_dashboard.html', 
                           users=users, 
                           check_item_grades=check_item_grades,
                           show_dropdown=show_dropdown)

@app.route('/reports_dashboard', methods=['GET'])
@login_required
def reports_dashboard():
    return render_template('reports/reports_dashboard.html')

@app.route('/envision_qualification_expiry_report', methods=['GET'])
@login_required
@roles_required('Training Team')
def envision_qualification_expiry_report():
    today = datetime.utcnow().date()
    current_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    # Fetch all users
    users = User.query.all()
    
    # Prepare data structure
    report_data = {
        'expired': [],
        '0-30': [],
        '30-60': [],
        '60-90': []
    }
    
    for user in users:
        qualifications = Qualification.query.filter_by(employee_id=user.id).all()
        for qualification in qualifications:
            if not qualification.valid_to:
                continue
            
            days_to_expiry = (qualification.valid_to.date() - today).days
            
            if days_to_expiry < 0:
                report_data['expired'].append((user, qualification))
            elif 0 <= days_to_expiry <= 30:
                report_data['0-30'].append((user, qualification))
            elif 31 <= days_to_expiry <= 60:
                report_data['30-60'].append((user, qualification))
            elif 61 <= days_to_expiry <= 90:
                report_data['60-90'].append((user, qualification))
    
    return render_template('reports/qualification_expiry_report.html', report_data=report_data, today=today, current_time=current_time)



##########################
###Check Form Templates###
##########################

@app.route('/manage_form_templates', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_form_templates():
    if request.method == 'POST':
        template_name = request.form.get('template_name')
        template_json = request.form.get('template_json')

        if template_name and template_json:
            new_template = FormTemplate(name=template_name, template_json=template_json)
            db.session.add(new_template)
            db.session.commit()
            flash('Form template created successfully.', 'success')
        else:
            flash('Template name and JSON content are required.', 'danger')

    templates = FormTemplate.query.all()
    return render_template('crew_checks/manage_form_templates.html', templates=templates)

@app.route('/edit_form_template/<int:template_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_form_template(template_id):
    template = FormTemplate.query.get_or_404(template_id)

    if request.method == 'POST':
        template.name = request.form.get('template_name')
        template.template_json = request.form.get('template_json')
        db.session.commit()
        flash('Form template updated successfully.', 'success')
        return redirect(url_for('manage_form_templates'))

    return render_template('edit_form_template.html', template=template)

@app.route('/delete_form_template/<int:template_id>', methods=['POST'])
@login_required
@admin_required
def delete_form_template(template_id):
    template = FormTemplate.query.get_or_404(template_id)
    db.session.delete(template)
    db.session.commit()
    flash('Form template deleted successfully.', 'success')
    return redirect(url_for('manage_form_templates'))



#####################
###Timesheets###
#####################

@app.route('/timesheet/weekly', methods=['GET', 'POST'])
@login_required
def submit_weekly_timesheet():
    payroll_periods = PayrollPeriod.query.filter_by(status="Open").order_by(PayrollPeriod.start_date.desc()).all()
    selected_payroll_period_id = request.args.get('payroll_period_id', type=int)
    selected_payroll_period = PayrollPeriod.query.get(selected_payroll_period_id) if selected_payroll_period_id else None

    week_days = []
    timesheets = {}
    timesheet_status = None

    if selected_payroll_period:
        week_days = [selected_payroll_period.start_date + timedelta(days=i) for i in range(14)]

        # Fetch the user's timesheet for the selected payroll period
        timesheet = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=selected_payroll_period.id).first()

        if timesheet:
            timesheet_status = timesheet.status

            timesheet_entries = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=selected_payroll_period.id).all()

            timesheets = {
                ts.date: {
                    "start_time": ts.start_time.strftime('%H:%M') if ts.start_time else '',
                    "finish_time": ts.finish_time.strftime('%H:%M') if ts.finish_time else '',
                    "actual_hours": ts.actual_hours if ts.actual_hours else 0.0,
                    "unpaid_break": ts.unpaid_break if ts.unpaid_break else 0.0,
                    "paid_hours": ts.paid_hours if ts.paid_hours else 0.0,
                    "lunch_break": ts.lunch_break,
                    "call_in": ts.call_in,
                    "runway_inspections": ts.runway_inspections,
                    "annual_leave": ts.annual_leave,
                    "sick_leave": ts.sick_leave,
                    "other_notes": ts.other_notes
                }
                for ts in timesheet_entries
            }

    if request.method == 'POST':
        payroll_period_id = request.form.get('payroll_period_id')
        payroll_period = PayrollPeriod.query.get(payroll_period_id)

        if not payroll_period or payroll_period.status == "Closed":
            flash("Invalid or closed payroll period selected!", "danger")
            return redirect(url_for('submit_weekly_timesheet'))

        week_days = [payroll_period.start_date + timedelta(days=i) for i in range(14)]

        timesheets_to_update = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=payroll_period.id).all()
        for ts in timesheets_to_update:
            ts.status = "Pending"

        for day in week_days:
            date_str = day.strftime("%Y-%m-%d")
            start_time = request.form.get(f"start_time_{date_str}")
            finish_time = request.form.get(f"finish_time_{date_str}")
            lunch_break = request.form.get(f"lunch_break_{date_str}") == "on"
            
            # Ensure call_in is correctly retrieved
            call_in = f"call_in_{date_str}" in request.form  # Check if checkbox was submitted

            # Fetch or create timesheet entry
            timesheet_entry = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=payroll_period.id, date=day).first()

            if not timesheet_entry:
                timesheet_entry = Timesheet(
                    user_id=current_user.id,
                    payroll_period_id=payroll_period.id,
                    date=day,
                    status="Pending"
                )
                db.session.add(timesheet_entry)

            if start_time and finish_time:
                start = datetime.strptime(start_time, "%H:%M")
                finish = datetime.strptime(finish_time, "%H:%M")
                total_hours = (finish - start).seconds / 3600
                unpaid_hours = 1.0 if lunch_break else 0
                paid_hours = total_hours - unpaid_hours

                timesheet_entry.start_time = start.time()
                timesheet_entry.finish_time = finish.time()
                timesheet_entry.lunch_break = lunch_break
                timesheet_entry.actual_hours = total_hours
                timesheet_entry.unpaid_break = unpaid_hours
                timesheet_entry.paid_hours = paid_hours
                timesheet_entry.call_in = call_in  # Ensure call_in is saved

        db.session.commit()
        flash("Timesheet updated successfully!", "success")
        return redirect(url_for('submit_weekly_timesheet', payroll_period_id=payroll_period.id))

    return render_template(
        'payroll/timesheet_weekly.html',
        payroll_periods=payroll_periods,
        selected_payroll_period=selected_payroll_period,
        week_days=week_days,
        timesheets=timesheets,
        timesheet_status=timesheet_status
    )




@app.route('/save_timesheet', methods=['POST'])
@login_required
def save_timesheet():
    try:
        data = request.json  # Get JSON data from the request
        
        # ✅ Validate required fields
        if 'date' not in data or not data['date']:
            return jsonify({"success": False, "error": "Missing required field: date"}), 400
        
        if 'payroll_period_id' not in data or not data['payroll_period_id']:
            return jsonify({"success": False, "error": "Payroll period is required"}), 400

        # ✅ Convert date and retrieve the timesheet
        date = datetime.strptime(data['date'], "%Y-%m-%d").date()
        payroll_period_id = int(data['payroll_period_id'])  # Ensure it's an integer

        timesheet = Timesheet.query.filter_by(user_id=current_user.id, date=date).first()

        if not timesheet:
            # ✅ Create a new timesheet entry if it does not exist
            timesheet = Timesheet(
                user_id=current_user.id,
                date=date,
                payroll_period_id=payroll_period_id  # ✅ Ensure payroll period is assigned
            )
            db.session.add(timesheet)

        # ✅ Ensure safe parsing of time fields
        timesheet.start_time = datetime.strptime(data['start_time'], "%H:%M").time() if data.get('start_time') else None
        timesheet.finish_time = datetime.strptime(data['finish_time'], "%H:%M").time() if data.get('finish_time') else None
        timesheet.lunch_break = data.get('lunch_break') == "on"
        timesheet.call_in = data.get('call_in') == "on"
        timesheet.runway_inspections = int(data['runway']) if data.get('runway') and data['runway'].isdigit() else 0
        timesheet.annual_leave = data.get('annual_leave') == "on"
        timesheet.sick_leave = data.get('sick_leave') == "on"
        timesheet.other_notes = data.get('other', "")

        db.session.commit()
        return jsonify({"success": True})

    except Exception as e:
        print(f"Error saving timesheet: {e}")  # ✅ Log error for debugging
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/timesheets', methods=['GET'])
@login_required
def view_timesheets():
    timesheets = Timesheet.query.filter_by(user_id=current_user.id).order_by(Timesheet.date.desc()).all()
    return render_template('payroll/timesheet_list.html', timesheets=timesheets)

@app.route('/timesheet/manage', methods=['GET'])
@login_required
@admin_required
def manage_timesheets():
    timesheets = Timesheet.query.filter_by(status='Pending').all()
    return render_template('payroll/timesheet_manage.html', timesheets=timesheets)

@app.route('/timesheet/update/<int:timesheet_id>/<string:action>', methods=['POST'])
@login_required
@admin_required
def update_timesheet_status(timesheet_id, action):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    if action in ['Approved', 'Rejected']:
        timesheet.status = action
        db.session.commit()
        flash(f"Timesheet {action} successfully!", "success")
    return redirect(url_for('manage_timesheets'))

@app.route('/payroll_periods', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_payroll_periods():
    # Fetch the last payroll period
    last_payroll_period = PayrollPeriod.query.order_by(PayrollPeriod.end_date.desc()).first()

    # Suggest new period based on the last period
    if last_payroll_period:
        suggested_start_date = last_payroll_period.end_date + timedelta(days=1)  # Next day
        suggested_end_date = suggested_start_date + timedelta(days=13)  # 14-day (2-week) period
    else:
        # Default start if no previous payroll exists
        suggested_start_date = datetime.today()
        suggested_end_date = suggested_start_date + timedelta(days=13)

    if request.method == 'POST':
        try:
            start_date = datetime.strptime(request.form.get('start_date'), "%Y-%m-%d").date()
            end_date = datetime.strptime(request.form.get('end_date'), "%Y-%m-%d").date()

            if PayrollPeriod.query.filter_by(start_date=start_date).first():
                flash("Payroll period already exists!", "warning")
            else:
                payroll_period = PayrollPeriod(start_date=start_date, end_date=end_date)
                db.session.add(payroll_period)
                db.session.commit()
                flash("Payroll period added successfully!", "success")

        except ValueError:
            flash("Invalid date format! Please use YYYY-MM-DD.", "danger")

        return redirect(url_for('manage_payroll_periods'))

    payroll_periods = PayrollPeriod.query.order_by(PayrollPeriod.start_date.desc()).all()

    return render_template(
        'payroll/payroll_periods.html', 
        payroll_periods=payroll_periods,
        suggested_start_date=suggested_start_date.strftime("%Y-%m-%d"),  
        suggested_end_date=suggested_end_date.strftime("%Y-%m-%d")  
    )

@app.route('/payroll_periods/toggle_status/<int:payroll_id>', methods=['POST'])
@login_required
@admin_required
def toggle_payroll_status(payroll_id):
    payroll_period = PayrollPeriod.query.get_or_404(payroll_id)

    if payroll_period.status == "Open":
        payroll_period.status = "Closed"
    else:
        payroll_period.status = "Open"

    db.session.commit()
    flash(f"Payroll period {payroll_period.start_date.strftime('%A %d %B, %Y')} is now {payroll_period.status}.", "success")
    
    return redirect(url_for('manage_payroll_periods'))


@app.route('/payroll_periods/delete/<int:payroll_id>', methods=['POST'])
@login_required
@admin_required
def delete_payroll_period(payroll_id):
    payroll_period = PayrollPeriod.query.get_or_404(payroll_id)
    
    # Prevent deletion if timesheets exist for this payroll period
    if payroll_period.timesheets:
        flash("Cannot delete payroll period. It has associated timesheets!", "danger")
        return redirect(url_for('manage_payroll_periods'))
    
    db.session.delete(payroll_period)
    db.session.commit()
    flash("Payroll period deleted successfully!", "success")
    return redirect(url_for('manage_payroll_periods'))

@app.route('/payroll_dashboard', methods=['GET'])
@login_required
def payroll_dashboard():
    # ✅ Only allow access to payroll dashboard for users with payroll access
    if not current_user.job_title or not current_user.job_title.has_payroll_access:
        flash("You do not have permission to access the payroll dashboard.", "danger")

    payroll_periods = PayrollPeriod.query.order_by(PayrollPeriod.start_date.desc()).all()
    selected_payroll_period_id = request.args.get('payroll_period_id', type=int)
    selected_tab = request.args.get('status', 'Pending')  # Default tab is 'Pending'

    employees = {
        "Approved": [],
        "Rejected": [],
        "Pending": [],
        "Not Submitted": []
    }

    if selected_payroll_period_id:
        if current_user.is_admin:
            # ✅ Admins see all employees with timesheet access
            employee_query = (
                db.session.query(User)
                .join(JobTitle, User.job_title_id == JobTitle.id)
                .filter(JobTitle.has_timesheet_access == True)
                .all()
            )
        
        elif current_user.job_title:
            # ✅ Managers only see staff at their location
            subordinate_roles = current_user.job_title.get_all_subordinate_roles()
            employee_query = (
                db.session.query(User)
                .join(JobTitle, User.job_title_id == JobTitle.id)
                .filter(User.location_id == current_user.location_id)  # ✅ Only show staff at the same location
                .filter(User.job_title_id.in_(subordinate_roles), JobTitle.has_timesheet_access == True)
                .all()
            )
        else:
            employee_query = []

        for employee in employee_query:
            timesheet = Timesheet.query.filter_by(user_id=employee.id, payroll_period_id=selected_payroll_period_id).first()
            if timesheet:
                employees[timesheet.status].append(employee)
            else:
                employees["Not Submitted"].append(employee)

    return render_template(
        'payroll/payroll_dashboard.html',
        payroll_periods=payroll_periods,
        employees=employees,
        selected_payroll_period_id=selected_payroll_period_id,
        selected_tab=selected_tab
    )

@app.route('/payroll_reports', methods=['GET'])
@login_required
def payroll_reports():
    """Generate payroll reports with filtering for table and graph separately."""
    
    payroll_periods = PayrollPeriod.query.order_by(PayrollPeriod.start_date.desc()).all()
    locations = Location.query.all()

    # Table Filters
    selected_period_id = request.args.get('payroll_period_id', type=int)
    selected_quarter = request.args.get('quarter', type=str)
    selected_location = request.args.get('location_id', type=int)

    # Graph Filters
    selected_year = request.args.get('graph_year', type=int, default=datetime.utcnow().year)

    # ✅ Query for Employee Hours Per Payroll Period
    query_filter = []
    if selected_period_id:
        query_filter.append(Timesheet.payroll_period_id == selected_period_id)
    
    if selected_quarter:
        quarter_months = {
            "Q1": [1, 2, 3],
            "Q2": [4, 5, 6],
            "Q3": [7, 8, 9],
            "Q4": [10, 11, 12]
        }
        query_filter.append(extract('month', PayrollPeriod.start_date).in_(quarter_months[selected_quarter]))

    if selected_location:
        query_filter.append(User.location_id == selected_location)

    # ✅ Fetch Employee Hours Data (Only Approved Payrolls)
    employee_hours = (
        db.session.query(
            User.username.label("employee"),
            Location.name.label("location"),
            PayrollPeriod.start_date.label("period_start"),
            PayrollPeriod.end_date.label("period_end"),
            func.sum(Timesheet.paid_hours).label("total_hours")
        )
        .select_from(Timesheet)
        .join(User, Timesheet.user_id == User.id)
        .join(Location, User.location_id == Location.id)
        .join(PayrollPeriod, Timesheet.payroll_period_id == PayrollPeriod.id)
        .filter(Timesheet.status == "Approved")  # ✅ Only Approved Payroll Data
        .filter(*query_filter)  # ✅ Apply existing filters
        .group_by("employee", "location", "period_start", "period_end")
        .order_by("location", "employee", "period_start")
        .all()
    )


    # ✅ Format Data for Table
    employee_data = {}
    payroll_period_labels = sorted({(period_start, period_end) for _, _, period_start, period_end, _ in employee_hours})

    for employee, location, period_start, period_end, total_hours in employee_hours:
        key = (employee, location)
        if key not in employee_data:
            employee_data[key] = {period: 0.0 for period in payroll_period_labels}  # ✅ Default to 0
        employee_data[key][(period_start, period_end)] = round(total_hours or 0.0, 2)  # ✅ Convert None to 0.0

    # ✅ Fetch Graph Data (Separate Year Filter)
    graph_data = (
        db.session.query(
            extract('month', Timesheet.date).label("month"),
            Location.name.label("location"),
            func.sum(Timesheet.paid_hours).label("total_hours")
        )
        .select_from(Timesheet)
        .join(User, Timesheet.user_id == User.id)
        .join(Location, User.location_id == Location.id)
        .filter(extract('year', Timesheet.date) == selected_year)
        .group_by("month", "location")
        .order_by("month", "location")
        .all()
    )

    # ✅ Format Graph Data
    formatted_graph_data = {}
    for month, location, total_hours in graph_data:
        label = f"{int(month):02d}"
        if label not in formatted_graph_data:
            formatted_graph_data[label] = {}
        formatted_graph_data[label][location] = round(total_hours or 0.0, 2)  # ✅ Convert None to 0.0

    return render_template(
        "reports/payroll_reports.html",
        payroll_periods=payroll_periods,
        locations=locations,
        selected_period_id=selected_period_id,
        selected_quarter=selected_quarter,
        selected_location=selected_location,
        selected_year=selected_year,
        employee_data=employee_data or {},  # ✅ Ensures it always sends a dictionary
        payroll_period_labels=payroll_period_labels or [],  # ✅ Ensures it always sends a list
        graph_data=json.dumps(formatted_graph_data, default=str)  # ✅ Ensure JSON serialization
    )



@app.route('/payroll/view/<int:payroll_period_id>/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def view_employee_payroll(payroll_period_id, user_id):
    payroll_period = PayrollPeriod.query.get_or_404(payroll_period_id)
    user = User.query.get_or_404(user_id)

    timesheets = Timesheet.query.filter_by(user_id=user_id, payroll_period_id=payroll_period_id).all()

    if request.method == 'POST':
        action = request.form.get("action")
        reject_reason = request.form.get("reject_reason", "").strip()

        if action == "approve":
            for timesheet in timesheets:
                timesheet.status = "Approved"
            message_body = f"Your timesheet for {payroll_period.start_date.strftime('%A %d %B %Y')} - {payroll_period.end_date.strftime('%A %d %B %Y')} has been APPROVED."

        elif action == "reject":
            if not reject_reason:
                flash("Please provide a reason for rejection.", "danger")
                return redirect(url_for('view_employee_payroll', payroll_period_id=payroll_period_id, user_id=user_id))

            for timesheet in timesheets:
                timesheet.status = "Rejected"

            message_body = f"Your timesheet for {payroll_period.start_date.strftime('%A %d %B %Y')} - {payroll_period.end_date.strftime('%A %d %B %Y')} has been REJECTED.\n\nReason: {reject_reason}"

        db.session.commit()

        # ✅ Send email notification
        send_timesheet_response(user.email, current_app._get_current_object(), "Timesheet Status Update", message_body)

        flash(f"Timesheets for {user.username} have been {action}d.", "success")
        return redirect(url_for('payroll_dashboard', payroll_period_id=payroll_period_id))

    return render_template(
        'payroll/employee_payroll.html',
        payroll_period=payroll_period,
        user=user,
        timesheets=timesheets
    )

@app.route('/my_timesheets', methods=['GET'])
@login_required
def my_timesheets():
    """Show all payroll periods for which the user has submitted timesheets."""
    
    # ✅ Fetch unique payroll periods the user has submitted timesheets for
    payroll_periods = (
        db.session.query(PayrollPeriod)
        .join(Timesheet, PayrollPeriod.id == Timesheet.payroll_period_id)
        .filter(Timesheet.user_id == current_user.id)
        .distinct()
        .order_by(PayrollPeriod.start_date.desc())
        .all()
    )

    # ✅ Get the latest payroll status for each period
    payroll_statuses = {}
    for period in payroll_periods:
        latest_status = (
            Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=period.id)
            .order_by(Timesheet.date.desc())
            .first()
        )
        payroll_statuses[period.id] = latest_status.status if latest_status else "Not Submitted"

    return render_template(
        'payroll/my_timesheets.html',
        payroll_periods=payroll_periods,
        payroll_statuses=payroll_statuses
    )

@app.route('/my_timesheet/<int:payroll_period_id>', methods=['GET'])
@login_required
def view_my_timesheet(payroll_period_id):
    """Allow users to view their payroll details in read-only mode."""
    
    payroll_period = PayrollPeriod.query.get_or_404(payroll_period_id)

    # ✅ Fetch the user's timesheets for the selected payroll period
    timesheets = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=payroll_period_id).all()

    return render_template(
        'payroll/my_timesheet_detail.html',
        payroll_period=payroll_period,
        timesheets=timesheets
    )



@app.route('/timesheet/approve/<int:timesheet_id>', methods=['POST'])
@login_required
@admin_required
def approve_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    timesheet.status = 'Approved'
    db.session.commit()
    flash(f"Timesheet for {timesheet.user.username} approved!", "success")
    return redirect(url_for('payroll_dashboard'))

@app.route('/timesheet/reject/<int:timesheet_id>', methods=['POST'])
@login_required
@admin_required
def reject_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    timesheet.status = 'Rejected'
    db.session.commit()
    flash(f"Timesheet for {timesheet.user.username} rejected!", "danger")
    return redirect(url_for('payroll_dashboard'))

@app.route('/payroll/export', methods=['GET'])
@login_required
@admin_required
def export_payroll():
    selected_payroll_period_id = request.args.get('payroll_period_id', type=int)
    
    # Get filtered timesheets
    if selected_payroll_period_id:
        timesheets = Timesheet.query.filter_by(payroll_period_id=selected_payroll_period_id).all()
    else:
        timesheets = Timesheet.query.all()

    # Prepare CSV
    output = []
    output.append(["Employee", "Date", "Start Time", "Finish Time", "Paid Hours", "Call In", "Annual Leave", "Sick Leave", "Other"])

    for timesheet in timesheets:
        output.append([
            timesheet.user.username,
            timesheet.date,
            timesheet.start_time or "N/A",
            timesheet.finish_time or "N/A",
            timesheet.paid_hours,
            "Yes" if timesheet.call_in else "No",
            "Yes" if timesheet.annual_leave else "No",
            "Yes" if timesheet.sick_leave else "No",
            timesheet.other_notes or "None"
        ])

    # Generate response
    response = Response('\n'.join([','.join(map(str, row)) for row in output]), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=payroll_export.csv"
    return response

@app.route('/timesheet/resubmit/<int:payroll_period_id>', methods=['POST'])
@login_required
def resubmit_timesheet(payroll_period_id):
    # Fetch the user's timesheet for the given payroll period
    timesheet = Timesheet.query.filter_by(user_id=current_user.id, payroll_period_id=payroll_period_id).first()

    if timesheet:
        # Update the status to 'Pending'
        timesheet.status = 'Pending'
        db.session.commit()
        flash('Timesheet status has been changed to Pending.', 'success')
    else:
        flash('Timesheet not found.', 'danger')

    return redirect(url_for('submit_weekly_timesheet', payroll_period_id=payroll_period_id))

###############
###Job Title###
###############

@app.route('/manage_job_titles', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_job_titles():
    job_titles = JobTitle.query.all()
    users = User.query.all()
    locations = Location.query.all()  # ✅ Fetch available locations

    if request.method == 'POST':
        title = request.form.get('title').strip()
        manager_id = request.form.get('manager_id')
        reports_to_id = request.form.get('reports_to_id')
        location_id = request.form.get('location_id')  # ✅ Fetch selected location

        has_timesheet_access = 'has_timesheet_access' in request.form
        has_payroll_access = 'has_payroll_access' in request.form

        if not title:
            flash("Job title cannot be empty.", "danger")
        elif JobTitle.query.filter_by(title=title, location_id=location_id).first():
            flash("Job title already exists at this location.", "warning")
        else:
            new_job = JobTitle(
                title=title,
                manager_id=manager_id if manager_id else None,
                reports_to=reports_to_id if reports_to_id else None,
                location_id=location_id,  # ✅ Assign location
                has_timesheet_access=has_timesheet_access,
                has_payroll_access=has_payroll_access
            )
            db.session.add(new_job)
            db.session.commit()
            flash(f"Job title '{title}' added successfully.", "success")

        return redirect(url_for('admin/manage_job_titles'))

    # ✅ Generate `job_users_map` to track users assigned to each job title
    job_users_map = {
        job.id: [
            {"id": user.id, "username": user.username, "email": user.email}
            for user in User.query.filter_by(job_title_id=job.id).all()
        ]
        for job in job_titles
    }

    return render_template(
        'manage_job_titles.html',
        job_titles=job_titles,
        users=users,
        locations=locations,  # ✅ Pass locations to template
        job_users_map=job_users_map  # ✅ Pass job_users_map to template
    )


@app.route('/edit_job_title', methods=['POST'])
@login_required
@admin_required
def edit_job_title():
    job_id = request.form.get('job_id')
    job = JobTitle.query.get_or_404(job_id)

    job.title = request.form.get('title').strip()
    job.manager_id = request.form.get('manager_id') if request.form.get('manager_id') else None
    job.reports_to = request.form.get('reports_to_id') if request.form.get('reports_to_id') else None

    # ✅ Update timesheet and payroll access
    job.has_timesheet_access = 'has_timesheet_access' in request.form
    job.has_payroll_access = 'has_payroll_access' in request.form

    db.session.commit()
    flash(f"Job title '{job.title}' updated successfully.", "success")

    return redirect(url_for('manage_job_titles'))


@app.route('/delete_job_title/<int:job_id>', methods=['POST'])
@login_required
@admin_required
def delete_job_title(job_id):
    job = JobTitle.query.get_or_404(job_id)
    affected_users = User.query.filter_by(job_title_id=job.id).all()

    # ✅ If no users are assigned, delete the job title immediately
    if not affected_users:
        db.session.delete(job)
        db.session.commit()
        flash(f"Job title '{job.title}' deleted successfully.", "success")
        return redirect(url_for('manage_job_titles'))

    # ✅ If users exist but admin confirms deletion, reset their job title and delete
    if request.form.get('confirm_delete'):
        for user in affected_users:
            user.job_title_id = None  # Unassign job title

        db.session.delete(job)
        db.session.commit()
        flash(f"Job title '{job.title}' and all assigned users' job titles have been removed.", "success")
    else:
        flash("Deletion canceled.", "info")

    return redirect(url_for('manage_job_titles'))

#####################
###Scheduler Tasks###
#####################

@app.route('/send_email', methods=['GET'])
@login_required
def send_email():
    try:
        send_course_reminders()
        return jsonify({"message": "Course reminders sent successfully."}), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/fetch_update_roles', methods=['GET'])
@login_required
def fetch_update_roles():
    try:
        fetch_and_update_qualifications()
        fetch_and_update_roles()
        return jsonify({"message": "Qualifications and roles updated successfully."}), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

# Schedule the function to run daily at midnight
@scheduler.task('cron', id='send_reminders', hour=1, minute=5)
def scheduled_tasks():
    print("[INFO] Running scheduled send_course_reminders()...")
    send_course_reminders()
    fetch_and_update_qualifications()
    fetch_and_update_roles()

#######################
###Company Structure###
#######################
@app.route('/company_structure')
@login_required
def company_structure():
    """Generate a hierarchical company structure for display."""
    job_titles = JobTitle.query.all()

    # Create a mapping of job titles to store their hierarchy
    job_title_map = {job.id: {
        "id": job.id, 
        "title": job.title, 
        "employees": [], 
        "children": []
    } for job in job_titles}

    # Associate employees with job titles
    employees = User.query.all()
    for employee in employees:
        if employee.job_title_id and employee.job_title_id in job_title_map:
            job_title_map[employee.job_title_id]["employees"].append({
                "id": employee.id,
                "username": employee.username,
                "email": employee.email
            })

    # Build hierarchical structure
    root_jobs = []
    for job in job_titles:
        if job.parent_job:  # If job has a supervisor
            job_title_map[job.parent_job.id]["children"].append(job_title_map[job.id])
        else:
            root_jobs.append(job_title_map[job.id])  # Top-level job titles (e.g., CEO)

    return render_template("company_structure.html", root_jobs=root_jobs, render_tree=render_tree)

# ✅ Recursive function to render the hierarchy
def render_tree(job):
    html = f'<div class="node-container">'
    html += f'<div class="node"><strong>{job["title"]}</strong>'

    if job["employees"]:
        html += '<div class="employees">'
        for employee in job["employees"]:
            html += f'<div class="employee">👤 {employee["username"]} ({employee["email"]})</div>'
        html += '</div>'

    html += '</div>'  # Closing the node div

    if job["children"]:
        html += '<div class="connector"></div>'  # Line connecting parent to children
        html += '<div class="children">'
        for child in job["children"]:
            html += render_tree(child)  # Recursive Call
        html += '</div>'

    html += '</div>'  # Closing node-container div
    return html


##############
###Locations###
##############
@app.route('/manage_locations', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_locations():
    locations = Location.query.order_by(Location.name).all()

    if request.method == 'POST':
        location_name = request.form.get('location_name').strip()

        if not location_name:
            flash("Location name cannot be empty.", "danger")
        elif Location.query.filter_by(name=location_name).first():
            flash("Location already exists.", "warning")
        else:
            new_location = Location(name=location_name)
            db.session.add(new_location)
            db.session.commit()
            flash(f"Location '{location_name}' added successfully.", "success")

        return redirect(url_for('manage_locations'))

    return render_template('admin/manage_locations.html', locations=locations)
@app.route('/delete_location/<int:location_id>', methods=['POST'])
@login_required
@admin_required
def delete_location(location_id):
    location = Location.query.get_or_404(location_id)

    # Prevent deletion if users or job titles are assigned to this location
    if User.query.filter_by(location_id=location.id).first() or JobTitle.query.filter_by(location_id=location.id).first():
        flash("Cannot delete location with assigned users or job titles. Reassign them first.", "danger")
        return redirect(url_for('manage_locations'))

    db.session.delete(location)
    db.session.commit()
    flash("Location deleted successfully.", "success")
    
    return redirect(url_for('manage_locations'))

# Initialize the app and run
if __name__ == "__main__":
    #scheduler.init_app(app) Scheduler to send automatic emails for qualifications
    #scheduler.start()  Scheduler to send automatic emails for qualifications
    app.run(debug=True)
    