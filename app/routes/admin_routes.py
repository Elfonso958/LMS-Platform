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

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session
from flask_login import login_user, logout_user, login_required, current_user

from flask_bcrypt import Bcrypt
from app import create_app, db, mail
from app.models import Course, RoleType, UserSlideProgress, UserExamAttempt, Questions, Answers, UserAnswer, course_role, User, db, PayrollInformation, CrewCheck, CrewCheckMeta, CheckItem, user_role,CheckItemGrade, LineTrainingForm, Location, Port, HandlerFlightMap, GroundHandler, CrewAcknowledgement, DocumentType
from app.models import Task,TaskCompletion,Topic, LineTrainingItem,UserLineTrainingForm, Sector, RosterChange, Flight, FormTemplate,RoutePermission,Qualification,EmployeeSkill, EmailConfig, JobTitle, Timesheet, Location, PayrollPeriod,PayrollInformation, NavItem, NavItemPermission, DocumentReviewRequest # Import your models and database session
from app.utils import extract_slides_to_png, calculate_exam_score, get_slide_count, admin_required, natural_sort_key, roles_required, generate_certificate, save_uploaded_document
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.sql.expression import extract  # ✅ Import `extract`
from pptx import Presentation
from PIL import Image
from flask import send_file, jsonify
import shutil, logging
from datetime import datetime, timedelta
from app.forms import LoginForm, LineTrainingFormEditForm, LineTrainingEmailConfigForm, CourseReminderEmailConfigForm, TimesheetForm, DocumentTypeForm, CREW_CHECK_FIELDS, MedicalExpiryEmailConfigForm, DirectDocumentUploadForm  # Import your LoginForm
from flask_mail import Message
from app.email_utils import send_email_to_training_team, Send_Release_To_Supervisor_Email, send_course_reminders, send_qualification_reminders, send_qualification_expiry_email, send_timesheet_response, send_email
from sqlalchemy.orm import joinedload, aliased
from flask_apscheduler import APScheduler
from itsdangerous import URLSafeTimedSerializer
from flask.sessions import SecureCookieSessionInterface
from app.roster_utils import normalize_duty, duty_dict, get_current_duty, fetch_and_save_flights, check_for_flight_changes, check_for_daily_changes
from fpdf import FPDF
from sqlalchemy import func
from sqlalchemy import text, bindparam
from cachetools import TTLCache
from collections import defaultdict
from services.envision_api import fetch_and_assign_user_roles, fetch_all_employees, fetch_and_update_user_roles, fetch_and_update_roles  # Import the function to fetch and assign user roles from Envision

admin_bp = Blueprint("admin", __name__)
ENVISION_URL = "https://envision.airchathams.co.nz:8790/v1"

@admin_bp.route('/switch_user', methods=['GET', 'POST'])
def switch_user():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)
        if user:
            login_user(user)
            return redirect(url_for('user.user_dashboard'))  # or any page you want
    users = User.query.all()
    return render_template('admin/switch_user.html', users=users)


################################
###Link all users to Envision###
################################

@admin_bp.route('/bulk_link_envision', methods=['POST'])
@login_required
def bulk_link_envision():
    """Fetch all Envision Employees, bulk-link User.employee_id, then assign roles."""
    auth_token = session.get('auth_token')
    if not auth_token:
        return jsonify(success=False, message="Missing Envision auth token"), 400

    # 1) pull down all employees
    headers = {'Authorization': f'Bearer {auth_token}'}
    resp = requests.get(f'{ENVISION_URL}/Employees', headers=headers, timeout=10)
    if not resp.ok:
        current_app.logger.error("Failed fetch Envision Employees: %s %s",
                                resp.status_code, resp.text)
        return jsonify(success=False,
                       message="Failed to fetch Employees from Envision"), 502

    employees = resp.json()
    emp_map = {e['employeeNo']: e['id'] for e in employees if 'employeeNo' in e and 'id' in e}

    report = []
    # 2) iterate all Users who have a crew_code
    for u in User.query.filter(User.crew_code.isnot(None)).all():
        envision_id = emp_map.get(u.crew_code)
        if not envision_id:
            # no match in Envision
            report.append({
                'username': u.username,
                'linked': False,
                'message': 'No matching Envision employeeNo'
            })
            continue

        changed = False
        if u.employee_id != envision_id:
            u.employee_id = envision_id
            changed = True

        # 3) fetch & assign roles based on skills
        #    fetch_and_assign_user_roles commits internally
        data = fetch_and_assign_user_roles(u) or []

        # pull out the current role names from the DB
        roles = [ r.role_name for r in u.roles ]

        report.append({
            'username': u.username,
            'linked': True,
            'employee_id': envision_id,
            'employee_id_changed': changed,
            'roles': roles
        })

    # 4) commit any employee_id changes
    db.session.commit()
    current_app.logger.info("Bulk linked %d users", len([r for r in report if r['linked']]))

    return jsonify(
        success=True,
        report=report
    ), 200

###########################################
#### Admin Routes for Navbar Management####
###########################################
@admin_bp.route('/manage_navbar', methods=['GET', 'POST'])
@login_required
def manage_navbar():
    available_endpoints = sorted(current_app.view_functions.keys())

    if request.method == 'POST':
        NavItemPermission.query.delete()
        db.session.commit()

        for nav_item in NavItem.query.all():
            # Roles
            selected_roles = request.form.getlist(f'permissions-{nav_item.id}-role')
            for role_id in selected_roles:
                if int(role_id) != -1:
                    db.session.add(NavItemPermission(nav_item_id=nav_item.id, role_id=int(role_id)))

            # Job Titles
            selected_jobs = request.form.getlist(f'permissions-{nav_item.id}-job')
            for job_id in selected_jobs:
                db.session.add(NavItemPermission(nav_item_id=nav_item.id, job_title_id=int(job_id)))

            # (Optional: Skills)
            # selected_skills = request.form.getlist(f'permissions-{nav_item.id}-skill')
            # for skill_id in selected_skills:
            #     db.session.add(NavItemPermission(nav_item_id=nav_item.id, skill_id=int(skill_id)))

            # Inherit logic
            for child in nav_item.children:
                if request.form.get(f'inherit_roles_{child.id}'):
                    # Inherit roles
                    for role_id in selected_roles:
                        if int(role_id) != -1:
                            db.session.add(NavItemPermission(nav_item_id=child.id, role_id=int(role_id)))
                    # Inherit job titles
                    for job_id in selected_jobs:
                        db.session.add(NavItemPermission(nav_item_id=child.id, job_title_id=int(job_id)))
                    # Inherit skills — future support
                    # for skill_id in selected_skills:
                    #     db.session.add(NavItemPermission(nav_item_id=child.id, skill_id=int(skill_id)))

        # Save or update nav item
        if request.form.get('nav_action') == 'save_nav':
            item_id = request.form.get('id')
            label = request.form.get('label')
            endpoint = request.form.get('endpoint') or None
            parent_id = request.form.get('parent_id') or None
            if endpoint and not is_valid_endpoint(endpoint):
                flash(f"Invalid endpoint '{endpoint}' — it does not exist in the app routes.", "danger")
                return redirect(url_for('admin.manage_navbar'))

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
            return redirect(url_for('admin.manage_navbar'))

        db.session.commit()
        flash("Permissions updated successfully.", "success")
        return redirect(url_for('admin.manage_navbar'))

    # GET
    all_roles = RoleType.query.all() + [type('Role', (), {'roleID': -1, 'role_name': 'Admin'})()]
    all_job_titles = JobTitle.query.all()

    nav_items = NavItem.query.filter_by(parent_id=None).order_by(NavItem.order.asc()).all()
    enriched_nav_items = []

    for item in nav_items:
        allowed_role_ids = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=item.id).filter(NavItemPermission.role_id.isnot(None)).all()]
        allowed_job_ids = [p.job_title_id for p in NavItemPermission.query.filter_by(nav_item_id=item.id).filter(NavItemPermission.job_title_id.isnot(None)).all()]

        children = []
        for child in sorted(item.children, key=lambda c: c.order or 0):
            child_roles = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=child.id).filter(NavItemPermission.role_id.isnot(None)).all()]
            child_jobs = [p.job_title_id for p in NavItemPermission.query.filter_by(nav_item_id=child.id).filter(NavItemPermission.job_title_id.isnot(None)).all()]

            children.append({
                "id": child.id,
                "label": child.label,
                "endpoint": child.endpoint,
                "allowed_role_ids": child_roles,
                "allowed_job_ids": child_jobs,
                "inherit_roles": child.inherit_roles
            })

        enriched_nav_items.append({
            "id": item.id,
            "label": item.label,
            "endpoint": item.endpoint,
            "allowed_role_ids": allowed_role_ids,
            "allowed_job_ids": allowed_job_ids,
            "children": children
        })

    return render_template(
        'admin/manage_navbar.html',
        nav_items=enriched_nav_items,
        all_roles=all_roles,
        all_job_titles=all_job_titles,
        all_headers=nav_items,
        available_endpoints=available_endpoints
    )


@admin_bp.route('/toggle_inherit_roles', methods=['POST'])
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

def is_valid_endpoint(endpoint_name):
    if not endpoint_name:
        return True  # Allow empty endpoints (they're valid for headers without links)
    return endpoint_name.strip() in current_app.view_functions

@admin_bp.route('/delete_nav_item', methods=['POST'])
@login_required
def delete_nav_item():
    nav_item_id = request.form.get('nav_item_id')
    item = NavItem.query.get_or_404(nav_item_id)

    # Check for children
    if item.parent_id is None and item.children:
        flash("Cannot delete a header with children. Please delete child links first.", "warning")
        return redirect(url_for('admin.manage_navbar'))

    # Delete permissions + the item
    NavItemPermission.query.filter_by(nav_item_id=item.id).delete()
    db.session.delete(item)
    db.session.commit()

    flash(f"'{item.label}' was deleted successfully.", "success")
    return redirect(url_for('admin.manage_navbar'))

@admin_bp.route('/reorder_nav_items', methods=['POST'])
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

@admin_bp.route('/manage_nav_items', methods=['GET', 'POST'])
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
        return redirect(url_for('admin.manage_nav_items'))

    headers = NavItem.query.filter_by(parent_id=None).all()
    items = NavItem.query.all()
    return render_template('admin/manage_nav_items.html', headers=headers, items=items)

@admin_bp.route('/update_nav_permission_ajax', methods=['POST'])
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

@admin_bp.route('/update_nav_job_permission_ajax', methods=['POST'])
@login_required
def update_nav_job_permission_ajax():
    data = request.get_json()
    nav_item_id = int(data['nav_item_id'])
    job_title_id = int(data['job_title_id'])
    action = data['action']

    if action == 'add':
        existing = NavItemPermission.query.filter_by(nav_item_id=nav_item_id, job_title_id=job_title_id).first()
        if not existing:
            db.session.add(NavItemPermission(nav_item_id=nav_item_id, job_title_id=job_title_id))
    elif action == 'remove':
        NavItemPermission.query.filter_by(nav_item_id=nav_item_id, job_title_id=job_title_id).delete()

    db.session.commit()
    return '', 204


@admin_bp.route('/manage_roles', methods=['GET', 'POST'])
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
                return redirect(url_for('admin.manage_roles'))
            
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
                    # Step 1: Remove role from users (if needed)
                    if role.users:
                        for user in role.users:
                            user.roles.remove(role)
                        db.session.commit()

                    # ✅ Step 2: Remove related nav item permissions
                    NavItemPermission.query.filter_by(role_id=role.roleID).delete()
                    db.session.commit()

                    # Step 3: Delete the role itself
                    db.session.delete(role)
                    db.session.commit()

                    flash(f'Role "{role.role_name}" deleted successfully.', 'success')
                else:
                    flash('Role not found.', 'danger')
            else:
                flash('Invalid role ID.', 'danger')


        return redirect(url_for('admin.manage_roles'))

    roles = RoleType.query.all()
    return render_template('admin/manage_roles.html', roles=roles)

@admin_bp.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("You do not have permission to perform this action.", "danger")
        return redirect(url_for('admin.manage_users'))

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

    return redirect(url_for('admin.manage_users'))

#####################################
###Get Employee Data From Envision###
#####################################
@admin_bp.route('/v1/Employees', methods=['GET'])
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


@admin_bp.route('/archive_user/<int:user_id>', methods=['POST'])
@login_required
def archive_user(user_id):
    """Marks a user as archived (inactive) instead of deleting them."""
    if not current_user.is_admin:
        flash("You do not have permission to archive users.", "danger")
        return redirect(url_for('admin.manage_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = False  # 🔹 Archive user
    db.session.commit()

    flash(f"User {user.username} has been archived.", "info")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/reinstate_user/<int:user_id>', methods=['POST'])
@login_required
def reinstate_user(user_id):
    """Restores an archived user to active status."""
    if not current_user.is_admin:
        flash("You do not have permission to reinstate users.", "danger")
        return redirect(url_for('admin.manage_users'))

    user = User.query.get_or_404(user_id)
    user.is_active = True  # 🔹 Restore user
    db.session.commit()

    flash(f"User {user.username} has been reinstated.", "success")
    return redirect(url_for('admin.manage_users'))

# Admin Dashboard Route
@admin_bp.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('admin.user_dashboard'))

    admin_tools = [
        {"name": "User Management", "url": url_for('admin.manage_users')},
        {"name": "Course Management", "url": url_for('admin.manage_courses')},
        {"name": "Role Management", "url": url_for('admin.manage_roles')},
        #{"name": "Exam Attempts", "url": url_for('view_exam_attempts')},
        # Add more admin tools as needed
    ]
    return render_template('admin/admin_dashboard.html', admin_tools=admin_tools)

@admin_bp.route('/manage_users', methods=['GET', 'POST'])
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
            return redirect(url_for('admin.manage_users'))

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

        return redirect(url_for('admin.manage_users'))

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

#########################
### Email Config Page ###
#########################
from flask import render_template, redirect, url_for, flash, request
from app.forms import LineTrainingEmailConfigForm, CourseReminderEmailConfigForm
from app.models import EmailConfig, RoleType, User

@admin_bp.route('/email_config', methods=['GET', 'POST'])
@login_required
def email_config():
    config = EmailConfig.query.first()
    if not config:
        config = EmailConfig()
        db.session.add(config)
        db.session.commit()

    course_reminder_form = CourseReminderEmailConfigForm(obj=config)
    medical_expiry_form = MedicalExpiryEmailConfigForm(obj=config)  # ✅ new form

    # Populate role choices
    roles = RoleType.query.all()
    role_choices = [(role.roleID, role.role_name) for role in roles]

    if request.method == 'POST':

        if request.form['submit'] == 'course_reminder' and course_reminder_form.validate_on_submit():
            config.course_reminder_days = course_reminder_form.course_reminder_days.data
            config.course_reminder_email = course_reminder_form.course_reminder_email.data
            db.session.commit()
            flash('Course Reminder configuration updated successfully.', 'success')

        elif request.form['submit'] == 'medical_expiry' and medical_expiry_form.validate_on_submit():
            config.medical_expiry_days = medical_expiry_form.medical_expiry_days.data
            config.medical_expiry_email = medical_expiry_form.medical_expiry_email.data
            db.session.commit()
            flash('Medical Expiry configuration updated successfully.', 'success')

        return redirect(url_for('admin.email_config'))

    # Fetch users in the training team role for display
    training_team_role = RoleType.query.filter_by(role_name="Training Team").first()
    training_team_users = training_team_role.users if training_team_role else []

    # Set the form data from the config object

    course_reminder_form.course_reminder_days.data = config.course_reminder_days
    course_reminder_form.course_reminder_email.data = config.course_reminder_email
    medical_expiry_form.medical_expiry_days.data = str(config.medical_expiry_days or '')
    medical_expiry_form.medical_expiry_email.data = config.medical_expiry_email

    return render_template('emails/email_config.html',
                           course_reminder_form=course_reminder_form,
                           medical_expiry_form=medical_expiry_form,
                           training_team_users=training_team_users)

@admin_bp.route('/fetch_and_update_roles', methods=['GET'])
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
    
@admin_bp.route('/assign_lms_role', methods=['POST'])
@login_required
@admin_required
def assign_lms_role():
    user_id = request.form.get('user_id')
    role_id = request.form.get('role_id')

    user = User.query.get(user_id)
    role = RoleType.query.get(role_id)

    if not user or not role:
        flash('Invalid user or role.', 'danger')
        return redirect(url_for('admin.manage_users'))

    if role not in user.roles:
        user.roles.append(role)
        db.session.commit()
        flash(f'Role "{role.role_name}" assigned to user "{user.username}".', 'success')
    else:
        flash(f'User "{user.username}" already has the role "{role.role_name}".', 'info')

    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/run_fetch_roles', methods=['GET'])
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
    
@admin_bp.route('/email', methods=['GET'])
@login_required
def run_qualification_reminder_email():
    send_qualification_reminders()
    return "Email sent successfully."

###############
###Job Title###
###############

@admin_bp.route('/manage_job_titles', methods=['GET', 'POST'])
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

        return redirect(url_for('admin.manage_job_titles'))

    # ✅ Generate `job_users_map` to track users assigned to each job title
    job_users_map = {
        job.id: [
            {"id": user.id, "username": user.username, "email": user.email}
            for user in User.query.filter_by(job_title_id=job.id).all()
        ]
        for job in job_titles
    }

    return render_template(
        'admin/manage_job_titles.html',
        job_titles=job_titles,
        users=users,
        locations=locations,  # ✅ Pass locations to template
        job_users_map=job_users_map  # ✅ Pass job_users_map to template
    )


@admin_bp.route('/edit_job_title', methods=['POST'])
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

    return redirect(url_for('admin.manage_job_titles'))


@admin_bp.route('/delete_job_title/<int:job_id>', methods=['POST'])
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
        return redirect(url_for('admin.manage_job_titles'))

    # ✅ If users exist but admin confirms deletion, reset their job title and delete
    if request.form.get('confirm_delete'):
        for user in affected_users:
            user.job_title_id = None  # Unassign job title

        db.session.delete(job)
        db.session.commit()
        flash(f"Job title '{job.title}' and all assigned users' job titles have been removed.", "success")
    else:
        flash("Deletion canceled.", "info")

    return redirect(url_for('admin.manage_job_titles'))

##############################
### Global Route Permissions ###
##############################

@admin_bp.before_request
def check_route_permissions():
    # List of routes that do not require authentication
    allowed_routes = {'login', 'logout', 'static', 'reset_password', 'verify_sign_password'}

    # If the user is not authenticated, only allow access to public routes
    if not current_user.is_authenticated:
        if request.endpoint and request.endpoint in allowed_routes:
            return  # Allow access
        return redirect(url_for('admin.login'))  # Redirect to login

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
            return redirect(url_for('user.user_dashboard'))

def generate_nonce():
    """Generate a unique nonce for authentication requests."""
    return os.urandom(16).hex()
