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
from app.roster_utils import normalize_duty, duty_dict, get_current_duty, fetch_and_save_flights, check_for_flight_changes, check_for_daily_changes
from fpdf import FPDF
from flask import send_file
from sqlalchemy import func
from sqlalchemy import text, bindparam
from cachetools import TTLCache
from app.forms import CREW_CHECK_FIELDS
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

@app.route("/Test", methods=["GET", "POST"])
def test():
    print("Test For my Development Branch")

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
### Global Route Permissions ###
##############################

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

######################################
### Assign Role Based from Envision###
######################################

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    # Define the root path to the 'Course_Powerpoints' folder
    course_ppt_path = os.path.join(os.getcwd(), 'Course_Powerpoints')
    return send_from_directory(course_ppt_path, filename)

##################################
###Qualifications from Envision###
##################################




####################################
###Fetch User Roles from Envision###
####################################


##################################
###Roles from Envision###
##################################



#####################
###Reports Section###
#####################


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
    