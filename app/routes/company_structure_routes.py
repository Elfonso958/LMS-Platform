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

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, Response
from flask_login import login_user, logout_user, login_required, current_user

from flask_bcrypt import Bcrypt
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
from flask import send_file, jsonify
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
from services.envision_api import fetch_and_assign_user_roles, fetch_all_employees, fetch_and_update_user_roles, fetch_and_update_roles  # Import the function to fetch and assign user roles from Envision

company_bp = Blueprint("company", __name__)

#######################
###Company Structure###
#######################
@company_bp.route('/company_structure')
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
