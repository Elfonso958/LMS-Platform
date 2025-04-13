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
from services.envision_api import fetch_and_assign_user_roles  # Import the function to fetch and assign user roles from Envision

auth_bp = Blueprint("auth", __name__)

ENVISION_AUTH_URL = "https://envision.airchathams.co.nz:8790/v1/Authenticate"

@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        entered_password = request.form.get("password", "").strip()  # Store entered password

        if not username_or_email or not entered_password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("auth.login"))

        user = User.query.filter((User.crew_code == username_or_email) | (User.email == username_or_email)).first()

        if not user:
            current_app.logger.warning(f"Login attempt failed: User not found ({username_or_email})")
            flash("User not found.", "danger")
            return redirect(url_for("auth.login"))

        # Log user details for debugging
        current_app.logger.info(f"Login attempt: User ID={user.id}, Username={user.username}, Auth Type={user.auth_type}")

        # Determine authentication type
        if user.auth_type == "local":
            current_app.logger.info(f"User {user.username} is a local user. Verifying password...")

            stored_hashed_password = user.password  # Store hashed password for debugging
            is_password_correct = check_password_hash(stored_hashed_password, entered_password)

            # Log password comparison
            current_app.logger.info(f"Entered Password: {entered_password}")
            current_app.logger.info(f"Stored Hashed Password: {stored_hashed_password}")
            current_app.logger.info(f"Password Match: {is_password_correct}")

            if is_password_correct:
                current_app.logger.info(f"Password match successful for User ID={user.id}")
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("user.user_dashboard"))
            else:
                current_app.logger.warning(f"Password mismatch for User ID={user.id}")
                flash("Invalid username or password.", "danger")
                return redirect(url_for("auth.login"))

        elif user.auth_type == "envision":
            current_app.logger.info(f"User {user.username} is an Envision user. Sending authentication request...")

            response = requests.post(
                ENVISION_AUTH_URL,
                json={"username": username_or_email, "password": entered_password, "nonce": "some_nonce"},
                verify=False  # ⚠️ Temporary! Use 'verify="path/to/cert.pem"' in production.
            )

            current_app.logger.info(f"Envision API Response: {response.status_code}, Content: {response.text}")

            if response.status_code == 200:
                data = response.json()
                token = data.get("token")

                if not token:
                    current_app.logger.warning(f"Envision login failed: No token received for User ID={user.id}")
                    flash("Authentication token missing from API response.", "danger")
                    return redirect(url_for("auth.login"))

                session['auth_token'] = token
                login_user(user, remember=True)
                session.permanent = True
                flash("Login successful via Envision!", "success")
                fetch_and_assign_user_roles(user)
                return redirect(url_for("user.user_dashboard"))
            else:
                current_app.logger.warning(f"Envision login failed: Invalid credentials for User ID={user.id}")
                flash("Invalid username or password for Envision.", "danger")
                return redirect(url_for("auth.login"))

        else:
            current_app.logger.error(f"Invalid authentication method for User ID={user.id}")
            flash("Invalid authentication method.", "danger")
            return redirect(url_for("auth.login"))

    return render_template("login.html")

# Logout Route
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('user.user_dashboard'))