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
from services.envision_api import fetch_and_assign_user_roles  # Import the function to fetch and assign user roles from Envision


api_bp = Blueprint("api", __name__)

@api_bp.route('/assign_roles_based_on_skills', methods=['GET'])
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

@api_bp.route('/save_employee_id', methods=['POST'])
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
