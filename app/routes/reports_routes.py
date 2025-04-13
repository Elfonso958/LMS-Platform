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

reports_bp = Blueprint("reports", __name__)

@reports_bp.route('/user_qualifications_report', methods=['GET', 'POST'])
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

@reports_bp.route('/Crew_Checks_Report', methods=['GET', 'POST'])
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




@reports_bp.route('/qualifications_report', methods=['GET', 'POST'])
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

@reports_bp.route('/user_reports_dashboard', methods=['GET'])
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

@reports_bp.route('/reports_dashboard', methods=['GET'])
@login_required
def reports_dashboard():
    return render_template('reports/reports_dashboard.html')

@reports_bp.route('/envision_qualification_expiry_report', methods=['GET'])
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

