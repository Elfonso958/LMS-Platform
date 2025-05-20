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
from app.models import Course, RoleType, UserSlideProgress, UserExamAttempt, Questions, Answers, UserAnswer, course_role, User, db, PayrollInformation, CrewCheck, CrewCheckMeta, CheckItem, user_role,CheckItemGrade, LineTrainingForm, Location, Port, HandlerFlightMap, GroundHandler, CrewAcknowledgement, DocumentType, UserHRTask, HRTaskTemplate
from app.models import Task,TaskCompletion,Topic, LineTrainingItem,UserLineTrainingForm, Sector, RosterChange, Flight, FormTemplate,RoutePermission,Qualification,EmployeeSkill, EmailConfig, JobTitle, Timesheet, Location, PayrollPeriod,PayrollInformation, NavItem, NavItemPermission, DocumentReviewRequest # Import your models and database session
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
from app.forms import CREW_CHECK_FIELDS, FormUpload
from collections import defaultdict

user_bp = Blueprint("user", __name__)

@user_bp.route('/user_dashboard', methods=['GET'])
@login_required
def user_dashboard():
    if not current_user.is_authenticated:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for("auth.login"))

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
    pending_tasks = (
        UserHRTask.query
          .join(HRTaskTemplate, UserHRTask.task_template)
          .filter(
            UserHRTask.user_id             == current_user.id,
            UserHRTask.status              == 'Pending',
            HRTaskTemplate.is_employee_task == True
          )
          .order_by(UserHRTask.due_date)
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
        qualifications=qualifications,
        pending_tasks=pending_tasks
    )

@user_bp.route('/user_profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    # Determine which user we’re editing
    if request.method == 'POST':
        user_id = request.form.get('user_id', default=current_user.id, type=int)
    else:
        user_id = request.args.get('user_id', default=current_user.id, type=int)
    user = User.query.get_or_404(user_id)

    current_app.logger.info(f"Loading profile for: ID={user.id}, Username={user.username}, Email={user.email}")

    payroll = PayrollInformation.query.filter_by(user_id=user.id).first()
    roles = RoleType.query.all()
    job_titles = JobTitle.query.all()
    users = User.query.all()
    user_roles = [role.roleID for role in user.roles]
    user_roles_names = [role.role_name for role in user.roles]
    locations = Location.query.order_by(Location.name).all()

    if request.method == 'POST':
        try:
            # Permission check
            if user.id != current_user.id and not current_user.is_admin:
                flash('You do not have permission to edit this profile.', 'danger')
                return redirect(url_for('user.user_profile', user_id=user.id))

            current_app.logger.info(f"🔍 Full Form Data Received: {request.form.to_dict()}")

            # -- Always-updatable fields --
            user.email           = request.form.get('email')
            user.username        = request.form.get('username')
            user.phone_number    = request.form.get('phone_number')
            user.address         = request.form.get('address')
            user.next_of_kin     = request.form.get('next_of_kin')
            user.kin_phone_number= request.form.get('kin_phone_number')
            # Date fields: only set if non-empty
            dob_input            = request.form.get('date_of_birth', '').strip()
            user.date_of_birth   = dob_input or None

            # -- Admin-only fields --
            if current_user.is_admin:
                # Authentication type & password
                new_auth = request.form.get('auth_type')
                if new_auth in ('local', 'envision') and new_auth != user.auth_type:
                    current_app.logger.info(f"Auth type change: {user.auth_type} → {new_auth}")
                    user.auth_type = new_auth
                if user.auth_type == 'local':
                    pwd = request.form.get('password', '').strip()
                    if pwd:
                        user.password = generate_password_hash(pwd, method='pbkdf2:sha256')

                # License / medical
                user.license_type    = request.form.get('license_type')
                user.license_number  = request.form.get('license_number')
                med_exp = request.form.get('medical_expiry', '').strip()
                user.medical_expiry  = med_exp or None

                # Roles
                selected_roles = request.form.getlist('roles')
                user.roles = [RoleType.query.get(rid) for rid in selected_roles]

                # Admin flag
                user.is_admin = 'is_admin' in request.form

                # Location
                loc_id = request.form.get('location_id')
                user.location_id = loc_id or None

                # Job title & manager relationship
                jt = request.form.get('job_title_id')
                user.job_title_id = jt or None
                mgr = request.form.get('manager_id')
                user.reports_to   = mgr or None

                # Envision link handled separately in JS

                # -- Payroll updates --
                if not payroll:
                    payroll = PayrollInformation(user_id=user.id)
                    db.session.add(payroll)

                payroll.type_of_employment    = request.form.get('type_of_employment')
                payroll.minimum_hours         = request.form.get('minimum_hours') == 'True'
                payroll.hours                 = request.form.get('hours') if payroll.minimum_hours else None
                payroll.bank_account_details  = request.form.get('bank_account_details')
                
            # Commit *all* changes
            db.session.commit()

            flash('Profile updated successfully.', 'success')

        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"Database IntegrityError for user {user.id}: {e}")
            flash(f'An error occurred: {e.orig}', 'danger')

        return redirect(url_for('user.user_profile', user_id=user.id))

    # GET: render form
    return render_template(
        'user/user_profile.html',
        user=user,
        payroll=payroll,
        roles=roles,
        job_titles=job_titles,
        users=users,
        user_roles=user_roles,
        user_roles_names=user_roles_names,
        locations=locations,
    )

######################
###User Crew Checks###
#####################
@user_bp.route('/my_checks')
@login_required
def my_crew_checks():
    # Fetch only completed checks for the logged-in user
    completed_checks = CrewCheckMeta.query.filter_by(candidate_id=current_user.id, is_complete=True).order_by(CrewCheckMeta.date_of_test.desc()).all()

    return render_template('user/my_checks.html', crew_checks_meta=completed_checks)

