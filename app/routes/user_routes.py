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

@user_bp.route('/user_profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    user_id = request.form.get('user_id', default=current_user.id, type=int) if request.method == 'POST' else request.args.get('user_id', default=current_user.id, type=int)
    user = User.query.get_or_404(user_id)

    current_app.logger.info(f"Loading profile for: ID={user.id}, Username={user.username}, Email={user.email}")
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
                return redirect(url_for('user.user_profile', user_id=user.id))

            current_app.logger.info(f"🔍 Full Form Data Received: {request.form.to_dict()}")

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
                        current_app.logger.info(f"Changing authentication type for User ID={user.id} from {user.auth_type} to {new_auth_type}")
                        user.auth_type = new_auth_type

                        # ✅ If changing to Local, allow password update
                        if new_auth_type == "local":
                            new_password = request.form.get('password', "").strip()

                            if new_password:
                                current_app.logger.info(f"🔍 Received new password for User ID={user.id}: {new_password}")

                                hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                                current_app.logger.info(f"🔑 Generated hashed password for User ID={user.id}: {hashed_password}")

                                user.password = hashed_password
                            else:
                                current_app.logger.warning(f"⚠️ No password provided for User ID={user.id}, skipping update.")

            # ✅ Allow Local Users to Update Their Password Without Changing Auth Type
            if user.auth_type == "local":
                new_password = request.form.get('password', "").strip()
                if new_password:
                    current_app.logger.info(f"🔍 Received new password update for existing local user ID={user.id}: {new_password}")

                    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    current_app.logger.info(f"🔑 Generated new hashed password for existing local user ID={user.id}: {hashed_password}")

                    user.password = hashed_password
                else:
                    current_app.logger.info(f"🛑 No password update provided for existing local user ID={user.id}, skipping.")

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
            current_app.logger.info(f"✅ Password successfully updated in database for User ID={user.id}")  # Debug
            flash('Profile updated successfully.', 'success')

        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"❌ Database IntegrityError for user {user.id} ({user.username}): {str(e)}")
            flash(f'An error occurred: {str(e)}', 'danger')

        return redirect(url_for('user.user_profile', user_id=user.id))

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

@user_bp.route('/my_exam_attempts', methods=['GET'])
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

######################
###User Crew Checks###
#####################
@user_bp.route('/my_checks')
@login_required
def my_crew_checks():
    # Fetch only completed checks for the logged-in user
    completed_checks = CrewCheckMeta.query.filter_by(candidate_id=current_user.id, is_complete=True).order_by(CrewCheckMeta.date_of_test.desc()).all()

    return render_template('user/my_checks.html', crew_checks_meta=completed_checks)
