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
from pytz import timezone

roster_bp = Blueprint("roster", __name__)

@roster_bp.route('/roster')
@login_required
def roster():
    return render_template('roster/roster.html', user=current_user)

@roster_bp.route('/crew_acknowledgements')
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

@roster_bp.route('/acknowledge_flight', methods=['POST'])
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

