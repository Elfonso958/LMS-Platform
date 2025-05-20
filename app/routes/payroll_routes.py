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

payroll_bp = Blueprint("payroll", __name__)

#####################
###Timesheets###
#####################

@payroll_bp.route('/timesheet/weekly', methods=['GET', 'POST'])
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
            return redirect(url_for('payroll.submit_weekly_timesheet'))

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
        return redirect(url_for('payroll.submit_weekly_timesheet', payroll_period_id=payroll_period.id))

    return render_template(
        'payroll/timesheet_weekly.html',
        payroll_periods=payroll_periods,
        selected_payroll_period=selected_payroll_period,
        week_days=week_days,
        timesheets=timesheets,
        timesheet_status=timesheet_status
    )




@payroll_bp.route('/save_timesheet', methods=['POST'])
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


@payroll_bp.route('/timesheets', methods=['GET'])
@login_required
def view_timesheets():
    timesheets = Timesheet.query.filter_by(user_id=current_user.id).order_by(Timesheet.date.desc()).all()
    return render_template('payroll/timesheet_list.html', timesheets=timesheets)

@payroll_bp.route('/timesheet/manage', methods=['GET'])
@login_required
@admin_required
def manage_timesheets():
    timesheets = Timesheet.query.filter_by(status='Pending').all()
    return render_template('payroll/timesheet_manage.html', timesheets=timesheets)

@payroll_bp.route('/timesheet/update/<int:timesheet_id>/<string:action>', methods=['POST'])
@login_required
@admin_required
def update_timesheet_status(timesheet_id, action):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    if action in ['Approved', 'Rejected']:
        timesheet.status = action
        db.session.commit()
        flash(f"Timesheet {action} successfully!", "success")
    return redirect(url_for('payroll.manage_timesheets'))

@payroll_bp.route('/payroll_periods', methods=['GET', 'POST'])
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

        return redirect(url_for('payroll.manage_payroll_periods'))

    payroll_periods = PayrollPeriod.query.order_by(PayrollPeriod.start_date.desc()).all()

    return render_template(
        'payroll/payroll_periods.html', 
        payroll_periods=payroll_periods,
        suggested_start_date=suggested_start_date.strftime("%Y-%m-%d"),  
        suggested_end_date=suggested_end_date.strftime("%Y-%m-%d")  
    )

@payroll_bp.route('/payroll_periods/toggle_status/<int:payroll_id>', methods=['POST'])
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
    
    return redirect(url_for('payroll.manage_payroll_periods'))


@payroll_bp.route('/payroll_periods/delete/<int:payroll_id>', methods=['POST'])
@login_required
@admin_required
def delete_payroll_period(payroll_id):
    payroll_period = PayrollPeriod.query.get_or_404(payroll_id)
    
    # Prevent deletion if timesheets exist for this payroll period
    if payroll_period.timesheets:
        flash("Cannot delete payroll period. It has associated timesheets!", "danger")
        return redirect(url_for('payroll.manage_payroll_periods'))
    
    db.session.delete(payroll_period)
    db.session.commit()
    flash("Payroll period deleted successfully!", "success")
    return redirect(url_for('payroll.manage_payroll_periods'))

@payroll_bp.route('/payroll_dashboard', methods=['GET'])
@login_required
def payroll_dashboard():
    if not current_user.job_title or not current_user.job_title.has_payroll_access:
        flash("You do not have permission to access the payroll dashboard.", "danger")

    payroll_periods = PayrollPeriod.query.order_by(PayrollPeriod.start_date.desc()).all()
    selected_payroll_period_id = request.args.get('payroll_period_id', type=int)
    selected_tab = request.args.get('status', 'Pending')

    employees = {
        "Approved": [],
        "Rejected": [],
        "Pending": [],
        "Not Submitted": []
    }

    if selected_payroll_period_id:
        if current_user.is_admin:
            employee_query = (
                db.session.query(User)
                .join(JobTitle, User.job_title_id == JobTitle.id)
                .filter(JobTitle.has_timesheet_access == True)
                .all()
            )
        elif current_user.job_title:
            subordinate_roles = current_user.job_title.get_all_subordinate_roles()
            subordinate_roles.append(current_user.job_title.id)

            employee_query = (
                db.session.query(User)
                .join(JobTitle, User.job_title_id == JobTitle.id)
                .filter(User.job_title_id.in_(subordinate_roles))
                .filter(User.id != current_user.id)  # 👈 exclude self
                .filter(JobTitle.has_timesheet_access == True)
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


@payroll_bp.route('/payroll_reports', methods=['GET'])
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



@payroll_bp.route('/payroll/view/<int:payroll_period_id>/<int:user_id>', methods=['GET', 'POST'])
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
                return redirect(url_for('payroll.view_employee_payroll', payroll_period_id=payroll_period_id, user_id=user_id))

            for timesheet in timesheets:
                timesheet.status = "Rejected"

            message_body = f"Your timesheet for {payroll_period.start_date.strftime('%A %d %B %Y')} - {payroll_period.end_date.strftime('%A %d %B %Y')} has been REJECTED.\n\nReason: {reject_reason}"

        db.session.commit()

        # ✅ Send email notification
        send_timesheet_response(user.email, current_app._get_current_object(), "Timesheet Status Update", message_body)

        flash(f"Timesheets for {user.username} have been {action}d.", "success")
        return redirect(url_for('payroll.payroll_dashboard', payroll_period_id=payroll_period_id))

    return render_template(
        'payroll/employee_payroll.html',
        payroll_period=payroll_period,
        user=user,
        timesheets=timesheets
    )

@payroll_bp.route('/my_timesheets', methods=['GET'])
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

@payroll_bp.route('/my_timesheet/<int:payroll_period_id>', methods=['GET'])
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



@payroll_bp.route('/timesheet/approve/<int:timesheet_id>', methods=['POST'])
@login_required
@admin_required
def approve_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    timesheet.status = 'Approved'
    db.session.commit()
    flash(f"Timesheet for {timesheet.user.username} approved!", "success")
    return redirect(url_for('payroll.payroll_dashboard'))

@payroll_bp.route('/timesheet/reject/<int:timesheet_id>', methods=['POST'])
@login_required
@admin_required
def reject_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)
    timesheet.status = 'Rejected'
    db.session.commit()
    flash(f"Timesheet for {timesheet.user.username} rejected!", "danger")
    return redirect(url_for('payroll.payroll_dashboard'))

@payroll_bp.route('/payroll/export', methods=['GET'])
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

@payroll_bp.route('/timesheet/resubmit/<int:payroll_period_id>', methods=['POST'])
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

    return redirect(url_for('payroll.submit_weekly_timesheet', payroll_period_id=payroll_period_id))
