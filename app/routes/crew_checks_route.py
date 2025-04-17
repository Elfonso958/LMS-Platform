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

crew_checks_bp = Blueprint("crew_checks", __name__)

ENVISION_AUTH_URL = "https://envision.airchathams.co.nz:8790/v1/Authenticate"

@crew_checks_bp.route('/crew_checks_dashboard')
@login_required
def crew_checks_dashboard():
    required_roles = {'Training Team', 'SF34 Examiner', 'ATR72 Examiner'}
    user_roles = {role.role_name for role in current_user.roles}

    if not current_user.is_admin and not required_roles.intersection(user_roles):
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('user_dashboard'))
    # Debug: Print the current user's roles
    user_roles = [role.role_name for role in current_user.roles]
    # Fetch all crew checks from the database
    crew_checks = CrewCheck.query.order_by(CrewCheck.created_at.desc()).all()
    # Fetch all LineTrainingForm objects from the database
    line_training_forms = LineTrainingForm.query.all()
    # Create a form instance (for editing or displaying data)
    form = LineTrainingFormEditForm()  # Empty form, used for creating or editing line training forms
    roles = RoleType.query.all()
    return render_template('crew_checks/crew_checks_dashboard.html', crew_checks=crew_checks, line_training_forms=line_training_forms, form=form, roles=roles, all_fields=CREW_CHECK_FIELDS)

@crew_checks_bp.route('/create_crew_check', methods=['GET', 'POST'])
@login_required
@admin_required
def create_crew_check():
    if request.method == 'POST':
        name = request.form.get('name')
        role_ids = request.form.getlist('roles')  # List of role IDs

        new_check = CrewCheck(name=name)
        db.session.add(new_check)
        db.session.flush()  # Ensure new_check.id is available

        # Add roles to the check
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                new_check.roles.append(role)

        db.session.commit()
        flash('Crew Check created successfully!', 'success')
        return redirect(url_for('crew_checks.crew_checks_dashboard'))

    roles = RoleType.query.all()  # Get all roles
    return render_template('crew_checks/create_crew_check.html', roles=roles)

@crew_checks_bp.route('/edit_crew_check/<int:crew_check_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_crew_check(crew_check_id):
    crew_check = CrewCheck.query.get_or_404(crew_check_id)

    if request.method == 'POST':
        crew_check.name = request.form.get('name')
        role_ids = request.form.getlist('roles')  # List of role IDs

        # Update roles
        crew_check.roles = []
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                crew_check.roles.append(role)

        # ✅ Save selected headers
        selected_headers = request.form.getlist('headers')
        crew_check.visible_headers = json.dumps(selected_headers)

        db.session.commit()
        flash('Crew Check updated successfully!', 'success')
        return redirect(url_for('crew_checks.crew_checks_dashboard'))


    roles = RoleType.query.all()  # Get all roles
    return render_template('edit_crew_check.html', crew_check=crew_check, roles=roles)

@crew_checks_bp.route('/delete_crew_check/<int:crew_check_id>', methods=['POST'])
@login_required
@admin_required
def delete_crew_check(crew_check_id):
    """Allows admins to delete a crew check."""
    check = CrewCheck.query.get_or_404(crew_check_id)

    try:
        db.session.delete(check)
        db.session.commit()
        flash(f'Crew check "{check.name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting crew check: {str(e)}", "danger")

    return redirect(url_for('crew_checks.crew_checks_dashboard'))

# Crew Check Items
@crew_checks_bp.route('/add_check_item/<int:check_id>', methods=['GET', 'POST'])
@login_required
def add_check_item(check_id):
    crew_check = CrewCheck.query.get_or_404(check_id)
    
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        mandatory = request.form.get('mandatory') == 'on'
        manual_link = request.form.get('manual_link')
        additional_info = request.form.get('additional_info')
        # Determine the current highest version among CheckItems for this crew check.
        # If none exist, default to 0.
        highest_version = db.session.query(func.max(CheckItem.version)).filter_by(crew_check_id=check_id).scalar() or 0
        new_version = highest_version + 1

        new_item = CheckItem(
            crew_check_id=check_id,
            item_name=item_name,
            mandatory=mandatory,
            manual_link=manual_link,
            version=new_version,   # Set new version automatically
            additional_info=additional_info
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Check Item added successfully with version {}'.format(new_version), 'success')
        return redirect(url_for('crew_checks.add_check_item', check_id=check_id))

    # Fetch existing check items
    check_items = CheckItem.query.filter_by(crew_check_id=check_id).all()
    return render_template('crew_checks/add_check_item.html', crew_check=crew_check, check_items=check_items)

@crew_checks_bp.route('/get_check_item/<int:item_id>', methods=['GET'])
@login_required
def get_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    return jsonify({
        'id': item.id,
        'item_name': item.item_name,
        'mandatory': item.mandatory,
        'manual_link': item.manual_link,
        'additional_info': item.additional_info
    })

@crew_checks_bp.route('/update_check_item/<int:item_id>', methods=['POST'])
@login_required
def update_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    item.item_name = request.form.get('item_name')
    item.mandatory = request.form.get('mandatory') == 'on'
    item.manual_link = request.form.get('manual_link')
    item.additional_info = request.form.get('additional_info')
    db.session.commit()
    return jsonify({'success': True})

#################################
###Delete/Restore Crew Check Form Item###
#################################
@crew_checks_bp.route('/delete_check_item/<int:item_id>', methods=['POST'])
@login_required
def delete_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    
    # Mark item as deleted instead of actually deleting it
    item.deleted = True
    db.session.commit()
    
    flash("Check item marked as deleted successfully.", "success")
    return jsonify({'success': True, 'message': 'Check item marked as deleted successfully.'})

@crew_checks_bp.route('/restore_check_item/<int:item_id>', methods=['POST'])
@login_required
def restore_check_item(item_id):
    item = CheckItem.query.get_or_404(item_id)
    item.deleted = False  # Restore the check item
    db.session.commit()
    flash("Check item restored successfully.", "success")
    return redirect(url_for('crew_checks.add_check_item', check_id=item.crew_check_id))
######################################
###Add Sorting Order to Check Items###
######################################
@crew_checks_bp.route('/update_check_item_order', methods=['POST'])
@login_required
def update_check_item_order():
    data = request.get_json()

    print("\n=== Incoming Order Update Request ===")
    print(data)  # ✅ Debugging: Log received data

    if not data or "items" not in data:
        print("❌ Error: Invalid request data")
        return jsonify({"success": False, "message": "Invalid data"}), 400

    try:
        check_item_ids = [int(item["id"]) for item in data["items"]]  # Convert IDs to int
        check_items = CheckItem.query.filter(CheckItem.id.in_(check_item_ids)).all()

        print("\n🔍 Before Update:")
        for item in check_items:
            print(f"CheckItem ID {item.id}: Order={item.order}")

        # Update orders based on received data
        for item_data in data["items"]:
            item_id = int(item_data["id"])  # Convert ID to int
            new_order = int(item_data["order"])  # Convert order to int

            check_item = next((ci for ci in check_items if ci.id == item_id), None)
            if check_item:
                print(f"🔄 Assigning: CheckItem ID {check_item.id} → New Order {new_order}")
                check_item.order = new_order

        db.session.commit()
        print("✅ Order update committed successfully!\n")

        print("\n🔍 After Update:")
        for item in CheckItem.query.filter(CheckItem.id.in_(check_item_ids)).order_by(CheckItem.order).all():
            print(f"CheckItem ID {item.id}: Order={item.order}")

        return jsonify({"success": True, "message": "Order updated successfully"})

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error updating order: {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    
#########################################
### Delete Incomplete Crew Check Forms###
#########################################
@crew_checks_bp.route('/delete_check_meta/<int:meta_id>', methods=['POST'])
@login_required
@admin_required
def delete_check_meta(meta_id):
    check_meta = CrewCheckMeta.query.get_or_404(meta_id)
    if check_meta.is_complete:
        flash("Completed checks cannot be deleted.", "danger")
        return redirect(url_for('crew_checks.checks'))
    try:
        # Delete all associated CheckItemGrade records first
        grades = CheckItemGrade.query.filter_by(crew_check_meta_id=check_meta.id).all()
        for grade in grades:
            db.session.delete(grade)
        # Now delete the check meta record
        db.session.delete(check_meta)
        db.session.commit()
        flash("Incomplete check deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting check: {str(e)}", "danger")
    return redirect(url_for('crew_checks.checks'))


@crew_checks_bp.route('/update_template_task/<int:task_id>', methods=['POST'])
@login_required
def update_template_task(task_id):
    data = request.get_json()

    # ✅ Validate request data
    if not data or 'task_name' not in data or 'task_notes' not in data:
        return jsonify({'success': False, 'error': 'Invalid request data'}), 400

    task_name = data.get('task_name', '').strip()
    task_notes = data.get('task_notes', '').strip()

    # ✅ Find the task
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'success': False, 'error': 'Task not found'}), 404

    if not task_name:
        return jsonify({'success': False, 'error': 'Task name cannot be empty'}), 400

    try:
        # ✅ Update the task
        task.name = task_name
        task.notes = task_notes
        db.session.commit()
        return jsonify({'success': True, 'updated_name': task.name, 'updated_notes': task.notes})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@crew_checks_bp.route('/get_candidate_details/<int:candidate_id>', methods=['GET'])
@login_required
def get_candidate_details(candidate_id):
    """Returns candidate details for auto-filling the form"""
    candidate = User.query.get(candidate_id)
    
    if not candidate:
        return jsonify({"error": "Candidate not found"}), 404

    return jsonify({
        "license_type": candidate.license_type,
        "license_number": candidate.license_number,
        "medical_expiry": candidate.medical_expiry.strftime('%Y-%m-%d') if candidate.medical_expiry else "",
        'crew_code': candidate.crew_code
    })

@crew_checks_bp.route('/crew_check_form/<int:crew_check_id>', methods=['GET', 'POST'])
@login_required
def crew_check_form(crew_check_id):
    today = datetime.today().strftime('%Y-%m-%d')
    crew_check = CrewCheck.query.get_or_404(crew_check_id)
    # Get the role IDs assigned to this crew check
    assigned_role_ids = [role.roleID for role in crew_check.roles]
    # Only fetch users who have at least one of the assigned roles
    all_candidates = (
    User.query
    .join(User.roles)
    .filter(RoleType.roleID.in_(assigned_role_ids))
    .filter(User.is_active == True)  # Exclude archived users
    .distinct()
    .all()
    )

    check_items = CheckItem.query.filter_by(crew_check_id=crew_check_id).order_by(CheckItem.order).all()

    draft_id = request.args.get('draft_id', type=int)
    check_meta = CrewCheckMeta.query.get(draft_id) if draft_id else None

    candidate_id = request.args.get('candidate_id', type=int)
    form_id = request.args.get('form_id', type=int)
    candidate = User.query.get(candidate_id) if candidate_id else None

    candidate_data = {
        "username": candidate.username if candidate else "",
        "license_number": candidate.license_number if candidate else "",
        "medical_expiry": candidate.medical_expiry.strftime('%Y-%m-%d') if candidate and candidate.medical_expiry else "",
        "aircraft_type": "SF34",
    }

    visible_fields = json.loads(crew_check.visible_headers or "[]")

    if request.method == 'POST':
        candidate_id_form = request.form.get('candidate_id')
        if not candidate_id_form:
            return jsonify({'success': False, 'error': 'Candidate must be selected.'}), 400
        try:
            candidate_id_form = int(candidate_id_form)
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid candidate selection.'}), 400
        candidate = User.query.get(candidate_id_form)
        if not candidate:
            return jsonify({'success': False, 'error': 'Selected candidate not found.'}), 404

        if check_meta:
            updated_meta = check_meta
        else:
            updated_meta = CrewCheckMeta(crew_check_id=crew_check.id)
            db.session.add(updated_meta)

        updated_meta.candidate_id = candidate.id

        field_map = {
            "candidate_name": 'candidate_name',
            "licence_type": 'licence_type',
            "licence_number": 'licence_number',
            "medical_expiry": 'medical_expiry',
            "date_of_test": 'date_of_test',
            "aircraft_type": 'aircraft_type',
            "aircraft_registration": 'aircraft_registration',
            "type_of_check": 'type_of_check',
            "comments": 'comments',
            "flight_times": 'flight_times',
            "current_check_due": 'current_check_due',
            "test_result": 'test_result',
            "logbook_sticker_issued": 'logbook_sticker_issued',
            "next_check_due": 'next_check_due',
            "examiner_name": 'examiner_name',
            "examiner_license_number": 'examiner_license_number'
        }

        for field_key, attr in field_map.items():
            if field_key in visible_fields:
                setattr(updated_meta, attr, request.form.get(field_key))
            else:
                setattr(updated_meta, attr, None)

        if 'flight_times' in visible_fields:
            try:
                updated_meta.flight_time_day = int(request.form.get('flight_time_day', '0'))
                updated_meta.flight_time_night = int(request.form.get('flight_time_night', '0'))
                updated_meta.flight_time_if = int(request.form.get('flight_time_if', '0'))
            except ValueError:
                updated_meta.flight_time_day = updated_meta.flight_time_night = updated_meta.flight_time_if = 0
        else:
            updated_meta.flight_time_day = updated_meta.flight_time_night = updated_meta.flight_time_if = None

        if not updated_meta.is_complete:
            updated_meta.examiner_name = current_user.username
            updated_meta.examiner_license_number = current_user.license_number

        updated_meta.examiner_code = request.form.get('examiner_code')
        updated_meta.candidate_code = request.form.get('candidate_code')

        current_template_version = (
            db.session.query(func.max(CheckItem.version))
            .filter_by(crew_check_id=crew_check.id)
            .scalar()
        ) or 1
        updated_meta.template_version = current_template_version

        if 'save_draft' in request.form:
            updated_meta.is_complete = False
            flash('Crew check form saved as draft.', 'info')
        else:
            updated_meta.is_complete = True
            flash('Crew check form submitted successfully!', 'success')

        db.session.commit()

        for item in check_items:
            grade_value = request.form.get(f'grade_{item.id}')
            comment_value = request.form.get(f'comment_{item.id}', '').strip()
            comment_to_save = comment_value if comment_value else None

            existing_grade = CheckItemGrade.query.filter_by(
                crew_check_meta_id=updated_meta.id,
                check_item_id=item.id
            ).first()

            if grade_value:
                if existing_grade:
                    existing_grade.grade = grade_value
                    existing_grade.grade_comment = comment_to_save
                    existing_grade.grader_id = current_user.id
                    existing_grade.graded_at = datetime.now()
                else:
                    new_grade = CheckItemGrade(
                        crew_check_meta_id=updated_meta.id,
                        check_item_id=item.id,
                        grade=grade_value,
                        grade_comment=comment_to_save,
                        grader_id=current_user.id,
                        graded_at=datetime.now()
                    )
                    db.session.add(new_grade)

        db.session.commit()

        if updated_meta.is_complete:
            from app.email_utils import send_crew_check_email_to_training_team
            send_crew_check_email_to_training_team(current_app._get_current_object(), updated_meta.id)

        return jsonify({'success': True, 'draft_id': updated_meta.id})

    user_roles = [role.role_name for role in current_user.roles]

    return render_template(
        'crew_checks/crew_check_form.html',
        today=today,
        crew_check=crew_check,
        candidate=candidate,
        candidate_id=candidate_id,
        check_items=check_items,
        all_candidates=all_candidates,
        form_id=form_id,
        check_meta=check_meta,
        candidate_data=candidate_data,
        user_roles=user_roles,
        visible_fields=visible_fields
    )


##########################
### View My Crew Check ###
##########################
@crew_checks_bp.route('/view_my_crew_check/<int:meta_id>')
@login_required
def view_my_crew_check(meta_id):
    """Read-only view for crew check."""
    check_meta = CrewCheckMeta.query.get_or_404(meta_id)

    # ✅ Ensure only the owner (candidate) can view the check
    if check_meta.candidate_id != current_user.id:
        print(f"❌ Unauthorized access attempt! User: {current_user.username} tried to access Check ID: {meta_id}")
        flash("You do not have permission to view this check.", "danger")
        return redirect(url_for('my_crew_checks'))

    print(f"✅ Crew Check Found: ID {check_meta.id}, Candidate: {check_meta.candidate_id}")

    # ✅ Load check template to get visible field configuration
    crew_check = CrewCheck.query.get(check_meta.crew_check_id)
    visible_fields = json.loads(crew_check.visible_headers or "[]")

    check_items = CheckItem.query.filter_by(crew_check_id=check_meta.crew_check_id).all()

    return render_template(
        'user/view_my_check.html',
        check_meta=check_meta,
        check_items=check_items,
        visible_fields=visible_fields
    )


##############################################
### Verify Examinar and Candidate Password ###
##############################################
@crew_checks_bp.route('/verify_sign_password', methods=['POST'])
@login_required
def verify_sign_password():
    # Retrieve form data; draft_id may be empty if the form isn’t saved yet.
    user_crew_code = request.form.get("user_id", "").strip()  # Crew code
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "").strip()  # 'examiner' or 'candidate'
    draft_id = request.form.get("draft_id", "").strip()  # May be empty
    crew_check_id = request.form.get("crew_check_id", "").strip()  # Fallback if draft_id is missing

    # Validate required fields (except draft_id which is now optional)
    if not user_crew_code or not password or not role:
        current_app.logger.error("Missing crew code, password, or role in verify_sign_password")
        return jsonify({'success': False, 'error': 'Crew code, password, and role are required.'}), 400

    # Look up the user by crew_code
    user = User.query.filter_by(crew_code=user_crew_code).first()
    if not user:
        current_app.logger.error("User not found for Crew Code: %s", user_crew_code)
        return jsonify({'success': False, 'error': 'User not found.'}), 404

    # Retrieve the appropriate CrewCheckMeta record:
    # If draft_id is provided, use it; otherwise, fall back to crew_check_id.
    if draft_id:
        crew_check_meta = CrewCheckMeta.query.get(draft_id)
        if not crew_check_meta:
            current_app.logger.error("Crew check meta not found for Draft ID: %s", draft_id)
            return jsonify({'success': False, 'error': 'Crew check meta not found.'}), 404
    else:
        if not crew_check_id:
            current_app.logger.error("Missing crew check id when draft id is not provided")
            return jsonify({'success': False, 'error': 'Crew check id is required if draft id is missing.'}), 400
        # Query for the most recent CrewCheckMeta record for the given crew_check_id.
        crew_check_meta = (CrewCheckMeta.query
                           .filter_by(crew_check_id=crew_check_id)
                           .order_by(CrewCheckMeta.id.desc())
                           .first())
        if not crew_check_meta:
            current_app.logger.error("No CrewCheckMeta record found for crew_check_id: %s", crew_check_id)
            return jsonify({'success': False, 'error': 'Crew check meta not found.'}), 404

    # Construct payload for external authentication
    payload = {"username": user.crew_code, "password": password, "nonce": "some_nonce"}
    current_app.logger.info("Sending payload to %s: %s", ENVISION_AUTH_URL, payload)
    try:
        response = requests.post(ENVISION_AUTH_URL, json=payload, verify=False)
        current_app.logger.info("Received response with status %s: %s", response.status_code, response.text)
    except Exception as e:
        current_app.logger.error("Error calling Envision API: %s", e)
        return jsonify({'success': False, 'error': str(e)}), 500

    if response.status_code == 200:
        data = response.json()
        if not data.get("token"):
            current_app.logger.error("API response missing token: %s", data)
            return jsonify({'success': False, 'error': 'Invalid password.'}), 400

        # Update the CrewCheckMeta record based on role
        if role == 'examiner':
            crew_check_meta.examiner_signed = True
        elif role == 'candidate':
            crew_check_meta.candidate_signed = True

        db.session.commit()
        return jsonify({'success': True})
    else:
        current_app.logger.error("Envision API returned error status %s: %s", response.status_code, response.text)
        return jsonify({'success': False, 'error': 'Invalid password.'}), 400

###############################################
###IFR/OCA Crew Checks (Complete/Incomplete)###
###############################################
@crew_checks_bp.route('/checks')
@login_required
def checks():
    status_filter = request.args.get('status', 'all')
    aircraft_filter = request.args.get('aircraft', 'all')
    candidate_filter = request.args.get('candidate', '')
    type_of_check_filter = request.args.get('type_of_check', 'all')
    sort_by = request.args.get('sort_by', 'date_of_test')
    order = request.args.get('order', 'asc')
    required_roles = {'Training Team', 'SF34 Examiner', 'ATR72 Examiner'}
    user_roles = {role.role_name for role in current_user.roles}

    # Fetch all candidates
    all_candidates = User.query.all()

    # Fetch all distinct crew check names (for filter dropdown)
    crew_checks = CrewCheck.query.with_entities(CrewCheck.name).distinct().all()

    # Fetch all crew check meta data
    crew_checks_meta = CrewCheckMeta.query.all()

    active_filter = request.args.get('active', 'all')
    # Apply filters
    filtered_checks = []
    for check_meta in crew_checks_meta:
        completed = check_meta.is_complete
        user_active = check_meta.candidate.is_active if check_meta.candidate else False

        if (status_filter == 'all' or (status_filter == 'completed' and completed) or (status_filter == 'incomplete' and not completed)) and \
        (aircraft_filter == 'all' or check_meta.aircraft_type == aircraft_filter) and \
        (candidate_filter == '' or candidate_filter.lower() in check_meta.candidate.username.lower()) and \
        (type_of_check_filter == 'all' or check_meta.check.name == type_of_check_filter) and \
        (active_filter == 'all' or (active_filter == 'active' and user_active) or (active_filter == 'inactive' and not user_active)):
            filtered_checks.append(check_meta)

    # Apply sorting
    reverse = (order == 'desc')
    if sort_by == 'check_name':
        filtered_checks.sort(key=lambda x: x.check.name, reverse=reverse)
    elif sort_by == 'aircraft_type':
        filtered_checks.sort(key=lambda x: x.aircraft_type or '', reverse=reverse)
    elif sort_by == 'candidate':
        filtered_checks.sort(key=lambda x: x.candidate.username, reverse=reverse)
    elif sort_by == 'date_of_test':
        filtered_checks.sort(key=lambda x: x.date_of_test, reverse=reverse)
    elif sort_by == 'test_result':
        filtered_checks.sort(key=lambda x: x.test_result, reverse=reverse)
    elif sort_by == 'status':
        filtered_checks.sort(key=lambda x: x.is_complete, reverse=reverse)
    elif sort_by == 'next_check_due':
        filtered_checks.sort(key=lambda x: x.next_check_due, reverse=reverse)

    if not current_user.is_admin and not required_roles.intersection(user_roles):
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('user_dashboard'))

    return render_template(
        'crew_checks/checks.html',
        crew_checks_meta=filtered_checks,
        all_candidates=all_candidates,
        crew_checks=[check for check, in crew_checks]  # Extract check names only
    )


###############################
###Print IFR/OCA Crew Check###
###############################

@crew_checks_bp.route('/print_check/<int:check_meta_id>')
@login_required
def print_check(check_meta_id):
    # Retrieve the CrewCheckMeta record
    check_meta = CrewCheckMeta.query.get_or_404(check_meta_id)
    today = datetime.today().strftime('%Y-%m-%d')

    # Prepare candidate data for the template
    candidate_data = {
        'license_type': check_meta.candidate.license_type if check_meta.candidate else "Not Provided",
        'license_number': check_meta.candidate.license_number if check_meta.candidate else "Not Provided",
        'medical_expiry': (
            check_meta.candidate.medical_expiry.strftime('%Y-%m-%d')
            if check_meta.candidate and check_meta.candidate.medical_expiry else "Not Provided"
        )
    }

    # ✅ Add visible_fields extraction
    visible_fields = json.loads(check_meta.check.visible_headers or "[]")

    # Render the crew check PDF template
    rendered_html = render_template(
        "crew_checks/crew_check_form_pdf.html",
        crew_check_meta=check_meta,
        today=today,
        candidate_data=candidate_data,
        visible_fields=visible_fields  # Pass it in
    )

    # Configure pdfkit – ensure wkhtmltopdf path is correct
    path_wkhtmltopdf = r'C:\Users\Jayden\OneDrive - Air Chathams Ltd\Desktop\LMS Platform\wkhtmltopdf.exe'
    config = pdfkit.configuration(wkhtmltopdf=path_wkhtmltopdf)
    options = {
        'page-size': 'A4',
        'encoding': "UTF-8",
        'no-outline': None,
    }

    try:
        pdf_data = pdfkit.from_string(rendered_html, False, configuration=config, options=options)
    except Exception as e:
        current_app.logger.error(f"Error generating PDF: {e}")
        return f"Error generating PDF: {e}", 500

    # Return inline PDF response
    return Response(pdf_data,
                    mimetype='application/pdf',
                    headers={'Content-Disposition': 'inline; filename="CrewCheckForm.pdf"'})

