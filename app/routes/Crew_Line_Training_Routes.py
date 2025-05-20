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

linetraining_bp = Blueprint("Line_Training", __name__)


@linetraining_bp.route('/create_line_training_form', methods=['GET', 'POST'])
@login_required
@admin_required
def create_line_training_form():
    if request.method == 'POST':
        form_name = request.form['name']
        selected_roles = request.form.getlist('roles')  # Get selected roles from the form

        # Create a new LineTrainingForm object
        new_form = LineTrainingForm(name=form_name)

        # Associate roles with the new line training form
        for role_id in selected_roles:
            role = RoleType.query.get(role_id)
            if role:
                new_form.roles.append(role)

        db.session.add(new_form)
        db.session.commit()

        flash('Line training form created successfully!', 'success')
        return redirect(url_for('crew_checks.crew_checks_dashboard'))

    roles = RoleType.query.all()  # Fetch all available roles to display in the form
    return render_template('crew_checks/create_line_training_form.html', roles=roles)



@linetraining_bp.route('/add_items_to_line_training_form/<int:form_id>', methods=['GET', 'POST'])
def add_items_to_line_training_form(form_id):
    form = LineTrainingForm.query.get_or_404(form_id)
    
    # Add new topic
    if request.method == 'POST' and 'add_topic' in request.form:
        topic_name = request.form['topic_name']
        new_topic = Topic(name=topic_name, line_training_form_id=form.id)
        db.session.add(new_topic)
        db.session.commit()
        flash('Topic added!', 'success')

    # Add new task to a specific topic with trainer's notes
    if request.method == 'POST' and 'add_task' in request.form:
        topic_id = request.form['topic_id']
        task_name = request.form['task_name']
        task_notes = request.form['task_notes']  # Capturing the trainer's notes
        new_task = Task(name=task_name, topic_id=topic_id, notes=task_notes)
        db.session.add(new_task)
        db.session.commit()
        flash('Task added!', 'success')
    
    # Get all topics for this form
    topics = form.topics

    return render_template('line_training_forms/add_items_to_line_training_form.html', form=form, topics=topics)

@linetraining_bp.route('/create_active_line_training_form/<int:template_id>', methods=['GET', 'POST'])
def create_active_line_training_form(template_id):
    template = LineTrainingForm.query.get_or_404(template_id)

    if request.method == 'POST':
        # Get candidate details
        candidate_id = request.form.get('candidate_id')
        candidate = User.query.get_or_404(candidate_id)

        # Check if the form already exists for the candidate
        existing_form = UserLineTrainingForm.query.filter_by(user_id=candidate.id, template_id=template.id).first()
        if existing_form:
            flash(f"A Line Training Form for {candidate.username} using this template already exists!", "warning")
            return redirect(url_for('Line_Training.view_active_line_training_form', form_id=existing_form.id))

        # Create a new user-specific line training form
        active_form = UserLineTrainingForm(user_id=candidate.id, template_id=template.id)
        db.session.add(active_form)
        db.session.flush()  # Flush to generate the active_form ID

        # Copy topics and tasks from the template to the user-specific form
        for topic in template.topics:
            # Check if the topic already exists
            existing_topic = Topic.query.filter_by(user_line_training_form_id=active_form.id, name=topic.name).first()
            if not existing_topic:
                new_topic = Topic(name=topic.name, user_line_training_form_id=active_form.id)
                db.session.add(new_topic)
                db.session.flush()  # Get new topic ID

                for task in topic.tasks:
                    # Check if the task already exists
                    existing_task = Task.query.filter_by(topic_id=new_topic.id, name=task.name).first()
                    if not existing_task:
                        new_task = Task(name=task.name, topic_id=new_topic.id, notes=task.notes)
                        db.session.add(new_task)

        db.session.commit()

        flash(f"Line Training Form for {candidate.username} created successfully!", "success")
        return redirect(url_for('Line_Training.view_active_line_training_form', form_id=active_form.id))

    # Display a candidate selection form
    candidates = User.query.all()
    return render_template('Line_Training_Forms/select_candidate.html', template=template, candidates=candidates)

@linetraining_bp.route('/view_active_line_training_forms_for_examiners', methods=['GET'])
def view_active_line_training_forms_for_examiners():
    search = request.args.get('search', '').strip()
    user_roles = [role.role_name for role in current_user.roles]

    # If user is in Training Team, they can see all forms
    if 'Training Team' in user_roles:
        query = UserLineTrainingForm.query
    else:
        # Base query with role-based filtering
        query = UserLineTrainingForm.query

        if 'SF34 Examiner' in user_roles and 'ATR72 Examiner' not in user_roles:
            # Only SF34 forms (Customisable)
            query = query.filter(UserLineTrainingForm.template.has(name='SF34 Line Training Form'))
        elif 'ATR72 Examiner' in user_roles and 'SF34 Examiner' not in user_roles:
            # Only ATR72 forms (Customisable)
            query = query.filter(UserLineTrainingForm.template.has(name='ATR72 Line Training Form'))
        elif 'Instructor' in user_roles or ('SF34 Examiner' in user_roles and 'ATR72 Examiner' in user_roles):
            # These roles see all forms (Customisable)
            pass  # No additional filtering needed
        else:
            # Default to no forms for roles not matching criteria
            query = query.filter(False)

    # Apply search filters if provided
    if search:
        query = query.filter(
            UserLineTrainingForm.user.has(User.username.ilike(f"%{search}%")) |
            (UserLineTrainingForm.id == search)
        )

    # Eager loading for templates and users
    active_forms = query.options(
        joinedload(UserLineTrainingForm.user),
        joinedload(UserLineTrainingForm.template)
    ).all()

    return render_template('Line_Training_Forms/examiners_active_line_training_forms.html', active_forms=active_forms)

@linetraining_bp.route('/examiners/line_training_form/<int:form_id>', methods=['GET', 'POST'])
def view_active_line_training_form(form_id):
    form = UserLineTrainingForm.query.get_or_404(form_id)
    candidate = form.user  # Assuming the candidate is the user associated with the form

    # Candidate details
    candidate_name = candidate.username
    license_number = candidate.license_number
    medical_expiry_date = candidate.medical_expiry.strftime('%Y-%m-%d') if candidate.medical_expiry else "Not Available"

    # Dynamically calculate total flight time and sectors from the Sector table
    total_flight_time_sectors = Sector.query.filter_by(form_id=form_id).count()
    total_flight_time_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0
    total_takeoffs = db.session.query(db.func.sum(Sector.takeoff_count)).filter_by(form_id=form_id).scalar() or 0
    total_landings = db.session.query(db.func.sum(Sector.landing_count)).filter_by(form_id=form_id).scalar() or 0
    total_flight_time_hours = round(total_flight_time_hours, 1)

    # Task completion percentage
    total_tasks = sum(len(topic.tasks) for topic in form.topics)
    completed_tasks = sum(
        len([task for task in topic.tasks if TaskCompletion.query.filter_by(task_id=task.id).first()])
        for topic in form.topics
    )
    percentage_complete = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0

    if request.method == 'POST':
        # Debug: Print all incoming form data for the POST request
        print("Form Data Submitted:", request.form)

        # Parse incoming form data for new sectors
        row_count = len([key for key in request.form.keys() if key.startswith('date_')])
        print(f"Total number of sectors to process: {row_count}")

        # Get the last existing sector_number for this form
        last_sector = Sector.query.filter_by(form_id=form_id).order_by(Sector.sector_number.desc()).first()
        next_sector_number = last_sector.sector_number + 1 if last_sector else 1  # If no sectors exist, start with 1
        print(f"Next sector number: {next_sector_number}")

        for i in range(1, row_count + 1):
            # Debug: Print each sector's data from the form
            date = request.form.get(f'date_{i}')
            variant = request.form.get(f'variant_{i}')
            departure = request.form.get(f'departure_{i}')
            arrival = request.form.get(f'arrival_{i}')
            flight_time_sector = request.form.get(f'flight_time_sector_{i}', type=float)
            flight_time_total = request.form.get(f'flight_time_total_{i}', type=float)
            # if_time_sector = request.form.get(f'if_time_sector_{i}', type=float) or 0
            # if_time_total = request.form.get(f'if_time_total_{i}', type=float) or 0
            # sector_type = request.form.get(f'type_{i}')
            takeoff = request.form.get(f'takeoff_{i}', type=int) or 0
            landing = request.form.get(f'landing_{i}', type=int) or 0
            total_takeoffs=total_takeoffs,
            total_landings=total_landings,

            # Debug: Check what data was received for each sector
            print(f"Processing Data for Sector {i}:")
            print(f"Date: {date}, Variant: {variant}, Departure: {departure}, Arrival: {arrival}")
            print(f"Flight Time Sector: {flight_time_sector}, Flight Time Total: {flight_time_total}")
            print(f"Takeoff: {takeoff}, Landing: {landing}")

            # Validate required fields
            if not date or not variant or not departure or not arrival:
                print(f"Missing fields in sector {i}. Skipping this sector.")
                flash("All fields are required for a new sector.", "danger")
                return redirect(request.url)

            # Create and add new Sector with the correct sector_number
            new_sector = Sector(
                form_id=form.id,
                date=datetime.strptime(date, '%Y-%m-%d'),
                variant=variant,
                dep=departure,
                arr=arrival,
                flight_time_sector=flight_time_sector,
                flight_time_total=flight_time_total,
                #if_time_sector=if_time_sector,
                #if_time_total=if_time_total,
                #type=sector_type,
                takeoff_count=takeoff,
                landing_count=landing,
                sector_number=next_sector_number  # Assign the calculated sector_number
            )
            db.session.add(new_sector)
            next_sector_number += 1  # Increment the sector number for the next one

        try:
            db.session.commit()
            flash('Sector count updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred: {str(e)}", "danger")
            print(f"Error: {str(e)}")  # Debugging the error message

        return redirect(url_for('Line_Training.view_active_line_training_form', form_id=form_id))

    return render_template(
        'Line_Training_Forms/view_active_line_training_form.html',
        form=form,
        candidate_name=candidate_name,
        license_number=license_number,
        medical_expiry_date=medical_expiry_date,
        total_flight_time_sectors=total_flight_time_sectors,
        total_flight_time_hours=total_flight_time_hours,
        total_takeoffs=total_takeoffs,  # Add this
        total_landings=total_landings,  # Add this
        percentage_complete=percentage_complete,
        user=current_user
    )

@linetraining_bp.route('/get_sector_note/<int:sector_id>', methods=['GET'])
def get_sector_note(sector_id):
    sector = Sector.query.get_or_404(sector_id)
    return jsonify({
        'success': True,
        'note': sector.notes
    })

@linetraining_bp.route('/save_sector', methods=['POST'])
def save_sector():
    data = request.get_json()  # Get the incoming data as JSON

    # Debugging log
    current_app.logger.info(f"Received data: {data}")

    # Ensure all required fields are present
    required_fields = [
        'form_id', 'date', 'variant', 'departure', 'arrival',
        'flight_time_sector', 'flight_time_total', 'takeoff', 'landing'
    ]
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    if len(data['departure']) != 3 or not data['departure'].isalpha():
        return jsonify({'error': 'Invalid departure code. Must be 3 letters.'}), 400

    if len(data['arrival']) != 3 or not data['arrival'].isalpha():
        return jsonify({'error': 'Invalid arrival code. Must be 3 letters.'}), 400

    try:
        # Fetch the form and validate
        form_id = int(data['form_id'])
        form = UserLineTrainingForm.query.get(form_id)
        if not form:
            return jsonify({'error': f'Form with id {form_id} not found'}), 404

        # Fetch the last sector number for the given form_id
        last_sector = Sector.query.filter_by(form_id=form_id).order_by(Sector.sector_number.desc()).first()
        next_sector_number = (last_sector.sector_number + 1) if last_sector else 1

        # Create the new sector object
        new_sector = Sector(
            form_id=form_id,  # Match the foreign key field in Sector
            date=datetime.strptime(data['date'], '%Y-%m-%d'),
            variant=data['variant'],
            dep=data['departure'],
            arr=data['arrival'],
            flight_time_sector=float(data['flight_time_sector']),
            flight_time_total=float(data['flight_time_total']),
            #if_time_sector=float(data.get('if_time_sector', 0)),
            #if_time_total=float(data.get('if_time_total', 0)),
            type=data.get('type', ''),
            takeoff_count=int(data['takeoff']),
            landing_count=int(data['landing']),
            sector_number=next_sector_number,
            saved=True,
            notes=str(data.get('notes', '')) or None,
            note_creator_id=current_user.id if data.get('notes') else None  # Log user if a note is present
        )

        # Add the new sector to the database
        db.session.add(new_sector)

        # Update the form totals
        form.total_sectors += 1
        form.total_hours = (form.total_hours or 0) + float(data['flight_time_total'])
        db.session.commit()

        current_app.logger.info(f"Sector saved successfully: {new_sector}")
        current_app.logger.info(f"Updated totals: Sectors={form.total_sectors}, Hours={form.total_hours}")

        # Return success response
        return jsonify({
            'success': True,
            'sector_id': new_sector.id,
            'sector_number': next_sector_number,
            'updated_totals': {
                'total_sectors': form.total_sectors,
                'total_hours': form.total_hours,
                'note_creator': current_user.username if data.get('notes') else None  # Return username
            }
        }), 200

    except ValueError as ve:
        current_app.logger.error(f"Validation error: {ve}")
        return jsonify({'error': f'Invalid data: {str(ve)}'}), 400
    except Exception as e:
        current_app.logger.error(f"Error saving sector: {e}")
        db.session.rollback()
        return jsonify({'error': 'An error occurred while saving the sector'}), 500

@linetraining_bp.route('/edit_topic/<int:topic_id>', methods=['GET', 'POST'])
def edit_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if request.method == 'POST':
        topic.name = request.form['topic_name']
        db.session.commit()
        flash('Topic updated!', 'success')
        return redirect(url_for('Line_Training.add_items_to_line_training_form', form_id=topic.line_training_form_id))
    return render_template('edit_topic.html', topic=topic)

@linetraining_bp.route('/delete_topic/<int:topic_id>', methods=['POST'])
def delete_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    db.session.delete(topic)
    db.session.commit()
    flash('Topic deleted!', 'success')
    return redirect(url_for('Line_Training.add_items_to_line_training_form', form_id=topic.line_training_form_id))

@linetraining_bp.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if request.method == 'POST':
        task.name = request.form['task_name']
        task.is_completed = 'is_completed' in request.form  # Handle checkbox
        task.notes = request.form['notes']
        db.session.commit()
        flash('Task updated!', 'success')
        return redirect(url_for('Line_Training.add_items_to_line_training_form', form_id=task.topic.line_training_form_id))
    return render_template('edit_task.html', task=task)

# In your delete_task function
@linetraining_bp.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    # Fetch the task and ensure it's part of the session
    task = Task.query.get_or_404(task_id)
    
    # Access task.topic while still within the session
    topic_id = task.topic_id  # Now task.topic should be accessible
    
    # Set the topic_id to None if you want to dissociate the task from the topic
    task.topic_id = None
    
    db.session.commit()
    
    # Now delete the task
    db.session.delete(task)
    db.session.commit()

    flash('Task deleted successfully', 'success')
    return redirect(url_for('Line_Training.add_items_to_line_training_form', form_id=topic_id))

@login_required
@admin_required
@linetraining_bp.route('/remove_sector/<int:sector_id>', methods=['DELETE'])
def remove_sector(sector_id):
    sector = Sector.query.get(sector_id)
    if sector:
        try:
            db.session.delete(sector)  # Remove the sector from the database
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 400
    else:
        return jsonify({'success': False, 'error': 'Sector not found'}), 404

@linetraining_bp.route('/delete_sector/<int:sector_id>', methods=['DELETE'])
def delete_sector(sector_id):
    try:
        # Fetch the sector from the database
        sector = Sector.query.get_or_404(sector_id)
        form_id = sector.form_id

        # Delete the sector
        db.session.delete(sector)
        db.session.commit()

        # Recalculate totals
        total_sectors = Sector.query.filter_by(form_id=form_id).count()
        total_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0

        # Update the form's totals
        form = UserLineTrainingForm.query.get(form_id)
        form.total_sectors = total_sectors
        form.total_hours = total_hours
        db.session.commit()

        current_app.logger.info(f"Sector {sector_id} deleted. Updated totals: Sectors={total_sectors}, Hours={total_hours}")

        return jsonify({'success': True, 'total_sectors': total_sectors, 'total_hours': total_hours}), 200
    except Exception as e:
        current_app.logger.error(f"Error deleting sector {sector_id}: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@linetraining_bp.route('/update_task', methods=['POST'])
def update_task():
    data = request.get_json()

    # Extract data from the received JSON
    form_id = data['form_id']
    task_id = data['task_id']
    completed = data['completed']

    # Get the task from the database
    task = Task.query.get_or_404(task_id)

    try:
        if completed:
            # Check if a completion already exists
            completion = TaskCompletion.query.filter_by(task_id=task.id, form_id=form_id).first()
            if not completion:
                # If no completion exists, create a new one
                completion = TaskCompletion(
                    task_id=task.id,
                    form_id=form_id,
                    trainer_id=current_user.id,  # Set current user as the trainer
                    completed_at=datetime.utcnow()  # Log the timestamp
                )
                db.session.add(completion)
        else:
            # If the task is being unchecked, delete the completion if it exists
            completion = TaskCompletion.query.filter_by(task_id=task.id, form_id=form_id).first()
            if completion:
                db.session.delete(completion)

        # Commit the changes to the database
        db.session.commit()

        # Return success response with updated "completed_by" information
        completed_by = None
        if completed:
            completed_by = {
                "username": current_user.username,
                "completed_at": datetime.utcnow().strftime('%d-%m-%Y-')
            }

        return jsonify({'success': True, 'completed_by': completed_by})
    except Exception as e:
        # Rollback in case of error
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 400


@linetraining_bp.route('/edit_line_training_form/<int:form_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_line_training_form(form_id):
    form = LineTrainingForm.query.get_or_404(form_id)
    roles = RoleType.query.all()

    # Create the FlaskForm
    edit_form = LineTrainingFormEditForm(obj=form)
    edit_form.roles.choices = [(role.roleID, role.role_name) for role in roles]

    # POST: Handle form submission
    if request.method == 'POST' and edit_form.validate_on_submit():
        form.name = edit_form.name.data
        selected_roles = edit_form.roles.data
        form.roles = [RoleType.query.get(role_id) for role_id in selected_roles]

        # Store thresholds as comma-separated strings
        form.threshold_total_sectors = ",".join(filter(None, edit_form.threshold_total_sectors.data))
        form.threshold_total_hours = ",".join(filter(None, edit_form.threshold_total_hours.data))

        db.session.commit()
        flash('Line Training Form updated successfully!', 'success')
        return redirect(url_for('crew_checks.crew_checks_dashboard'))

    # GET: Populate threshold fields as FieldList entries
    if request.method == 'GET':
        # Populate currently assigned roles
        edit_form.roles.data = [role.roleID for role in form.roles]

        # Also repopulate the sector/hour thresholds if needed
        edit_form.threshold_total_sectors.entries = []
        for val in (form.threshold_total_sectors or '').split(','):
            if val.strip():
                edit_form.threshold_total_sectors.append_entry(val.strip())
        else:
            edit_form.threshold_total_sectors.append_entry("")

        edit_form.threshold_total_hours.entries = []
        for val in (form.threshold_total_hours or '').split(','):
            if val.strip():
                edit_form.threshold_total_hours.append_entry(val.strip())
        else:
            edit_form.threshold_total_hours.append_entry("")

    return render_template('Line_Training_Forms/edit_line_training_form.html', form=edit_form, roles=roles)



@linetraining_bp.route('/update_totals', methods=['POST'])
def update_totals():
    try:
        # Parse the incoming request data
        data = request.get_json()
        form_id = data['form_id']

        # Validate form_id
        if not form_id:
            raise ValueError("form_id is required.")

        # Fetch the form from the database
        form = UserLineTrainingForm.query.get(form_id)
        if not form:
            return jsonify({'success': False, 'error': f"Form with id {form_id} not found."}), 404

        # Commit any pending changes to ensure the latest data is used
        db.session.commit()

        # Query the Sector table for updated totals
        total_sectors = Sector.query.filter_by(form_id=form_id).count()
        total_hours = db.session.query(db.func.sum(Sector.flight_time_total)).filter_by(form_id=form_id).scalar() or 0.0

        # Log the updated totals
        current_app.logger.info(f"Form ID {form_id}: Updated totals - Sectors={total_sectors}, Hours={total_hours}")

        # === Get thresholds from LineTrainingForm template ===
        template = form.template
        sector_thresholds = []
        hour_thresholds = []

        if template.threshold_total_sectors:
            sector_thresholds = [
                int(s.strip()) for s in template.threshold_total_sectors.split(",") if s.strip().isdigit()
            ]
        if template.threshold_total_hours:
            hour_thresholds = [
                float(h.strip()) for h in template.threshold_total_hours.split(",") if h.strip()
            ]

        # === Check if any threshold is exceeded ===
        threshold_exceeded = any(total_sectors >= s for s in sector_thresholds) or \
                             any(total_hours >= h for h in hour_thresholds)

        if threshold_exceeded:
            send_email_to_training_team(
                mail, current_app._get_current_object(),
                form_id, total_sectors, total_hours
            )

        # Return updated totals to the frontend
        return jsonify({
            'success': True,
            'total_sectors': total_sectors,
            'total_hours': round(total_hours, 2)
        }), 200

    except ValueError as ve:
        current_app.logger.error(f"Validation error: {ve}")
        return jsonify({'success': False, 'error': str(ve)}), 400
    except Exception as e:
        current_app.logger.error(f"Error in /update_totals: {e}")
        return jsonify({'success': False, 'error': "An unexpected error occurred."}), 500


@linetraining_bp.route('/release_candidate/<int:form_id>', methods=['POST'])
@login_required
def release_candidate(form_id):
    try:
        # Fetch the form and its template
        form = UserLineTrainingForm.query.get_or_404(form_id)
        candidate = form.user

        if not candidate:
            return jsonify({'success': False, 'error': 'Candidate not found.'}), 404

        # Ensure the candidate meets the release criteria
        total_takeoffs = sum(sector.takeoff_count or 0 for sector in form.sectors)
        total_landings = sum(sector.landing_count or 0 for sector in form.sectors)
        total_hours = form.total_hours or 0

        if total_hours < 20 or total_takeoffs < 10 or total_landings < 10:
            return jsonify({'success': False, 'error': 'Candidate does not meet the requirements for release.'}), 400

        # Update the released status
        form.released = True
        db.session.commit()

        # Send email notification to supervisors
        Send_Release_To_Supervisor_Email(
            current_app._get_current_object(), candidate, form.template.name, form.id, total_hours, total_takeoffs, total_landings, form.template.roles
        )

        return jsonify({
            'success': True,
            'message': f"Candidate {candidate.username} has been successfully released."
        }), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error releasing candidate: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@linetraining_bp.route('/complete_route_check/<int:form_id>', methods=['GET'])
@login_required
def complete_route_check(form_id):
    """Redirect to the IFR/OCA Check Form with pre-filled candidate details."""
    form = UserLineTrainingForm.query.get_or_404(form_id)
    candidate = form.user

    if not candidate:
        flash("Candidate not found.", "danger")
        return redirect(url_for('Line_Training.view_active_line_training_form', form_id=form_id))

    # Redirect to the IFR/OCA Check Form while passing candidate details as query parameters


@linetraining_bp.route('/delete_line_training_form/<int:form_id>', methods=['POST'])
@login_required
@admin_required
def delete_line_training_form(form_id):
    form = UserLineTrainingForm.query.get_or_404(form_id)

    try:
        # Delete all associated task completions first
        for topic in form.topics:
            for task in topic.tasks:
                TaskCompletion.query.filter_by(task_id=task.id).delete()

        # Delete associated tasks and topics
        for topic in form.topics:
            for task in topic.tasks:
                db.session.delete(task)
            db.session.delete(topic)

        # Delete the form itself
        db.session.delete(form)
        db.session.commit()

        flash("Line Training Form deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred while deleting the form: {str(e)}", "danger")

    return redirect(url_for('Line_Training.view_active_line_training_forms_for_examiners'))
