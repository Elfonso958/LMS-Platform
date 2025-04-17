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

course_bp = Blueprint("course", __name__)

@course_bp.route('/course/<int:course_id>/start_again', methods=['POST'])
@login_required
def start_course_again(course_id):
    # Reset slide progress for the user
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if progress:
        progress.completed = False
        progress.last_slide_viewed = 0
        db.session.commit()

    flash("Your progress has been reset. Start the course again.", "info")
    return redirect(url_for('view_course', course_id=course_id))

@course_bp.route('/manage_courses', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_courses():
    if request.method == 'POST':
        # Fetch form data
        title = request.form['title']
        description = request.form['description']
        role_type_ids = request.form.getlist('role_type_ids')  # Multiple role IDs
        ppt_file = request.files['ppt_file']
        passing_mark = request.form.get('passing_mark', type=int)
        passing_percentage = request.form.get('passing_percentage', type=float)  # If applicable
        valid_for_days = request.form.get('valid_for_days', type=int)
        available_before_expiry_days = request.form.get('available_before_expiry_days', type=int)
        
        # Handle the boolean field `has_exam`
        has_exam = 'has_exam' in request.form  # Check if the checkbox is selected

        # Validate required fields
        if not title or not description or not role_type_ids or not ppt_file or passing_mark is None:
            flash('All fields, including Passing Mark, are required.', 'danger')
            return redirect(url_for('manage_courses'))

        # Save the uploaded PowerPoint file
        ppt_filename = secure_filename(ppt_file.filename)
        ppt_path = os.path.join(current_app.config['UPLOAD_FOLDER'], course.ppt_file)
        ppt_file.save(ppt_path)

        # Create the course instance
        course = Course(
            title=title,
            description=description,
            ppt_file=ppt_filename,
            passing_mark=passing_mark,
            passing_percentage=passing_percentage,  # Optional, only if relevant
            valid_for_days=valid_for_days,
            available_before_expiry_days=available_before_expiry_days,
            has_exam=has_exam  # Assign the boolean value
        )

        # Assign roles to the course
        roles = RoleType.query.filter(RoleType.roleID.in_(role_type_ids)).all()
        course.roles.extend(roles)

        db.session.add(course)
        db.session.commit()

        flash(f'Course "{title}" created successfully.', 'success')
        return redirect(url_for('manage_courses'))

    # Fetch existing courses and roles for display
    courses = Course.query.all()
    roles = RoleType.query.all()
    return render_template('course/manage_courses.html', courses=courses, roles=roles)

@course_bp.route('/edit_course/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_course(course_id):
    course = Course.query.get_or_404(course_id)

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        role_type_ids = request.form.getlist('role_type_ids')  # Fetch multiple roles
        passing_mark = request.form.get('passing_mark', type=int)
        passing_percentage = request.form.get('passing_percentage', type=float)  # Assuming percentage can be updated
        course.valid_for_days = request.form.get('valid_for_days', type=int)
        course.available_before_expiry_days = request.form.get('available_before_expiry_days', type=int)
        course.is_resit = 'is_resit' in request.form  # Checkbox input, true if checked
        course.has_exam = 'has_exam' in request.form

        if not title or not role_type_ids or passing_mark is None:
            flash('All required fields must be filled.', 'danger')
            return redirect(url_for('edit_course', course_id=course_id))

        # Update course details
        course.title = title
        course.description = description
        course.passing_mark = passing_mark
        course.passing_percentage = passing_percentage

        # Clear existing roles and assign new ones
        course.roles.clear()
        for role_id in role_type_ids:
            role = RoleType.query.get(role_id)
            if role:
                course.roles.append(role)

        db.session.commit()
        flash(f'Course "{title}" updated successfully.', 'success')
        return redirect(url_for('manage_courses'))

    # Fetch roles for the form
    roles = RoleType.query.all()
    return render_template('course/edit_course.html', course=course, roles=roles)

@course_bp.route('/course/<int:course_id>', methods=['GET'])
@login_required
def view_course(course_id):
    course = Course.query.get_or_404(course_id)

    # Check if the user has access to the course
    user_roles = [role.roleID for role in current_user.roles]
    course_roles = [role.roleID for role in course.roles]

    if not set(user_roles).intersection(course_roles) and not current_user.is_admin:
        flash('You do not have access to this course.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Ensure progress is tracked
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    if not progress:
        progress = UserSlideProgress(user_id=current_user.id, course_id=course_id, last_slide_viewed=0)
        db.session.add(progress)
        db.session.commit()

    # Extract slides
    ppt_path = os.path.join(current_app.config['UPLOAD_FOLDER'], course.ppt_file)
    slides_folder = os.path.join(current_app.static_folder, 'Course_Powerpoints', f'slides_{course.id}')
    os.makedirs(slides_folder, exist_ok=True)
    if not os.listdir(slides_folder):
        extract_slides_to_png(ppt_path, slides_folder)

    slide_paths = sorted(
        [os.path.join(slides_folder, f) for f in os.listdir(slides_folder) if f.endswith(".png")],
        key=natural_sort_key
    )
    slide_count = len(slide_paths)
    slide_index = int(request.args.get('slide', 0))

    # Validate the slide index
    if slide_index < 0 or slide_index >= slide_count:
        flash('Invalid slide index.', 'danger')
        return redirect(url_for('user_dashboard'))

    # Update progress
    if slide_index >= progress.last_slide_viewed:
        progress.last_slide_viewed = slide_index

    # Handle completion logic
    is_last_slide = slide_index == slide_count - 1
    if is_last_slide and not course.has_exam:
        progress.completed = True  # Mark as completed if no exam and last slide is viewed
    db.session.commit()

    # Debugging Progress
    print(f"Slide index: {slide_index}")
    print(f"Last slide viewed: {progress.last_slide_viewed}")
    print(f"Completed: {progress.completed}")
    print(f"Total slides: {slide_count}")

    # Determine buttons to show
    show_finish = not course.has_exam and is_last_slide
    show_take_exam = course.has_exam and is_last_slide

    # Pass data to the template
    return render_template(
        'course/view_course.html',
        course=course,
        current_slide=slide_index + 1,  # 1-based slide count for display
        total_slides=slide_count,
        slide_image=url_for('static', filename=f"Course_Powerpoints/slides_{course.id}/{os.path.basename(slide_paths[slide_index])}"),
        next_slide=slide_index + 1 if slide_index + 1 < slide_count else None,
        prev_slide=slide_index - 1 if slide_index > 0 else None,
        show_finish=show_finish,
        show_take_exam=show_take_exam
    )

@course_bp.route('/uploads/<path:filename>')
def serve_file(filename):
    # Define the root path to the 'Course_Powerpoints' folder
    course_ppt_path = os.path.join(os.getcwd(), 'Course_Powerpoints')
    return send_from_directory(course_ppt_path, filename)

@course_bp.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
@admin_required
def delete_course(course_id):
    course = Course.query.get_or_404(course_id)
    
    # Correct the slides folder path
    slides_folder = os.path.join(current_app.root_path, 'static', 'Course_Powerpoints', f"slides_{course.id}")
    if os.path.exists(slides_folder):
        try:
            shutil.rmtree(slides_folder)  # Attempt to remove the directory
        except Exception as e:
            flash(f"Permission error: Unable to delete slides folder. {e}", 'danger')
            return redirect(url_for('manage_courses'))

    # Correct the PowerPoint file path
    ppt_path = os.path.join(current_app.root_path, 'static', 'Course_Powerpoints', course.ppt_file)
    if os.path.exists(ppt_path):
        try:
            os.remove(ppt_path)
        except Exception as e:
            flash(f"Permission error: Unable to delete PowerPoint file. {e}", 'danger')
            return redirect(url_for('manage_courses'))

    # Delete associated course data
    try:
        # Delete related questions and answers
        questions = Questions.query.filter_by(course_id=course_id).all()
        for question in questions:
            Answers.query.filter_by(question_id=question.id).delete()
            db.session.delete(question)

        # Delete related user progress
        UserSlideProgress.query.filter_by(course_id=course_id).delete()

        # Delete related exam attempts
        UserExamAttempt.query.filter_by(course_id=course_id).delete()

        # Delete the course itself
        db.session.delete(course)
        db.session.commit()
    except Exception as e:
        flash(f"Error deleting course data: {e}", 'danger')
        return redirect(url_for('manage_courses'))

    flash(f'Course "{course.title}" and all associated data deleted successfully.', 'success')
    return redirect(url_for('manage_courses'))
@course_bp.route('/course/<int:course_id>/finish', methods=['POST'])
@login_required
def finish_course(course_id):
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    course = Course.query.get_or_404(course_id)

    if not progress or progress.last_slide_viewed < get_slide_count(course_id) - 1:
        flash("You must complete all slides before finishing this course.", "danger")
        return redirect(url_for('view_course', course_id=course_id))

    # Mark course as completed
    progress.completed = True
    progress.last_completed_date = datetime.utcnow()

    # Set expiry date if the course has validity
    if course.valid_for_days:
        progress.expiry_date = datetime.utcnow() + timedelta(days=course.valid_for_days)

    db.session.commit()
    flash("Course completed successfully!", "success")
    return redirect(url_for('user_dashboard'))

@course_bp.route('/course/<int:course_id>/take_exam', methods=['GET', 'POST'])
@login_required
def take_exam(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)

    # Ensure the user has viewed all slides
    progress = UserSlideProgress.query.filter_by(user_id=current_user.id, course_id=course_id).first()
    slide_count = get_slide_count(course.id)  # Function to get the total slides for the course

    if not progress or progress.last_slide_viewed < slide_count - 1:
        flash("You need to finish all the slides before taking the exam.", "danger")
        return redirect(url_for('view_course', course_id=course_id))

    if request.method == 'POST':
        # Extract submitted answers
        submitted_answers = {
            int(k.split('_')[1]): int(v)
            for k, v in request.form.items()
            if k.startswith('question_')
        }

        # Calculate the score and determine if passed
        score, passed = calculate_exam_score(course_id, submitted_answers)

        # Create a new exam attempt regardless of pass or fail
        attempt = UserExamAttempt(
            user_id=current_user.id,
            course_id=course_id,
            score=score,
            passed=passed,
            expiry_date=datetime.utcnow() + timedelta(days=course.valid_for_days) if passed else None,
            created_at=datetime.utcnow(),
            is_resit=False
        )
        db.session.add(attempt)
        db.session.flush()  # Ensure attempt.id is generated before use

        # Store the user's answers in the UserAnswers table
        for question_id, answer_id in submitted_answers.items():
            question = Questions.query.get(question_id)
            answer = Answers.query.get(answer_id)
            is_correct = answer.is_correct if answer else False

            user_answer = UserAnswer(
                attempt_id=attempt.id,
                question_id=question_id,
                answer_id=answer_id,
                is_correct=is_correct
            )
            db.session.add(user_answer)

        # Commit changes
        try:
            db.session.commit()

            if passed:
                # Mark the course progress as completed if the exam is passed
                if progress:
                    progress.completed = True
                    db.session.commit()
            
            # Redirect to the exam result page regardless of pass/fail
            return redirect(url_for('course.exam_result', course_id=course_id, attempt_id=attempt.id))

        except Exception as e:
            db.session.rollback()
            print(f"Error committing exam attempt: {e}")
            flash("There was an error submitting your exam. Please try again.", "danger")
            return redirect(url_for('course.take_exam', course_id=course_id))

    # Fetch the questions for this course
    questions = Questions.query.filter_by(course_id=course_id).all()
    random.shuffle(questions)  # Randomize the order of questions

    # For each question, shuffle its answers
    for question in questions:
        question.answers = question.answers[:]  # copy list to avoid side effects
        random.shuffle(question.answers)

    return render_template('course/exams/take_exam.html', course=course, questions=questions)

@course_bp.route('/course/<int:course_id>/exam_result/<int:attempt_id>', methods=['GET'])
@login_required
def exam_result(course_id, attempt_id):
    # Fetch the attempt and course
    attempt = UserExamAttempt.query.get_or_404(attempt_id)
    course = Course.query.get_or_404(course_id)

    # Ensure the attempt belongs to the current user
    if attempt.user_id != current_user.id:
        flash("You are not authorized to view this result.", "danger")
        return redirect(url_for('user_dashboard'))

    if attempt.passed:
        # Ensure the certificate is generated and saved
        try:
            certificate_path = generate_certificate(current_user, attempt)
            if certificate_path:
                print(f"Certificate generated at: {certificate_path}")
            else:
                print("Certificate generation failed.")
        except Exception as e:
            print(f"Error generating certificate: {e}")
            flash("Error generating certificate. Please contact support.", "danger")

    # Pass both the attempt and course to the template
    return render_template('Course/Exams/exam_result.html', attempt=attempt, course=course)

@course_bp.route('/generate_certificate_file/<int:attempt_id>', methods=['GET'])
@login_required
def generate_certificate_file(attempt_id):
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the attempt belongs to the current user
    if attempt.user_id != current_user.id:
        flash("You are not authorized to download this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Send the file to the user for download
    return send_from_directory(
        os.path.dirname(attempt.certificate_path),
        os.path.basename(attempt.certificate_path),
        as_attachment=True,
        download_name=os.path.basename(attempt.certificate_path)
    )

@course_bp.route('/download_certificate/<int:attempt_id>', methods=['GET'])
@login_required
def download_certificate(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You do not have permission to download this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Validate certificate path
    if not attempt.certificate_path or not os.path.exists(attempt.certificate_path):
        flash("Certificate not found. It may not have been generated yet.", "danger")
        return redirect(url_for('course.exam_result', course_id=attempt.course_id, attempt_id=attempt.id))

    # Send the file for download
    directory = os.path.dirname(attempt.certificate_path)
    filename = os.path.basename(attempt.certificate_path)
    return send_from_directory(directory, filename, as_attachment=True)

@course_bp.route('/view_certificate/<int:attempt_id>', methods=['GET'])
@login_required
def view_certificate(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You do not have permission to view this certificate.", "danger")
        return redirect(url_for('user_dashboard'))

    # Validate certificate path
    if not attempt.certificate_path or not os.path.exists(attempt.certificate_path):
        flash("Certificate not found. It may not have been generated yet.", "danger")
        return redirect(url_for('course.exam_result', course_id=attempt.course_id, attempt_id=attempt.id))

    # Return the certificate
    directory = os.path.dirname(attempt.certificate_path)
    filename = os.path.basename(attempt.certificate_path)
    return send_from_directory(directory, filename, as_attachment=False)


@course_bp.route('/admin/questions/<int:course_id>/add', methods=['POST'])
@login_required
@admin_required
def add_question(course_id):
    course = Course.query.get_or_404(course_id)

    question_text = request.form.get('question_text')
    if not question_text.strip():
        flash("Question text cannot be empty.", "danger")
        return redirect(url_for('manage_questions', course_id=course_id))

    new_question = Questions(text=question_text, course_id=course_id)
    db.session.add(new_question)
    db.session.commit()
    flash("Question added successfully!", "success")

    return redirect(url_for('manage_questions', course_id=course_id))

@course_bp.route('/admin/questions/delete/<int:question_id>', methods=['POST'])
@login_required
@admin_required
def delete_question(question_id):
    question = Questions.query.get_or_404(question_id)
    course_id = question.course_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", "success")
    return redirect(url_for('manage_questions', course_id=course_id))

@course_bp.route('/admin/questions/<int:course_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_questions(course_id):
    course = Course.query.get_or_404(course_id)
    questions = Questions.query.filter_by(course_id=course_id).all()

    if request.method == 'POST':
        question_text = request.form['question_text']
        new_question = Questions(text=question_text, course_id=course_id)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('manage_questions', course_id=course_id))

    return render_template('course/exams/manage_questions.html', course=course, questions=questions)

@course_bp.route('/admin/questions/edit/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_question(question_id):
    # Fetch the question by ID
    question = Questions.query.get_or_404(question_id)

    if request.method == 'POST':
        # Get the updated question text from the form
        question_text = request.form.get('question_text')
        if question_text and question_text.strip():
            question.text = question_text.strip()
            db.session.commit()
            flash('Question updated successfully.', 'success')
            return redirect(url_for('manage_questions', course_id=question.course_id))
        else:
            flash('Question text cannot be empty.', 'danger')
            return redirect(url_for('edit_question', question_id=question.id))

    # Render the edit question form
    return render_template('course/exams/edit_question.html', question=question)

@course_bp.route('/manage_answers/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_answers(question_id):
    question = Questions.query.get_or_404(question_id)

    # Adding a new answer
    if request.method == 'POST' and 'text' in request.form:
        if request.form.get('text'):
            new_answer = Answers(
                text=request.form.get('text'),
                is_correct=request.form.get('is_correct') == 'on',
                question_id=question_id
            )
            db.session.add(new_answer)
            db.session.commit()
            flash("Answer added successfully.", "success")
        else:
            flash("Answer text cannot be empty.", "danger")
        return redirect(url_for('manage_answers', question_id=question_id))

    # Updating an existing answer
    if request.method == 'POST' and 'answer_id' in request.form:
        answer_id = request.form.get('answer_id')
        updated_text = request.form.get('updated_text')
        updated_is_correct = request.form.get('updated_is_correct') == 'on'

        answer = Answers.query.get_or_404(answer_id)
        if updated_text:
            answer.text = updated_text
            answer.is_correct = updated_is_correct
            db.session.commit()
            flash("Answer updated successfully.", "success")
        else:
            flash("Updated text cannot be empty.", "danger")
        return redirect(url_for('manage_answers', question_id=question_id))

    # Fetch all answers for the question
    answers = Answers.query.filter_by(question_id=question_id).all()
    return render_template('course/exams/manage_answers.html', question=question, answers=answers)

@course_bp.route('/admin/manage_answers/<int:answer_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_answer(answer_id):
    answer = Answers.query.get_or_404(answer_id)
    question_id = answer.question_id  # Save question ID before deleting

    db.session.delete(answer)
    db.session.commit()
    flash('Answer deleted successfully.', 'success')
    return redirect(url_for('manage_answers', question_id=question_id))

@course_bp.route('/update_answer/<int:answer_id>', methods=['POST'])
@login_required
@admin_required
def update_answer(answer_id):
    # Fetch the answer from the database
    answer = Answers.query.get_or_404(answer_id)

    # Get the submitted data
    answer_text = request.form.get('answer_text')
    is_correct = request.form.get('is_correct') == 'on'

    # Debugging: Print the received data
    print(f"Updating Answer ID: {answer_id}")
    print(f"New Text: {answer_text}")
    print(f"Is Correct: {is_correct}")

    # Update the fields
    if answer_text:
        answer.text = answer_text
    answer.is_correct = is_correct

    # Save the changes
    db.session.commit()

    # Flash a success message and redirect
    flash('Answer updated successfully.', 'success')
    return redirect(url_for('manage_answers', question_id=answer.question_id))

@course_bp.route('/admin/answers/<int:answer_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_answer(answer_id):
    answer = Answers.query.get_or_404(answer_id)

    if request.method == 'POST':
        answertext = request.form['answer_text']
        answer.is_correct = 'is_correct' in request.form  # Checkbox for marking as correct
        db.session.commit()
        flash('Answer updated successfully!', 'success')
        return redirect(url_for('manage_answers', question_id=answer.question_id))

    return render_template('edit_answer.html', answer=answer)


# User able to Fetch their exam attempt
@course_bp.route('/view_my_exam_attempt/<int:attempt_id>', methods=['GET'])
@login_required
def view_my_exam_attempt(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Ensure the logged-in user owns the attempt
    if attempt.user_id != current_user.id:
        flash("You are not authorized to view this attempt.", "danger")
        return redirect(url_for('my_attempts'))

    # Fetch all the user's answers for this attempt
    user_answers = UserAnswer.query.filter_by(attempt_id=attempt_id).all()

    # Fetch all questions and answers for the course
    course_id = attempt.course_id
    questions = Questions.query.filter_by(course_id=course_id).all()

    # Prepare data for the template
    detailed_answers = []
    for question in questions:
        answers = Answers.query.filter_by(question_id=question.id).all()
        user_answer = next((ua for ua in user_answers if ua.question_id == question.id), None)
        
        detailed_answers.append({
            "question": question,
            "answers": answers,
            "user_answer_id": user_answer.answer_id if user_answer else None,
            "is_correct": user_answer.is_correct if user_answer else False,
        })

    return render_template(
        'user/view_my_exam_attempt.html',
        attempt=attempt,
        detailed_answers=detailed_answers
    )

@course_bp.route('/my_exam_attempts', methods=['GET'])
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

#Shows all the exam attempts for a specific course.
@course_bp.route('/course/<int:course_id>/exam_attempts', methods=['GET'])
@login_required
@admin_required
def view_exam_attempts(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)

    # Fetch all exam attempts for this course
    exam_attempts = UserExamAttempt.query.filter_by(course_id=course_id).all()

    return render_template(
        'Course/Exams/view_exam_attempts.html',
        course=course,
        exam_attempts=exam_attempts
    )

# Admin Able to Fetch the users exam attempt
@course_bp.route('/exam_attempt/<int:attempt_id>', methods=['GET'])
@login_required
@admin_required
def view_user_exam_attempt(attempt_id):
    # Fetch the exam attempt
    attempt = UserExamAttempt.query.get_or_404(attempt_id)

    # Fetch all the user's answers for this attempt
    user_answers = UserAnswer.query.filter_by(attempt_id=attempt_id).all()

    # Fetch all questions and answers for the course
    course_id = attempt.course_id
    questions = Questions.query.filter_by(course_id=course_id).all()

    # Prepare data for the template
    detailed_answers = []
    for question in questions:
        answers = Answers.query.filter_by(question_id=question.id).all()
        user_answer = next((ua for ua in user_answers if ua.question_id == question.id), None)
        
        detailed_answers.append({
            "question": question,
            "answers": answers,
            "user_answer_id": user_answer.answer_id if user_answer else None,
            "is_correct": user_answer.is_correct if user_answer else False,
        })

    return render_template(
        'course/exams/view_user_exam_attempt.html',
        attempt=attempt,
        detailed_answers=detailed_answers
    )


@course_bp.route('/delete_exam_attempt/<int:attempt_id>', methods=['POST'])
@login_required
@admin_required
def delete_exam_attempt(attempt_id):
    attempt = UserExamAttempt.query.get_or_404(attempt_id)
    user_id = attempt.user_id
    course_id = attempt.course_id

    try:
        # Remove related UserAnswers
        UserAnswer.query.filter_by(attempt_id=attempt.id).delete()

        # Remove the exam attempt
        db.session.delete(attempt)

        # Update UserSlideProgress to mark as not completed
        progress = UserSlideProgress.query.filter_by(user_id=user_id, course_id=course_id).first()
        if progress:
            progress.completed = False
            progress.last_completed_date = None
            progress.expiry_date = None
            db.session.commit()

        db.session.commit()
        flash('Exam attempt deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting exam attempt: {e}', 'danger')

    return redirect(url_for('course.view_exam_attempts', course_id=course_id))

@course_bp.route('/course/<int:course_id>/completed', methods=['GET'])
@login_required
@admin_required
def view_completed_users(course_id):
    # Fetch the course
    course = Course.query.get_or_404(course_id)
    
    # Ensure the course doesn't have an exam
    if course.has_exam:
        flash("This course has exams. Please use the 'Attempts' button instead.", "danger")
        return redirect(url_for('course.manage_courses'))

    # Fetch users who have completed the course
    completions = (
        db.session.query(UserSlideProgress, User)
        .join(User, UserSlideProgress.user_id == User.id)
        .filter(UserSlideProgress.course_id == course_id, UserSlideProgress.completed == True)
        .all()
    )

    # Pass the data to the template
    return render_template(
        'Course/view_completed_users.html',
        course=course,
        completions=completions
    )

# Assuming there is some mechanism to initiate a resit, e.g., a button press.
@course_bp.route('/initiate_resit/<int:course_id>', methods=['POST'])
@login_required
def initiate_resit(course_id):
    user_id = current_user.id

    # Fetch the latest attempt for this course by the user
    last_attempt = (
        UserExamAttempt.query
        .filter_by(user_id=user_id, course_id=course_id)
        .order_by(UserExamAttempt.created_at.desc())
        .first()
    )

    if last_attempt:
        # Calculate the start of the resit period
        resit_start_date = last_attempt.expiry_date - timedelta(days=last_attempt.course.available_before_expiry_days)

        # If within the valid resit period or expired
        if resit_start_date <= datetime.utcnow() or last_attempt.expiry_date < datetime.utcnow():
            # Create a new attempt
            new_attempt = UserExamAttempt(
                user_id=user_id,
                course_id=course_id,
                created_at=datetime.utcnow(),
                # Set a new expiry date from the current date
                expiry_date=datetime.utcnow() + timedelta(days=last_attempt.course.valid_for_days),
                passed=False  # Start with False until confirmed
            )

            # Add the new attempt to the session and commit
            db.session.add(new_attempt)
            db.session.commit()

            return jsonify({'message': 'New attempt initiated. Expiry date reset.'}), 200

    return jsonify({'error': 'Cannot initiate resit'}), 400
