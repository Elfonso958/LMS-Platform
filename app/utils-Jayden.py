from functools import wraps
from flask import redirect, url_for, flash, current_app
from flask_login import current_user
from pptx import Presentation
from PIL import Image, ImageDraw
from fpdf import FPDF
import shutil
from comtypes.client import CreateObject
import os, re
import pythoncom
from app.models import Questions, Answers, Course
from app import db
from flask import abort

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('landing'))
        return func(*args, **kwargs)
    return decorated_view

def extract_slides_to_png(ppt_path, output_folder):
    """Extract slides from a PowerPoint file as PNG images."""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Initialize COM
    pythoncom.CoInitialize()

    try:
        # Start PowerPoint application using COM
        powerpoint = CreateObject("PowerPoint.Application")
        powerpoint.Visible = 1  # Ensure PowerPoint runs in the background

        # Open the PowerPoint presentation
        presentation = powerpoint.Presentations.Open(ppt_path, WithWindow=False)

        # Iterate through all slides and export them to PNG
        for i, slide in enumerate(presentation.Slides):
            # Set the output file path for each slide
            slide_filename = os.path.join(output_folder, f"slide_{i + 1}.png")

            # Export slide to PNG
            slide.Export(slide_filename, "PNG")

        # Close the presentation after all slides are exported
        presentation.Close()

    finally:
        # Clean up COM resources
        powerpoint.Quit()
        pythoncom.CoUninitialize()

def generate_certificate(user, attempt):
    """
    Generate a certificate for the user after passing the exam.
    :param user: The user object
    :param attempt: The UserExamAttempt object
    :return: The path of the generated certificate file
    """
    # Create the user's profile directory if it doesn't exist
    user_certificates_dir = os.path.join(current_app.root_path, 'static', 'certificates', str(user.id))
    os.makedirs(user_certificates_dir, exist_ok=True)

    # Path for the certificate file
    certificate_filename = f"{user.username}_{attempt.course_id}_certificate.pdf"
    certificate_path = os.path.join(user_certificates_dir, certificate_filename)

    # Create a PDF certificate
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=16)
    
    # Add certificate content
    pdf.cell(200, 10, txt="Certificate of Achievement", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"This certifies that {user.username}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"has successfully completed the course: {attempt.course.title}", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Score: {attempt.score}%", ln=True, align='C')
    
    pdf.ln(20)
    pdf.cell(200, 10, txt="Congratulations!", ln=True, align='C')

    # Save the PDF
    pdf.output(certificate_path)

    # Save the certificate path in the database
    attempt.certificate_path = certificate_path
    db.session.commit()

    return certificate_path

def calculate_exam_score(course_id, submitted_answers):
    course = Course.query.get_or_404(course_id)
    passing_percentage = course.passing_percentage or 70.0  # Default to 70% if None

    # Fetch all questions for the course
    questions = Questions.query.filter_by(course_id=course_id).all()

    if not questions:
        return 0.0, False  # No questions means no score

    total_questions = len(questions)
    correct_answers = 0

    # Compare submitted answers with correct ones
    for question in questions:
        correct_answer = next((answer for answer in question.answers if answer.is_correct), None)
        if correct_answer and submitted_answers.get(question.id) == correct_answer.id:
            correct_answers += 1

    # Calculate score
    score = (correct_answers / total_questions) * 100
    passed = score >= passing_percentage

    return score, passed

# Natural sorting helper function
def natural_sort_key(path):
    base_name = os.path.basename(path)  # Get the filename
    numeric_part = re.findall(r'\d+', base_name)  # Extract numeric parts
    return int(numeric_part[0]) if numeric_part else base_name

def get_slide_count(course_id):
    # Path to the slide directory for the course
    slides_folder = os.path.join(current_app.static_folder, f"Course_Powerpoints/slides_{course_id}")
    if not os.path.exists(slides_folder):
        return 0  # No slides found
    
    # Count PNG files in the directory
    slide_files = [f for f in os.listdir(slides_folder) if f.endswith('.png')]
    return len(slide_files)

def roles_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("You need to be logged in to access this page.", "danger")
                return redirect(url_for('login'))
            
            user_roles = [role.role_name for role in current_user.roles]

            if not any(role in user_roles for role in roles):
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for('user_dashboard'))
            
            return f(*args, **kwargs)
        return decorated_function
    return wrapper