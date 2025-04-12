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
    Generate a certificate for the user after passing the exam with a horizontal layout,
    using a background image with 50% opacity and a semi-transparent white overlay for text clarity.
    The certificate includes the exam score (bottom left), the created_at date (bottom right),
    and a signature. The certificate will be output as a single page.
    """
    from PIL import Image, ImageDraw

    # Create the user's certificates directory if it doesn't exist
    user_certificates_dir = os.path.join(current_app.root_path, 'static', 'certificates', str(user.id))
    os.makedirs(user_certificates_dir, exist_ok=True)

    # Define the certificate filename and path
    certificate_filename = f"{user.username}_{attempt.course_id}_certificate.pdf"
    certificate_path = os.path.join(user_certificates_dir, certificate_filename)

    # Set PDF parameters for a landscape A4 document (in mm)
    pdf_width_mm = 297  # width in landscape A4
    pdf_height_mm = 210  # height in landscape A4

    # Choose DPI for the background image composition (e.g., 150 DPI)
    dpi = 150
    pdf_width_inch = pdf_width_mm / 25.4
    pdf_height_inch = pdf_height_mm / 25.4
    bg_width_px = int(pdf_width_inch * dpi)
    bg_height_px = int(pdf_height_inch * dpi)

    # Define overlay region (where text will be placed) in PDF mm units
    overlay_margin_mm = 30  # left/right margin for the overlay area
    overlay_y_mm = 30       # top y-coordinate of the overlay area
    overlay_width_mm = pdf_width_mm - 2 * overlay_margin_mm
    overlay_height_mm = 100  # height of the overlay area

    # Convert overlay region from mm to pixels for the composed background image
    overlay_margin_px = int((overlay_margin_mm / pdf_width_mm) * bg_width_px)
    overlay_y_px = int((overlay_y_mm / pdf_height_mm) * bg_height_px)
    overlay_width_px = int((overlay_width_mm / pdf_width_mm) * bg_width_px)
    overlay_height_px = int((overlay_height_mm / pdf_height_mm) * bg_height_px)

    #########################################################
    # 1. Process the background logo image using Pillow
    #########################################################
    # Build the logo image path (adjust if necessary)
    logo_path = os.path.join(
        os.path.dirname(current_app.root_path),
        'static',
        'images',
        'ACLogos',
        'AC LOGO Suite 2022',
        'AC Logo Suite.jpg'
    )
    if not os.path.exists(logo_path):
        raise FileNotFoundError(f"Logo file not found: {logo_path}")

    # Open the logo image and convert to RGBA for transparency processing
    logo_img = Image.open(logo_path).convert("RGBA")
    # Resize the logo image to cover the entire background
    logo_img = logo_img.resize((bg_width_px, bg_height_px))
    
    # Create a fully opaque white image of the same size
    white_img = Image.new("RGBA", (bg_width_px, bg_height_px), (255, 255, 255, 255))
    # Blend the white image and the logo to get a 50% opacity effect for the logo
    blended_bg = Image.blend(white_img, logo_img, 0.5)

    #########################################################
    # 2. Create a semi-transparent white overlay using Pillow
    #########################################################
    # Create an overlay image that is initially fully transparent
    overlay = Image.new("RGBA", (bg_width_px, bg_height_px), (255, 255, 255, 0))
    draw = ImageDraw.Draw(overlay)
    # Define a white color with 80% opacity (alpha=204 out of 255)
    overlay_color = (255, 255, 255, 204)
    # Draw the overlay rectangle in the region computed above
    draw.rectangle(
        [overlay_margin_px, overlay_y_px, overlay_margin_px + overlay_width_px, overlay_y_px + overlay_height_px],
        fill=overlay_color
    )

    # Composite the overlay onto the blended background
    final_bg = Image.alpha_composite(blended_bg, overlay)
    # Save the composited background image as a temporary PNG file
    temp_bg_path = os.path.join(user_certificates_dir, "temp_bg.png")
    final_bg.save(temp_bg_path)

    #########################################################
    # 3. Create the PDF and add the composed background image
    #########################################################
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.add_page()
    pdf.set_auto_page_break(auto=False)  # Disable auto page breaks to enforce single page

    # Add the processed background image (it will be stretched to full page dimensions)
    pdf.image(temp_bg_path, x=0, y=0, w=pdf.w, h=pdf.h)

    #########################################################
    # 4. Add certificate text on top of the background
    #########################################################
    pdf.set_text_color(0, 0, 128)  # dark blue text for contrast
    pdf.set_font("Arial", "B", 24)
    pdf.set_y(overlay_y_mm + 10)
    pdf.cell(0, 20, "Certificate of Achievement", ln=True, align='C')

    pdf.ln(5)
    pdf.set_font("Arial", "", 16)
    pdf.cell(0, 10, f"This certifies that {user.username}", ln=True, align='C')

    pdf.ln(5)
    pdf.cell(0, 10, "has successfully completed the course:", ln=True, align='C')

    pdf.ln(5)
    pdf.cell(0, 10, f"{attempt.course.title}", ln=True, align='C')

    pdf.ln(5)
    pdf.cell(0, 10, "Congratulations!", ln=True, align='C')

    #########################################################
    # 5. Add bottom details: score, created date, and signature
    #########################################################
    # Use the created_at attribute for the certificate date
    created_date = getattr(attempt, 'created_at', None)
    if created_date is None:
        created_date = datetime.now()
    formatted_date = created_date.strftime("%B %d, %Y")

    pdf.set_font("Arial", "", 12)
    # Add score in the bottom left
    score_text = f"Score: {attempt.score}%"
    left_margin = 10
    pdf.text(left_margin, pdf.h - 20, score_text)

    # Add the created date in the bottom right
    date_text = f"Issued on: {formatted_date}"
    right_margin = 10
    pdf.set_xy(0, pdf.h - 20)
    pdf.cell(pdf.w - right_margin, 10, date_text, align='R')

    # Add signature image above the bottom details
    signature_path = os.path.join(
        os.path.dirname(current_app.root_path),
        'static',
        'images',
        'ACLogos',
        'AC LOGO Suite 2022',
        'craig_sig.jpg'  # Adjust the extension if needed
    )
    if not os.path.exists(signature_path):
        raise FileNotFoundError(f"Signature file not found: {signature_path}")

    # Determine signature image dimensions, preserving aspect ratio
    sig_width = 50  # mm
    sig_img = Image.open(signature_path)
    sig_aspect = sig_img.height / sig_img.width
    sig_height = sig_width * sig_aspect

    sig_x = (pdf.w - sig_width) / 2
    sig_y = pdf.h - 20 - sig_height - 10  # positioned above the bottom texts

    pdf.image(signature_path, x=sig_x, y=sig_y, w=sig_width)

    #########################################################
    # 6. Output the PDF and clean up temporary files
    #########################################################
    pdf.output(certificate_path)
    os.remove(temp_bg_path)

    # Save the certificate path in the database and commit
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