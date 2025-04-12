from sqlalchemy.orm import joinedload
from flask_mail import Message
from app.models import Course, RoleType, UserSlideProgress, UserExamAttempt, Questions, Answers, UserAnswer, course_role, User, db, PayrollInformation, CrewCheck, CrewCheckMeta, CheckItem, user_role, CheckItemGrade, LineTrainingForm, Task, TaskCompletion, Topic, LineTrainingItem, UserLineTrainingForm, Sector, Qualification, EmailConfig
from app import create_app, db, mail
from threading import Thread
import textwrap
from datetime import datetime, timedelta
import pdfkit
from flask import render_template
import json


# Define when reminders should be sent
REMINDER_DAYS = {60, 30, 15, 10, 5, 4, 3, 2, 1, 0}  # Reminder Days to send course expiry emails to users
BASE_COURSE_URL = "http://127.0.0.1:5000/course/"
path_wkhtmltopdf = r'C:\Users\Jayden\OneDrive - Air Chathams Ltd\Desktop\LMS Platform\wkhtmltopdf.exe'

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email_to_training_team(mail, app, form_id, total_sectors, total_hours):
    try:
        # Fetch email configuration
        config = EmailConfig.query.first()
        if not config:
            app.logger.warning("Email configuration not found.")
            return

        # Define the thresholds
        thresholds = set(config.get_line_training_thresholds())

        # Check if the current total sectors match any threshold
        if total_sectors not in thresholds:
            app.logger.info(f"Total sectors {total_sectors} does not match any threshold. Email not sent.")
            return

        # Fetch the form with eager-loaded topics and tasks
        form = UserLineTrainingForm.query.options(
            joinedload(UserLineTrainingForm.topics).joinedload(Topic.tasks)
        ).get(form_id)

        if not form:
            app.logger.warning(f"No form found with ID {form_id}. Email not sent.")
            return

        # Fetch the form name
        form_name = form.template.name if form.template and form.template.name else "Unknown Form"

        # Fetch the candidate's name
        candidate_name = form.user.username if form.user and form.user.username else "Unknown Candidate"

        # Fetch training team emails based on role IDs
        role_ids = config.get_line_training_roles()
        if not role_ids:
            app.logger.warning("No role IDs found for Training Team.")
            return

        training_team_users = User.query.join(User.roles).filter(RoleType.roleID.in_(role_ids)).all()
        recipients = [user.email for user in training_team_users if user.email]
        if not recipients:
            app.logger.warning("No email recipients found for Training Team.")
            return

        # Calculate percentage completed for topics
        topic_details = []
        for topic in form.topics:
            total_tasks = len(topic.tasks)
            completed_tasks = sum(
                1 for task in topic.tasks if len(task.completions.all()) > 0
            )
            percentage = round((completed_tasks / total_tasks * 100), 2) if total_tasks > 0 else 0
            topic_details.append(f"<li><strong>{topic.name}</strong>: {percentage}% completed</li>")

        # Fetch completed sectors
        completed_sectors = Sector.query.filter_by(form_id=form_id).all()
        sector_list = "".join(
            [
                f"<li>{sector.dep} to {sector.arr} on {sector.date.strftime('%d-%m-%Y')}</li>"
                for sector in completed_sectors
            ]
        )

        # Prepare email content
        topic_summary = "".join(topic_details)

        # If 20 sectors are completed, modify the email content
        if total_sectors == 20:
            subject = f"{candidate_name} - {form_name} Ready for Supervisor Release"
            body = f"""
            <html>
            <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                }}
                .header {{
                    background-color: #f8d7da;
                    color: #721c24;
                    padding: 10px;
                    border: 1px solid #f5c6cb;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .summary {{
                    margin-bottom: 20px;
                }}
                .summary strong {{
                    color: #343a40;
                }}
                .topics, .sectors {{
                    margin-bottom: 20px;
                }}
                .topics ul, .sectors ul {{
                    list-style-type: none;
                    padding: 0;
                }}
                .topics li, .sectors li {{
                    background-color: #f1f3f5;
                    margin: 5px 0;
                    padding: 10px;
                    border-radius: 5px;
                }}
                .release-button {{
                    display: inline-block;
                    padding: 10px 20px;
                    font-size: 16px;
                    font-weight: bold;
                    color: white;
                    background-color: #28a745;
                    text-align: center;
                    border-radius: 5px;
                    text-decoration: none;
                }}
                .release-button:hover {{
                    background-color: #218838;
                }}
            </style>
            </head>
            <body>
            <div class="header">
                <h2>{candidate_name} - {form_name} Ready for Supervisor Release</h2>
            </div>
            <div class="summary">
                <p><strong>Total Sectors:</strong> {total_sectors}</p>
                <p><strong>Total Hours:</strong> {total_hours:.2f}</p>
            </div>
            <div class="topics">
                <h3>Topic Progress</h3>
                <ul>
                    {topic_summary}
                </ul>
            </div>
            <div class="sectors">
                <h3>Completed Sectors</h3>
                <ul>
                    {sector_list}
                </ul>
            </div>
            <p>The candidate has completed 20 sectors and is now ready for supervisor release.</p>
            <p><a href="{app.config['BASE_URL']}/confirm_release/{form_id}" class="release-button">Review & Release Candidate</a></p>
            </body>
            </html>
            """        
        else:
            subject = f"{candidate_name} - {form_name} Update"
            body = f"""
            <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                    }}
                    .header {{
                        background-color: #f8d7da;
                        color: #721c24;
                        padding: 10px;
                        border: 1px solid #f5c6cb;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }}
                    .summary {{
                        margin-bottom: 20px;
                    }}
                    .summary strong {{
                        color: #343a40;
                    }}
                    .topics, .sectors {{
                        margin-bottom: 20px;
                    }}
                    .topics ul, .sectors ul {{
                        list-style-type: none;
                        padding: 0;
                    }}
                    .topics li, .sectors li {{
                        background-color: #f1f3f5;
                        margin: 5px 0;
                        padding: 10px;
                        border-radius: 5px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h2>{candidate_name} - {form_name} Update</h2>
                </div>
                <div class="summary">
                    <p><strong>Total Sectors:</strong> {total_sectors}</p>
                    <p><strong>Total Hours:</strong> {total_hours:.2f}</p>
                </div>
                <div class="topics">
                    <h3>Topic Progress</h3>
                    <ul>
                        {topic_summary}
                    </ul>
                </div>
                <div class="sectors">
                    <h3>Completed Sectors</h3>
                    <ul>
                        {sector_list}
                    </ul>
                </div>
                <p>Please review and take necessary action.</p>
            </body>
            </html>
            """

        msg = Message(subject, recipients=recipients, sender=app.config['MAIL_DEFAULT_SENDER'])
        msg.html = body  # Set the HTML content

        # Send email asynchronously
        Thread(target=send_async_email, args=(app, msg)).start()
        app.logger.info(f"Email queued to Training Team: {', '.join(recipients)}")
    except Exception as e:
        app.logger.error(f"Error queuing email: {str(e)}")

def Send_Release_To_Supervisor_Email(app, candidate, form_name, form_id, total_hours, total_takeoffs, total_landings, associated_roles):
    try:
        # Determine whether it's an SF34 or ATR72 form
        if "SF34" in form_name:
            primary_roles = ["SF34 Supervisor"]
        elif "ATR72" in form_name:
            primary_roles = ["ATR72 Supervisor"]
        else:
            app.logger.warning(f"Unknown form type: {form_name}")
            return

        # Always CC Training Team and Operations
        cc_roles = ["Training Team", "Operations"]

        # Fetch primary supervisors (only SF34 or ATR72 Supervisors)
        primary_supervisors = User.query.join(User.roles).filter(
            User.roles.any(RoleType.role_name.in_(primary_roles))
        ).all()
        primary_recipient_emails = [user.email for user in primary_supervisors if user.email]

        # Fetch CC recipients (Training Team and Operations)
        cc_recipients = User.query.join(User.roles).filter(
            User.roles.any(RoleType.role_name.in_(cc_roles))
        ).all()
        cc_emails = [user.email for user in cc_recipients if user.email]

        if not primary_recipient_emails:
            app.logger.warning(f"No primary recipients found for {form_name} roles: {', '.join(primary_roles)}")
            return

        # Format supervisor list properly (only SF34 or ATR72 Supervisors listed)
        supervisor_list = "\n".join(
            [f"- {user.username} ({user.email})" for user in primary_supervisors]
        )

        # Define the subject for the email
        subject = f"Candidate {candidate.username} Released - {form_name}"

        # Prepare the email body
        email_body = f"""
        The candidate {candidate.username} has been successfully released.

        Form Name: {form_name}
        Candidate Name: {candidate.username}
        Total Hours: {total_hours:.2f}
        Total Takeoffs: {total_takeoffs}
        Total Landings: {total_landings}

        Candidate can now fly with the following supervisors:

        {supervisor_list}

        Please review and take necessary action.
        """

        # Dedent the body text while preserving supervisor formatting
        body = textwrap.dedent(email_body).strip()

        # Create the email message
        msg = Message(
            subject,
            recipients=primary_recipient_emails,  # SF34 or ATR72 Supervisors
            cc=cc_emails,  # Always CC Training Team & Operations
            body=body,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )

        # Send the email
        with app.app_context():
            mail.send(msg)

        app.logger.info(f"Release email sent to: {', '.join(primary_recipient_emails)} (CC: {', '.join(cc_emails)})")
    
    except Exception as e:
        app.logger.error(f"Error sending release email: {e}")


def send_course_reminders():
    """Send course expiry reminders daily, but exclude users who no longer require the course."""
    app = create_app()
    
    with app.app_context():
        today = datetime.utcnow().date()
        print(f"[DEBUG] Running send_course_reminders on {today}")

        # Fetch email configuration
        config = EmailConfig.query.first()
        if not config:
            print("[WARNING] Email configuration not found.")
            return

        # Fetch user progress records where expiry_date is set
        progress_records = UserSlideProgress.query.filter(UserSlideProgress.expiry_date.isnot(None)).all()
        exam_attempts = UserExamAttempt.query.filter(UserExamAttempt.expiry_date.isnot(None)).all()

        # Fetch the user-defined course reminder email
        course_reminder_email = config.course_reminder_email

        def process_reminders(records, is_exam):
            for record in records:
                if not record.expiry_date:
                    continue

                days_to_expiry = (record.expiry_date.date() - today).days
                formatted_date = record.expiry_date.strftime("%A, %b %d, %Y")  # Example: "Monday, Feb 21, 2025"
                user = record.user
                course = record.course

                if not user or not course:
                    print(f"[WARNING] Missing user or course data for record ID {record.id}")
                    continue
                if not user.is_active:  # Skip inactive users
                    print(f"[INFO] Skipping {user.email} - User is archived.")
                    continue
                # Check if the user still holds a relevant role for this course
                required_roles = {role.role_name for role in course.roles}
                user_roles = {role.role_name for role in user.roles}

                if not required_roles.intersection(user_roles):  # User no longer holds any required roles
                    print(f"[INFO] Skipping email for {user.email} - No longer required to complete {course.title}")
                    continue  # Skip this user

                # Only send emails if the course is expired OR matches REMINDER_DAYS
                if days_to_expiry not in config.get_course_reminder_days() and days_to_expiry >= 0:
                    print(f"[DEBUG] Skipping {course.title} for {user.email} (Days to Expiry: {days_to_expiry})")
                    continue  # Skip sending email

                # Generate course link
                course_link = f"{BASE_COURSE_URL}{course.id}"

                # Stronger message for expired courses
                if days_to_expiry < 0:
                    subject = f"⚠️ URGENT: {course.title} Training is Overdue!"
                    body = f"""
                    <html>
                    <body>
                        <h2 style="color: red;">Your required training for {course.title} is OVERDUE!</h2>
                        <p>Dear {user.username},</p>
                        <p><strong>Immediate action is required.</strong> Your training expired <b>{abs(days_to_expiry)} days ago</b> on <b>{formatted_date}</b>.</p>
                        <p>Failure to complete this training may impact your compliance and operational status.</p>
                        <p><a href="{course_link}" style="color: white; background-color: red; padding: 10px 15px; text-decoration: none; border-radius: 5px;">📌 Click Here to Access Your Course</a></p>
                        <p>Best regards,<br>Training Team</p>
                    </body>
                    </html>
                    """
                else:
                    subject = f"Reminder: {course.title} Expiry in {days_to_expiry} days"
                    body = f"""
                    <html>
                    <body>
                        <h2>Reminder: {course.title} Expiring Soon</h2>
                        <p>Dear {user.username},</p>
                        <p>Your course will expire in <b>{days_to_expiry} days</b> on <b>{formatted_date}</b>.</p>
                        <p>To ensure compliance, please complete it before the deadline.</p>
                        <p><a href="{course_link}" style="color: white; background-color: blue; padding: 10px 15px; text-decoration: none; border-radius: 5px;">📌 Click Here to Access Your Course</a></p>
                        <p>Best regards,<br>Training Team</p>
                    </body>
                    </html>
                    """

                msg = Message(subject, recipients=[user.email], cc=[course_reminder_email], html=body)

                try:
                    mail.send(msg)
                    print(f"[INFO] Sent {'EXPIRED' if days_to_expiry < 0 else 'reminder'} email to {user.email} for {course.title} (Days to Expiry: {days_to_expiry})")
                except Exception as e:
                    print(f"[ERROR] Failed to send email to {user.email}: {e}")

        print("[DEBUG] Processing UserSlideProgress reminders...")
        process_reminders(progress_records, is_exam=False)

        print("[DEBUG] Processing UserExamAttempt reminders...")
        process_reminders(exam_attempts, is_exam=True)

        # New logic to send reminders for courses with no last completed date
        print("[DEBUG] Processing new courses reminders...")
        new_courses = Course.query.all()
        for course in new_courses:
            for user in course.users:
                if not user.is_active:
                    print(f"[INFO] Skipping {user.email} - User is archived.")
                    continue
                if user.has_completed_course(course.id):
                    print(f"[INFO] Skipping {user.email} - Course {course.title} already completed.")
                    continue

                # Generate course link
                course_link = f"{BASE_COURSE_URL}{course.id}"

                subject = f"Reminder: New Course {course.title} Available"
                body = f"""
                <html>
                <body>
                    <h2>New Course Available: {course.title}</h2>
                    <p>Dear {user.username},</p>
                    <p>A new course titled <b>{course.title}</b> is available for you to complete.</p>
                    <p>Please complete it at your earliest convenience.</p>
                    <p><a href="{course_link}" style="color: white; background-color: green; padding: 10px 15px; text-decoration: none; border-radius: 5px;">📌 Click Here to Access Your Course</a></p>
                    <p>Best regards,<br>Training Team</p>
                </body>
                </html>
                """

                msg = Message(subject, recipients=[user.email], cc=[course_reminder_email], html=body)

                try:
                    mail.send(msg)
                    print(f"[INFO] Sent new course reminder email to {user.email} for {course.title}")
                except Exception as e:
                    print(f"[ERROR] Failed to send email to {user.email}: {e}")

        print("[DEBUG] send_course_reminders() finished.")

def send_qualification_expiry_email(user, qualification, days_to_expiry, formatted_date):
    if days_to_expiry < 0:
        subject = f"⚠️ URGENT: {qualification.qualification} Qualification is Overdue!"
        body = f"""
        <html>
        <body>
            <h2 style="color: red;">Your qualification for {qualification.qualification} is OVERDUE!</h2>
            <p>Dear {user.username},</p>
            <p><strong>Immediate action is required.</strong> Your qualification expired <b>{abs(days_to_expiry)} days ago</b> on <b>{formatted_date}</b>.</p>
            <p>Failure to renew this qualification may impact your compliance and operational status.</p>
            <p>Best regards,<br>Training Team</p>
        </body>
        </html>
        """
    else:
        subject = f"Reminder: {qualification.qualification} Expiry in {days_to_expiry} days"
        body = f"""
        <html>
        <body>
            <h2>Reminder: {qualification.qualification} Expiring Soon</h2>
            <p>Dear {user.username},</p>
            <p>Your qualification will expire in <b>{days_to_expiry} days</b> on <b>{formatted_date}</b>.</p>
            <p>To ensure compliance, please renew it before the deadline.</p>
            <p>Best regards,<br>Training Team</p>
        </body>
        </html>
        """
    return subject, body

def send_qualification_reminders():
    """Send qualification expiry reminders daily."""
    app = create_app()
    
    with app.app_context():
        today = datetime.utcnow().date()
        print(f"[DEBUG] Running send_qualification_reminders on {today}")

        # Fetch qualifications where valid_to is set
        qualifications = Qualification.query.filter(Qualification.valid_to.isnot(None)).all()

        # Fetch Training Team role users
        training_team_role = RoleType.query.filter_by(role_name="Training Team").first()
        training_team_emails = [user.email for user in training_team_role.users if user.email] if training_team_role else []

        for qualification in qualifications:
            if not qualification.valid_to:
                continue

            days_to_expiry = (qualification.valid_to.date() - today).days
            formatted_date = qualification.valid_to.strftime("%A, %b %d, %Y")  # Example: "Monday, Feb 21, 2025"
            user = qualification.user

            if not user:
                print(f"[WARNING] Missing user data for qualification ID {qualification.id}")
                continue
            if not user.is_active:  # Skip inactive users
                print(f"[INFO] Skipping {user.email} - User is archived.")
                continue

            # Only send emails if the qualification is expired OR matches REMINDER_DAYS
            if days_to_expiry not in REMINDER_DAYS and days_to_expiry >= 0:
                print(f"[DEBUG] Skipping {qualification.qualification} for {user.email} (Days to Expiry: {days_to_expiry})")
                continue  # Skip sending email

            # Generate email body
            subject, body = send_qualification_expiry_email(user, qualification, days_to_expiry, formatted_date)

            msg = Message(subject, recipients=[user.email], cc=training_team_emails, html=body)

            try:
                mail.send(msg)
                print(f"[INFO] Sent {'EXPIRED' if days_to_expiry < 0 else 'reminder'} email to {user.email} for {qualification.qualification} (Days to Expiry: {days_to_expiry})")
            except Exception as e:
                print(f"[ERROR] Failed to send email to {user.email}: {e}")

        print("[DEBUG] send_qualification_reminders() finished.")

def send_crew_check_email_to_training_team(app, crew_check_meta_id):
    try:
        # Fetch email configuration
        config = EmailConfig.query.first()
        if not config:
            app.logger.warning("Email configuration not found.")
            return

        # Retrieve the crew check meta record and related data
        crew_check_meta = CrewCheckMeta.query.get(crew_check_meta_id)
        if not crew_check_meta:
            app.logger.warning(f"No crew check meta found for ID {crew_check_meta_id}.")
            return

        candidate_name = crew_check_meta.candidate.username if crew_check_meta.candidate else "Unknown Candidate"
        # Explicitly query the CrewCheck record instead of using crew_check_meta.check
        from app.models import CrewCheck  # ensure it's imported
        crew_check = CrewCheck.query.get(crew_check_meta.crew_check_id)
        crew_check_name = crew_check.name if crew_check else "Unknown Crew Check"
        date_of_test = crew_check_meta.date_of_test.strftime('%Y-%m-%d') if crew_check_meta.date_of_test else "Unknown Date"
        aircraft_type = crew_check_meta.aircraft_type or "Unknown Aircraft"
        
        # Retrieve all check items for this crew check (even if not graded)
        check_items = CheckItem.query.filter_by(crew_check_id=crew_check_meta.crew_check_id).order_by(CheckItem.order).all()

        # Build an HTML snippet that shows each check item with actual radio buttons (disabled)
        grades_html = "<ul style='list-style-type:none; padding:0;'>"
        for item in check_items:
            grade_obj = CheckItemGrade.query.filter_by(
                crew_check_meta_id=crew_check_meta.id,
                check_item_id=item.id
            ).first()
            try:
                selected = int(grade_obj.grade) if grade_obj and grade_obj.grade is not None else None
            except (ValueError, TypeError):
                selected = None

            radios = ""
            for option in range(1, 6):
                if selected == option:
                    radios += f"<label style='margin-right:10px;'><input type='radio' name='item_{item.id}' value='{option}' disabled checked> {option}</label>"
                else:
                    radios += f"<label style='margin-right:10px;'><input type='radio' name='item_{item.id}' value='{option}' disabled> {option}</label>"
            # Also include NA option
            if selected is None:
                radios += f"<label style='margin-right:10px;'><input type='radio' name='item_{item.id}' value='NA' disabled checked> NA</label>"
            else:
                radios += f"<label style='margin-right:10px;'><input type='radio' name='item_{item.id}' value='NA' disabled> NA</label>"
            grades_html += f"<li style='margin-bottom:8px;'><strong>{item.item_name}:</strong> {radios}</li>"
        grades_html += "</ul>"

        subject = f"{crew_check_name} - {candidate_name} - Expiry {crew_check_meta.next_check_due.strftime('%d-%m-%Y')}"

        body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    font-size: 14px;
                    line-height: 1.6;
                    color: #333;
                }}
                .container {{
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    background-color: #f9f9f9;
                }}
                .header {{
                    font-size: 18px;
                    font-weight: bold;
                    color: #2d6a4f;
                    margin-bottom: 10px;
                }}
                .info {{
                    margin-bottom: 10px;
                }}
                .info strong {{
                    color: #2d6a4f;
                }}
                .footer {{
                    margin-top: 20px;
                    font-size: 13px;
                    color: #555;
                }}
                .link {{
                    color: #007bff;
                    text-decoration: none;
                }}
                .link:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    {crew_check_meta.check.name if crew_check_meta.check else "Crew Check Summary"}
                </div>

                <div class="info"><strong>Candidate:</strong> {crew_check_meta.candidate.username if crew_check_meta.candidate else "Unknown Candidate"}</div>
                <div class="info"><strong>Check Name:</strong> {crew_check_meta.check.name if crew_check_meta.check else "Not Provided"}</div>
                <div class="info"><strong>Date of Test:</strong> {crew_check_meta.date_of_test.strftime('%d-%m-%Y') if crew_check_meta.date_of_test else "Unknown Date"}</div>
                <div class="info"><strong>Result:</strong> {crew_check_meta.test_result if crew_check_meta.test_result else "Not Provided"}</div>
                <div class="info"><strong>Examiner:</strong> {crew_check_meta.examiner_name if crew_check_meta.examiner_name else "Not Provided"}</div>

                <div class="footer">
                    <p>Please find the attached crew check form for your records.</p>
                    <p>Please update <strong>Envision</strong> records accordingly: <a class="link" href="https://envision.airchathams.co.nz/Envision.Web#" target="_blank">Update Records in Envision</a></p>
                </div>
            </div>
        </body>
        </html>
        """



        # Render a PDF version of the complete web form.
        # Ensure you have the template at "templates/crew_checks/crew_check_form_pdf.html"
        visible_fields = json.loads(crew_check.visible_headers or "[]")  # Add this before rendering
        form_html = render_template('crew_checks/crew_check_form_pdf.html', crew_check_meta=crew_check_meta,visible_fields=visible_fields)
        pdf_data = pdfkit.from_string(form_html, False)
        pdf_filename = f"{crew_check_meta.check.name.replace(' ', '_')}_{crew_check_meta.candidate.username.replace(' ', '_')}_{crew_check_meta.next_check_due.strftime('%d-%m-%Y') if crew_check_meta.next_check_due else 'No_Expiry'}.pdf"
        # Fetch training team emails based on your configuration.
        role_ids = config.get_line_training_roles()  # Adjust as needed.
        training_team_users = User.query.join(User.roles).filter(RoleType.roleID.in_(role_ids)).all()
        recipients = [user.email for user in training_team_users if user.email]
        print  (f"[DEBUG] Training Team Users: {training_team_users}")
        print (f"[DEBUG] Role_Ids: {role_ids}")
        if not recipients:
            app.logger.warning("No email recipients found for Training Team.")
            return

        msg = Message(subject, recipients=recipients, sender=app.config['MAIL_DEFAULT_SENDER'])
        msg.html = body
        msg.attach(pdf_filename, "application/pdf", pdf_data)

        Thread(target=send_async_email, args=(app, msg)).start()
        app.logger.info(f"Queued crew check email to Training Team: {', '.join(recipients)}")
    except Exception as e:
        app.logger.error(f"Error queuing crew check email: {str(e)}")

def send_timesheet_response(to, app, subject, body):
    """
    Sends an email notification about timesheet approval or rejection using app config settings.

    :param to: Recipient email address
    :param app: Flask application instance for context
    :param subject: Email subject line
    :param body: Email message body
    """
    try:
        with app.app_context():  # ✅ Ensure we use the correct app context
            sender_email = app.config['MAIL_DEFAULT_SENDER']

            msg = Message(subject, sender=sender_email, recipients=[to])
            msg.body = body
            mail.send(msg)
            print(f"Timesheet email sent to {to} from {sender_email}")

    except Exception as e:
        print(f"Error sending email to {to}: {e}")