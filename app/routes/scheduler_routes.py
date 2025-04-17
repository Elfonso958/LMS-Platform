from flask import Blueprint, jsonify, render_template
from flask_login import login_required
from app.email_utils import send_course_reminders
from app.services.envision_api import fetch_and_update_qualifications, fetch_and_update_roles
from datetime import datetime, timedelta

scheduler_bp = Blueprint("scheduler", __name__)

@scheduler_bp.route('/send_email', methods=['GET'])
@login_required
def send_email():
    try:
        send_course_reminders()
        return jsonify({"message": "Course reminders sent successfully."}), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@scheduler_bp.route('/fetch_update_roles', methods=['GET'])
@login_required
def fetch_update_roles():
    try:
        fetch_and_update_qualifications()
        fetch_and_update_roles()
        return jsonify({"message": "Qualifications and roles updated successfully."}), 200
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    
@scheduler_bp.route('/send_medical_expiry_alerts', methods=['GET'])
@login_required
def send_medical_expiry_alerts():
    from app.models import User, EmailConfig
    from app.email_utils import send_email
    from itertools import chain
    from sqlalchemy import func

    config = EmailConfig.query.first()
    if not config:
        return jsonify({"message": "Email config not found."}), 400

    days_list = list(map(int, (config.medical_expiry_days or "30").split(",")))

    users_due = list(chain.from_iterable(
        User.query.filter(
            User.medical_expiry != None,
            func.date(User.medical_expiry) == (datetime.utcnow().date() + timedelta(days=day))
        ).all()
        for day in days_list
    ))

    if not users_due:
        return jsonify({"message": f"No users with medical expiry in next {', '.join(map(str, days_list))} days."})

    count = 0
    for user in users_due:
        if not user.email:
            continue

        html_body = render_template(
            'emails/medical_expiry_user_reminder.html',
            user=user
        )

        send_email(
            subject="Reminder: Medical Certificate Expiry",
            recipients=[user.email],
            html=html_body
            # You can also add: cc=[config.medical_expiry_email] if you want a copy
        )
        count += 1

    return jsonify({"message": f"Sent reminders to {count} user(s)."})