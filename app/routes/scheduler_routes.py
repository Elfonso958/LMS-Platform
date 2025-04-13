from flask import Blueprint, jsonify
from flask_login import login_required
from app.email_utils import send_course_reminders
from app.services.envision_api import fetch_and_update_qualifications, fetch_and_update_roles

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
