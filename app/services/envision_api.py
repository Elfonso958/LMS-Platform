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

ENVISION_URL = "https://envision.airchathams.co.nz:8790/v1"
EMPLOYEE_CACHE = TTLCache(maxsize=1000, ttl=3600)  # Stores up to 1000 employees, expires in 1 hour

######################################
### Assign Role Based from Envision###
######################################
def fetch_and_assign_user_roles(user):
    print("Starting fetch_and_assign_user_roles function")  # Debugging: Function start
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")  # Debugging: Missing auth token
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    # Ensure the employee_id is correctly set
    if not user.employee_id:
        print(f"User {user.username} does not have an employee_id set.")
        return None

    url = f'{ENVISION_URL}/Employees/{user.employee_id}/Skills'
    print(f"Sending request to URL: {url}")  # Debugging: Log the URL
    print(f"With headers: {headers}")  # Debugging: Log the headers

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"Fetched data: {data}")  # Debugging: Log the fetched data
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        print(f"Existing roles: {existing_roles.keys()}")  # Debugging: Log existing roles
        
        # Track roles fetched from Envision
        envision_roles = set()

        for skill in data:
            role_name = skill.get('skill')  # Correctly fetch the skill description
            if not role_name:
                print(f"Skipping skill with no description: {skill}")  # Debugging: Skipping skill
                continue
            
            envision_roles.add(role_name)
            
            if role_name not in existing_roles:
                # Create a new role if it doesn't exist
                role = RoleType(role_name=role_name, role_description=role_name, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
                print(f"Created new role: {role_name}")  # Debugging: Created new role
            else:
                role = existing_roles[role_name]
                print(f"Using existing role: {role_name}")  # Debugging: Using existing role
            
            # Assign role to user
            if role not in user.roles:
                user.roles.append(role)
                print(f"Assigned role {role.role_name} to user {user.username}")  # Debugging: Assigned role

        # Remove roles that are no longer present in Envision and were pulled from Envision
        for role in user.roles[:]:
            if role.pulled_from_envision and role.role_name not in envision_roles:
                user.roles.remove(role)
                print(f"Removed role {role.role_name} from user {user.username}")  # Debugging: Removed role
        
        db.session.commit()
        print(f"Committed roles to user {user.username}")  # Debugging: Committed roles
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")  # Debugging: Failed to fetch data
        print(f"Response content: {response.text}")  # Debugging: Log the response content
        return None
    
def fetch_flights_from_envision(date_from, date_to, auth_token):
    """Fetch flights from Envision API."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    params = {"dateFrom": date_from, "dateTo": date_to}
    
    response = requests.get(f"{ENVISION_URL}/Flights", headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching flights: {response.text}")
        return []

def fetch_crew_from_envision(flight_id, auth_token):
    """Fetch crew assigned to a flight."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = requests.get(f"{ENVISION_URL}/Flights/{flight_id}/Crew", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching crew for flight {flight_id}: {response.text}")
        return []

def fetch_employee_name(employee_id, auth_token):
    """Fetch an employee's name using their ID."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    response = requests.get(f"{ENVISION_URL}/Employees/{employee_id}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching employee {employee_id}: {response.text}")
        return None

def fetch_all_employees(auth_token):
    """Fetch all employees and store in cache."""
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(f"{ENVISION_URL}/Employees", headers=headers)
    
    if response.status_code == 200:
        employees = response.json()
        for emp in employees:
            EMPLOYEE_CACHE[emp["id"]] = {"firstName": emp["firstName"], "surname": emp["surname"]}
        print(f"✅ Cached {len(employees)} employees")
    else:
        print(f"❌ Error fetching employees: {response.text}")

def fetch_and_update_qualifications():
    
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Employees/Qualifications', headers=headers)
    if response.status_code == 200:
        data = response.json()
        for employee in data:
            employee_no = employee['employeeNo']
            user = User.query.filter_by(crew_code=employee_no).first()
            if user:
                for qual in employee['qualifications']:
                    qualification_id = qual['qualificationId']
                    qualification = Qualification.query.filter_by(employee_id=user.id, qualification_id=qualification_id).first()
                    if not qualification:
                        qualification = Qualification(
                            employee_id=user.id,  # Store the user's ID
                            qualification_id=qualification_id,
                            qualification=qual['qualification'],
                            valid_from=datetime.strptime(qual['validFrom'], '%Y-%m-%dT%H:%M:%S'),
                            valid_to=datetime.strptime(qual['validTo'], '%Y-%m-%dT%H:%M:%S') if qual['validTo'] else None
                        )
                        db.session.add(qualification)
                    else:
                        qualification.qualification = qual['qualification']
                        qualification.valid_from = datetime.strptime(qual['validFrom'], '%Y-%m-%dT%H:%M:%S')
                        qualification.valid_to = datetime.strptime(qual['validTo'], '%Y-%m-%dT%H:%M:%S') if qual['validTo'] else None
        db.session.commit()
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None

def fetch_and_update_user_roles():
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Employees/Skills', headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"Fetched data: {data}")  # Log the fetched data
        
        # Clear existing employee skills
        EmployeeSkill.query.delete()
        db.session.commit()
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        
        for skill in data:
            print(f"Processing skill: {skill}")  # Log each skill item
            role_name = skill.get('skill')
            role_description = skill.get('skill')
            employee_id = skill.get('employeeId')
            skill_id = skill.get('skillId')
            valid = skill.get('valid')
            priority = skill.get('priority')
            
            if not role_name or not employee_id:
                print(f"Skipping skill due to missing role_name or employee_id: {skill}")
                continue
            
            # Store the employee skill
            employee_skill = EmployeeSkill(
                employee_id=employee_id,
                skill_id=skill_id,
                description=role_description,
                valid=valid,
                priority=priority
            )
            db.session.add(employee_skill)
            print(f"Stored employee skill: {employee_skill}")
            
            if role_name not in existing_roles:
                role = RoleType(role_name=role_name, role_description=role_description, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
                print(f"Created new role: {role}")
            else:
                role = existing_roles[role_name]
                role.role_description = role_description  # Update the description if it exists
                role.pulled_from_envision = True  # Update the flag if the role is from Envision
                print(f"Updated existing role: {role}")
            
            # Assign role to user
            user = User.query.filter_by(employee_id=employee_id).first()  # Match employee_id with User.employee_id
            if user and role not in user.roles:
                user.roles.append(role)
                print(f"Assigned role {role.role_name} to user {user.username}")
        
        db.session.commit()
        print("Data committed to the database.")
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None

def fetch_and_update_roles():
    auth_token = session.get('auth_token')
    if not auth_token:
        print("Auth token is missing.")
        return None

    headers = {
        'Authorization': f'Bearer {auth_token}'
    }

    response = requests.get(ENVISION_URL + '/Skills', headers=headers)
    if response.status_code == 200:
        data = response.json()
        
        # Fetch all existing roles
        existing_roles = {role.role_name: role for role in RoleType.query.all()}
        
        # Track roles found in the Envision API response
        roles_found_in_envision = set()
        
        for skill in data:
            role_name = skill['skill']
            role_description = skill['description']
            roles_found_in_envision.add(role_name)
            if role_name not in existing_roles:
                role = RoleType(role_name=role_name, role_description=role_description, pulled_from_envision=True)
                db.session.add(role)
                db.session.flush()  # Ensure the role ID is generated
                existing_roles[role_name] = role
            else:
                role = existing_roles[role_name]
                role.role_description = role_description  # Update the description if it exists
                role.pulled_from_envision = True  # Update the flag if the role is from Envision
        
        # Delete roles that are not found in the Envision API response and have pulled_from_envision set to True
        for role_name, role in existing_roles.items():
            if role_name not in roles_found_in_envision and role.pulled_from_envision:
                db.session.delete(role)
        
        db.session.commit()
        return data  # Return the fetched data
    else:
        print(f"Failed to fetch data from API. Status code: {response.status_code}")
        return None