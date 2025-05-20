import os
from flask import Flask, current_app, render_template, request, redirect, url_for, flash
from app.extensions import db, migrate, login_manager, mail
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_migrate import Migrate
from flask_mail import Mail
from app.models import Course, RoleType, UserSlideProgress, UserExamAttempt, Questions, Answers, UserAnswer, course_role, User, db, PayrollInformation, CrewCheck, CrewCheckMeta, CheckItem, user_role,CheckItemGrade, LineTrainingForm, Location, Port, HandlerFlightMap, GroundHandler, CrewAcknowledgement
from app.models import Task,TaskCompletion,Topic, LineTrainingItem,UserLineTrainingForm, Sector, RosterChange, Flight, FormTemplate,RoutePermission,Qualification,EmployeeSkill, EmailConfig, JobTitle, Timesheet, Location, PayrollPeriod,PayrollInformation, NavItem, NavItemPermission # Import your models and database session
from dotenv import load_dotenv
from app.scheduler import scheduler
from flask import g
from app.scheduler_jobs import medical_alerts
from datetime import datetime
from app.utils import format_ddmmyyyy, format_human_date

def create_app():
    """Application Factory"""

    # Decide which env/config to load
    flask_env = os.getenv('FLASK_ENV', 'development').lower()
    if flask_env == 'production':
        load_dotenv('.env.prod', override=False)
        config_name = 'config.prod'
    else:
        load_dotenv('.env.dev',  override=False)
        config_name = 'config.dev'

    app = Flask(__name__, template_folder='../templates', static_folder='../static')
    app.config.from_object(config_name)
    app.config['FLASK_CONFIG'] = config_name

    # Jinja filters   
    app.jinja_env.filters['human_date'] = format_human_date
    app.jinja_env.filters['format_ddmmyyyy'] = format_ddmmyyyy

    @app.context_processor
    def inject_config():
        return dict(config=app.config)  
      
    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login" 

    @login_manager.user_loader
    def load_user(user_id):
        user = User.query.get(int(user_id))
        if user:
            # Fetch employee skills for the user
            employee_skills = EmployeeSkill.query.filter_by(employee_id=user.crew_code).all()
            for skill in employee_skills:
                role = RoleType.query.filter_by(role_name=skill.description).first()
                if role and role not in user.roles:
                    user.roles.append(role)
            db.session.commit()
        return user
    
    @app.before_request
    def load_crew_checks():
        if current_user.is_authenticated:
            user_roles = [role.role_name for role in current_user.roles]
            g.crew_checks = CrewCheck.query.filter(
                CrewCheck.roles.any(RoleType.role_name.in_(user_roles))
            ).all()
        else:
            g.crew_checks = []

    # Define upload folder for course PowerPoints
    upload_folder = os.path.join(os.getcwd(), 'Course_Powerpoints')
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_folder

    # Register models (imported here to avoid circular imports)
    with app.app_context():
        from . import models

    # ✅ Register blueprints
    from app.routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.user_routes import user_bp
    app.register_blueprint(user_bp)

    from app.routes.api_routes import api_bp
    app.register_blueprint(api_bp)

    from app.routes.admin_routes import admin_bp
    app.register_blueprint(admin_bp)

    from app.routes.roster_routes import roster_bp
    app.register_blueprint(roster_bp)

    from app.routes.flight_operations_routes import flightops_bp
    app.register_blueprint(flightops_bp)

    from app.routes.course_routes import course_bp 
    app.register_blueprint(course_bp)

    from app.routes.Crew_Line_Training_Routes import linetraining_bp 
    app.register_blueprint(linetraining_bp)

    from app.routes.crew_checks_route import crew_checks_bp 
    app.register_blueprint(crew_checks_bp)

    from app.routes.reports_routes import reports_bp 
    app.register_blueprint(reports_bp)

    from app.routes.payroll_routes import payroll_bp 
    app.register_blueprint(payroll_bp)

    from app.routes.scheduler_routes import scheduler_bp
    app.register_blueprint(scheduler_bp)

    from app.routes.company_structure_routes import company_bp
    app.register_blueprint(company_bp)

    from app.routes.hr_rotues import hr_bp
    app.register_blueprint(hr_bp)

    from app.routes.document_routes import document_bp
    app.register_blueprint(document_bp)

    app.context_processor(inject_nav_structure)
    #scheduler.init_app(app)
    #scheduler.start()
    
    return app

def inject_nav_structure():
    def get_nav_for_user(user):
        if not user.is_authenticated:
            return []

        role_ids = [r.roleID for r in user.roles]
        job_title_id = user.job_title_id
        valid_endpoints = current_app.view_functions.keys()

        # Gather all nav items allowed via role or job title
        permissions = NavItemPermission.query.filter(
            (NavItemPermission.role_id.in_(role_ids)) |
            (NavItemPermission.job_title_id == job_title_id)
        ).all()

        allowed_nav_ids = {p.nav_item_id for p in permissions}

        def is_allowed(nav_id):
            return nav_id in allowed_nav_ids

        headers = NavItem.query.filter_by(parent_id=None).order_by(NavItem.order).all()

        nav_structure = []
        for header in headers:
            if not (is_allowed(header.id) or user.is_admin):
                continue

            children = []
            for child in sorted(header.children, key=lambda c: c.order or 0):
                # Get permissions for this child
                child_perms = NavItemPermission.query.filter_by(nav_item_id=child.id).all()
                child_roles = [p.role_id for p in child_perms if p.role_id is not None]
                child_jobs  = [p.job_title_id for p in child_perms if p.job_title_id is not None]

                allow_child = (
                    user.is_admin
                    or any(rid in role_ids for rid in child_roles)
                    or (job_title_id and job_title_id in child_jobs)
                    or (
                        child.inherit_roles and is_allowed(header.id)
                    )
                )

                if child.endpoint in valid_endpoints and allow_child:
                    children.append({
                        "label": child.label,
                        "endpoint": child.endpoint
                    })

            nav_structure.append({
                "label": header.label,
                "endpoint": header.endpoint if header.endpoint in valid_endpoints else None,
                "children": children
            })

        # ✅ Debug output to confirm what's visible
        print("=== FINAL NAV STRUCTURE ===")
        import pprint
        pprint.pprint(nav_structure)

        return nav_structure

    return dict(user_nav_items=get_nav_for_user(current_user))
