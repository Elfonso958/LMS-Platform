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

def create_app():
    """Application Factory"""

    # Load environment variables from .env file
    load_dotenv()

    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    @app.context_processor
    def inject_config():
        return dict(config=app.config)

    # 🔁 Load config from environment variable (default to dev)
    config_name = os.getenv('FLASK_CONFIG', 'config.dev')
    app.config.from_object(config_name)
    app.config['FLASK_CONFIG'] = config_name

    # Initialize extensions
    db.init_app(app)
    mail.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)

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


    app.context_processor(inject_nav_structure)
    #scheduler.init_app(app)
    #scheduler.start()
    with app.app_context():
        for rule in app.url_map.iter_rules():
            if 'delete' in str(rule):
                print(f"{rule.endpoint} => {rule.methods} => {rule.rule}")
                        
    with app.app_context():
        for rule in app.url_map.iter_rules():
            print(rule)
    return app

def inject_nav_structure():
    def get_nav_for_user(user):
        if not user.is_authenticated:
            return []

        role_ids = [r.roleID for r in user.roles]
        valid_endpoints = current_app.view_functions.keys()

        # Admin sees all
        if user.is_admin:
            allowed_items = NavItem.query.all()
        else:
            allowed_items = db.session.query(NavItem).outerjoin(NavItemPermission).filter(
                (NavItemPermission.role_id.in_(role_ids)) | (NavItem.inherit_roles == True)
            ).all()

        headers = [item for item in allowed_items if item.parent_id is None]
        sorted_headers = sorted(headers, key=lambda h: h.order if h.order is not None else 9999)

        nav_structure = []
        for header in sorted_headers:
            header_roles = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=header.id)]
            show_header = user.is_admin or any(role_id in role_ids for role_id in header_roles)

            children = [c for c in allowed_items if c.parent_id == header.id]
            sorted_children = sorted(children, key=lambda c: c.order if c.order is not None else 9999)

            child_items = []
            for child in sorted_children:
                child_roles = [p.role_id for p in NavItemPermission.query.filter_by(nav_item_id=child.id)]
                # ✅ Allow if user has direct access or child is set to inherit and header grants access
                allow_child = (
                    user.is_admin
                    or any(role_id in role_ids for role_id in child_roles)
                    or (child.inherit_roles and any(role_id in role_ids for role_id in header_roles))
                )
                if child.endpoint in valid_endpoints and allow_child:
                    child_items.append({
                        "label": child.label,
                        "endpoint": child.endpoint
                    })

            if show_header or child_items:
                nav_structure.append({
                    "label": header.label,
                    "endpoint": header.endpoint if header.endpoint in valid_endpoints else None,
                    "children": child_items
                })

        return nav_structure

    return dict(user_nav_items=get_nav_for_user(current_user))
