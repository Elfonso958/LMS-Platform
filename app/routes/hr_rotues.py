from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from app import db, mail
from flask_mail import Message
from app.models import User, HRTaskTemplate, UserHRTask, RecruitmentRequest, Location, Department, EmploymentType, JobTitle, RoleType, DocumentType, RecruitmentType
from app.utils import admin_required
from app.utils_file.hr import assign_hr_tasks_for_job_title
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
from email_utils import send_hr_task_email
hr_bp = Blueprint("hr", __name__)


@hr_bp.route('/start_onboarding/<int:user_id>', methods=['POST'])
@login_required
def start_onboarding(user_id):
    user = User.query.get_or_404(user_id)

    task_templates = (
        HRTaskTemplate.query
        .filter(HRTaskTemplate.phase == "onboarding", HRTaskTemplate.is_active == True)
        .join(HRTaskTemplate.assigned_job_titles)
        .filter(JobTitle.id == user.job_title_id)
        .all()
    )

    for template in task_templates:
        # Calculate due_date based on timing
        due_date = None
        if user.onboarding_start_date:
            if template.timing == "before":
                due_date = user.onboarding_start_date - timedelta(days=template.days_before or 0)
            elif template.timing == "after":
                due_date = user.onboarding_start_date + timedelta(days=template.days_before or 0)

        task = UserHRTask(
            user_id=user.id,
            task_template_id=template.id,
            status="Pending",
            due_date=due_date
        )
        db.session.add(task)

        recipient_email = (
            template.responsible_email
            or (template.responsible_job_title.manager.email if template.responsible_job_title and template.responsible_job_title.manager else None)
        )

        if recipient_email:
            msg = Message(
                subject=f"[Onboarding] Action Required: {template.name} for {user.username}",
                recipients=[recipient_email],
                html=render_template("emails/hr_task_notify.html", user=user, task_template=template)
            )
            mail.send(msg)

    db.session.commit()
    
    flash(f"Onboarding tasks created for {user.username}", "success")
    return redirect(url_for('admin.manage_users'))

@hr_bp.route('/create_hr_task', methods=['POST'])
def create_hr_task():
    name = request.form.get('name')
    phase = request.form.get('phase')
    timing = request.form.get('timing')
    days_before = request.form.get('days_before')
    description = request.form.get('description')
    responsible_job_title_id = request.form.get('responsible_job_title_id')
    responsible_email = request.form.get('responsible_email')
    assigned_ids = request.form.getlist('assigned_job_title_ids')

    if not name or not phase or not assigned_ids:
        flash('Please fill in all required fields.', 'danger')
        return redirect(request.referrer or url_for('hr.manage_hr_tasks'))

    # Create the new template
    new_task = HRTaskTemplate(
        name=name,
        phase=phase,
        timing=timing,
        days_before=int(days_before) if days_before else 0,
        description=description,
        responsible_job_title_id=int(responsible_job_title_id) if responsible_job_title_id else None,
        responsible_email=responsible_email
    )

    # Assign job titles (many-to-many)
    job_titles = JobTitle.query.filter(JobTitle.id.in_(assigned_ids)).all()
    new_task.assigned_job_titles.extend(job_titles)

    db.session.add(new_task)
    db.session.commit()

    flash('Task template created successfully!', 'success')
    return redirect(url_for('hr.manage_hr_tasks'))


@hr_bp.route('/sign_off_task/<int:user_id>/<int:task_template_id>', methods=['GET', 'POST'])
def sign_off_task(user_id, task_template_id):
    task = UserHRTask.query.filter_by(user_id=user_id, task_template_id=task_template_id).first_or_404()

    if request.method == 'POST':
        task.status = "Completed"
        task.completed_by = request.form.get("completed_by", "System")
        task.completed_at = datetime.utcnow()
        task.comment = request.form.get("comment")
        db.session.commit()
        flash("Task marked as complete.", "success")
        return redirect(url_for('admin.manage_users'))

    return render_template("HR_Module/confirm_task.html", task=task)

@hr_bp.route('/hr_tasks/<int:user_id>', methods=['GET', 'POST'])
@login_required
def view_hr_tasks(user_id):
    user = User.query.get_or_404(user_id)
    tasks = UserHRTask.query.filter_by(user_id=user.id).all()
    templates = HRTaskTemplate.query.order_by(HRTaskTemplate.phase, HRTaskTemplate.name).all()

    if request.method == 'POST':
        task_template_id = request.form.get('task_template_id')
        if task_template_id:
            existing = UserHRTask.query.filter_by(user_id=user.id, task_template_id=task_template_id).first()
            if not existing:
                template = HRTaskTemplate.query.get(task_template_id)
                due_date = None

                if template:
                    # Calculate due date based on phase + timing
                    if template.phase == "onboarding" and user.onboarding_start_date:
                        if template.timing == "before":
                            due_date = user.onboarding_start_date - timedelta(days=template.days_before or 0)
                        elif template.timing == "after":
                            due_date = user.onboarding_start_date + timedelta(days=template.days_before or 0)
                    elif template.phase == "offboarding" and user.offboarding_end_date:
                        if template.timing == "before":
                            due_date = user.offboarding_end_date - timedelta(days=template.days_before or 0)
                        elif template.timing == "after":
                            due_date = user.offboarding_end_date + timedelta(days=template.days_before or 0)

                # Create and store task
                task = UserHRTask(
                    user_id=user.id,
                    task_template_id=template.id,
                    status="Pending",
                    due_date=due_date
                )
                db.session.add(task)
                db.session.commit()

                # ✅ Send email with access to both task and template
                send_hr_task_email(task, template, user)

                flash("Task assigned manually.", "success")
            else:
                flash("Task already assigned.", "warning")
        return redirect(url_for('hr.view_hr_tasks', user_id=user.id))

    return render_template("HR_Module/user_tasks.html", tasks=tasks, user=user, templates=templates)

@hr_bp.route('/hr_dashboard', methods=['GET'])
@login_required
def hr_dashboard():
    selected_phase = request.args.get("phase", "onboarding")
    selected_status = request.args.get("status", "all")

    print("FILTER:", selected_phase, selected_status)

    tasks = (
        UserHRTask.query
        .join(UserHRTask.user)
        .join(UserHRTask.task_template)
        .all()
    )

    print("TOTAL TASKS FOUND:", len(tasks))

    user_dict = {}
    for task in tasks:
        print("Task:", task.user.username, task.task_template.phase, task.status)

        if selected_phase != "all" and task.task_template.phase != selected_phase:
            continue
        if selected_status != "all" and task.status != selected_status:
            continue

        user = task.user
        uid = user.id

        if uid not in user_dict:
            user_dict[uid] = {
                "user": user,
                "phase": task.task_template.phase,
                "total": 0,
                "completed": 0,
                "date": user.onboarding_start_date if task.task_template.phase == 'onboarding' else user.offboarding_end_date
            }

        user_dict[uid]["total"] += 1
        if task.status == "Completed":
            user_dict[uid]["completed"] += 1

    user_data = []
    for u in user_dict.values():
        u["progress"] = int((u["completed"] / u["total"]) * 100) if u["total"] > 0 else 0
        user_data.append(u)

    print("USERS FOUND:", len(user_data))

    return render_template(
        "HR_Module/hr_dashboard.html",
        user_data=user_data,
        selected_phase=selected_phase,
        selected_status=selected_status
    )

@hr_bp.route('/manage_hr_tasks', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_hr_tasks():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        phase = request.form.get('phase')
        responsible_email = request.form.get('responsible_email')
        responsible_job_title_id = request.form.get('responsible_job_title_id')
        days_before = request.form.get('days_before', type=int)
        assigned_job_title_ids = request.form.getlist('assigned_job_title_ids')
        timing = request.form.get('timing') or 'before'
        job_title = JobTitle.query.get(responsible_job_title_id) if responsible_job_title_id else None
        responsible_manager_id = job_title.manager_id if job_title and job_title.manager_id else None

        if name and phase and assigned_job_title_ids:
            task = HRTaskTemplate(
                name=name,
                description=description,
                phase=phase,
                responsible_email=responsible_email or None,
                responsible_job_title_id=responsible_job_title_id or None,
                responsible_manager_id=responsible_manager_id,
                days_before=days_before or 0,
                timing=timing
            )
            task.assigned_job_titles = JobTitle.query.filter(JobTitle.id.in_(assigned_job_title_ids)).all()
            db.session.add(task)
            db.session.commit()
            flash("Task added successfully!", "success")
        else:
            flash("Name, phase and at least one job title are required.", "danger")

        return redirect(url_for('hr.manage_hr_tasks'))

    tasks = HRTaskTemplate.query.order_by(HRTaskTemplate.phase).all()
    job_titles = JobTitle.query.all()
    return render_template("HR_Module/manage_hr_tasks.html", tasks=tasks, job_titles=job_titles)

@hr_bp.route('/update_hr_task/<int:task_id>', methods=['POST'])
@login_required
def update_hr_task(task_id):
    task = HRTaskTemplate.query.get_or_404(task_id)
    data = request.get_json()

    task.name = data.get('name', task.name)
    task.description = data.get('description', task.description)
    task.phase = data.get('phase', task.phase)
    task.responsible_email = data.get('responsible_email', task.responsible_email)
    task.days_before = data.get('days_before', task.days_before)
    task.timing = data.get('timing', task.timing)

    new_responsible_jt_id = data.get('responsible_job_title_id')
    task.responsible_job_title_id = new_responsible_jt_id

    if new_responsible_jt_id:
        job_title = JobTitle.query.get(new_responsible_jt_id)
        task.responsible_manager_id = job_title.manager_id if job_title and job_title.manager_id else None
    else:
        task.responsible_manager_id = None

    job_title_ids = data.get('assigned_job_title_ids')
    if job_title_ids is not None:
        task.assigned_job_titles = JobTitle.query.filter(JobTitle.id.in_(job_title_ids)).all()

    db.session.commit()
    return jsonify(success=True)


@hr_bp.route('/delete_hr_task/<int:task_id>', methods=['POST'])
@login_required
def delete_hr_task(task_id):
    task = HRTaskTemplate.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    return jsonify(success=True)

@hr_bp.route('/hr_overview')
@login_required
@admin_required
def hr_overview():
    users = User.query.join(UserHRTask).distinct().all()

    user_data = []
    for user in users:
        tasks = user.hr_tasks  # Assuming backref from UserHRTask
        onboarding = [t for t in tasks if t.task_template.phase == 'onboarding']
        offboarding = [t for t in tasks if t.task_template.phase == 'offboarding']

        if onboarding:
            phase = 'onboarding'
            total = len(onboarding)
            complete = sum(1 for t in onboarding if t.status == 'Completed')
            date = user.onboarding_start_date
        elif offboarding:
            phase = 'offboarding'
            total = len(offboarding)
            complete = sum(1 for t in offboarding if t.status == 'Completed')
            date = user.offboarding_end_date
        else:
            continue

        progress = round((complete / total) * 100, 1) if total else 0

        user_data.append({
            'user': user,
            'phase': phase,
            'date': date,
            'progress': progress
        })

    return render_template('HR_Module/hr_dashboard.html', user_data=user_data)

@hr_bp.route('/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    roles = RoleType.query.all()
    job_titles = JobTitle.query.all()
    locations = Location.query.all()

    if request.method == 'POST':
        form = request.form
        password = generate_password_hash(form['password'], method='pbkdf2:sha256')

        new_user = User(
            username=form['username'],
            email=form['email'],
            password=password,
            phone_number=form.get('phone_number'),
            address=form.get('address'),
            date_of_birth=form.get('date_of_birth') or None,
            medical_expiry=form.get('medical_expiry') or None,
            license_type=form.get('license_type'),
            license_number=form.get('license_number'),
            next_of_kin=form.get('next_of_kin'),
            kin_phone_number=form.get('kin_phone_number'),
            job_title_id=form.get('job_title_id'),
            location_id=form.get('location_id'),
            is_admin=form.get('is_admin') == 'on',
            auth_type=form.get('auth_type') or 'local',
            crew_code=form.get('crew_code') or None,
            onboarding_start_date=form.get('onboarding_start_date') or None,
            offboarding_end_date=form.get('offboarding_end_date') or None,
            is_active=True
        )

        role_ids = form.getlist('role_ids')
        for role_id in role_ids:
            role = RoleType.query.get(role_id)
            if role:
                new_user.roles.append(role)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {new_user.username} created successfully.", "success")

            # Optional: auto-create onboarding tasks
            if form.get("create_onboarding_tasks") == "yes":
                assign_hr_tasks_for_job_title(new_user)

            return redirect(url_for("hr.hr_dashboard"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating user: {str(e)}", "danger")

    return render_template("HR_Module/create_user.html", roles=roles, job_titles=job_titles, locations=locations)

@hr_bp.route('/my_tasks')
@login_required
def my_tasks():
    # Get templates where the current user is responsible (either directly or via their job title)
    templates = HRTaskTemplate.query.filter(
        (HRTaskTemplate.responsible_manager_id == current_user.id) |
        (HRTaskTemplate.responsible_job_title_id == current_user.job_title_id)
    ).all()

    template_ids = [t.id for t in templates]

    # Only fetch user tasks that match those templates
    tasks = UserHRTask.query.filter(UserHRTask.task_template_id.in_(template_ids)).all()

    return render_template("HR_Module/my_tasks.html", tasks=tasks)

@hr_bp.route('/sign_off_task_post', methods=['POST'])
@login_required
def sign_off_task_post():
    user_id = request.form.get('user_id')
    template_id = request.form.get('task_template_id')
    comment = request.form.get('comment')
    completed_by = request.form.get('completed_by') or current_user.username

    task = UserHRTask.query.filter_by(user_id=user_id, task_template_id=template_id).first_or_404()
    task.status = "Completed"
    task.completed_by = completed_by
    task.comment = comment
    task.completed_at = datetime.utcnow()

    db.session.commit()
    flash("Task signed off successfully.", "success")
    return redirect(url_for("hr.my_tasks"))
