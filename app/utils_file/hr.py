from datetime import timedelta
from app.models import HRTaskTemplate, UserHRTask, JobTitle, db
from email_utils import send_hr_task_email

def assign_hr_tasks_for_job_title(user):
    if not user.job_title_id:
        return

    templates = (
        HRTaskTemplate.query
        .filter(HRTaskTemplate.phase == 'onboarding', HRTaskTemplate.is_active == True)
        .join(HRTaskTemplate.assigned_job_titles)
        .filter(JobTitle.id == user.job_title_id)
        .all()
    )

    for template in templates:
        existing = UserHRTask.query.filter_by(user_id=user.id, task_template_id=template.id).first()
        if not existing:
            # ⏱ Determine due date based on onboarding/offboarding date and days_before
            if template.phase == 'onboarding' and user.onboarding_start_date:
                due_date = user.onboarding_start_date - timedelta(days=template.days_before or 0)
            elif template.phase == 'offboarding' and user.offboarding_end_date:
                due_date = user.offboarding_end_date - timedelta(days=template.days_before or 0)
            else:
                due_date = None

            db.session.add(UserHRTask(
                user_id=user.id,
                task_template_id=template.id,
                due_date=due_date,
                status="Pending"
            ))

    db.session.commit()


def assign_offboarding_tasks(user):
    if not user.offboarding_end_date:
        return

    print(f"[DEBUG] Checking offboarding assignment for user: {user.username} (ID: {user.id})")

    offboarding_templates = (
        HRTaskTemplate.query
        .filter(HRTaskTemplate.phase == "offboarding", HRTaskTemplate.is_active == True)
        .join(HRTaskTemplate.assigned_job_titles)
        .filter(JobTitle.id == user.job_title_id)
        .all()
    )

    print(f"[DEBUG] Found {len(offboarding_templates)} offboarding templates for job title {user.job_title_id}")

    new_tasks = []
    for template in offboarding_templates:
        existing = UserHRTask.query.filter_by(user_id=user.id, task_template_id=template.id).first()
        if existing:
            continue

        due_date = None
        if template.timing == "before":
            due_date = user.offboarding_end_date - timedelta(days=template.days_before or 0)
        elif template.timing == "after":
            due_date = user.offboarding_end_date + timedelta(days=template.days_before or 0)

        task = UserHRTask(
            user_id=user.id,
            task_template_id=template.id,
            status="Pending",
            due_date=due_date
        )
        db.session.add(task)
        db.session.flush()  # Ensure task has an ID before sending email
        new_tasks.append((task, template))

    db.session.commit()

    # ✅ Send emails for each new task
    for task, template in new_tasks:
        send_hr_task_email(task, template, user)

    print(f"[DEBUG] Committed {len(new_tasks)} new offboarding task(s) for user {user.username}")

