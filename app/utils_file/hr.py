from datetime import timedelta
from app.models import HRTaskTemplate, UserHRTask, JobTitle, db

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
