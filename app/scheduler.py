from flask_apscheduler import APScheduler

scheduler = APScheduler()

@scheduler.task('cron', id='send_reminders', hour=1, minute=5)
def scheduled_tasks():
    from flask import current_app
    from app.email_utils import send_course_reminders

    with current_app.app_context():
        try:
            print("[INFO] Running scheduled send_course_reminders()...")
            send_course_reminders()
        except Exception as e:
            print(f"[ERROR] Failed to send course reminders: {str(e)}")

def send_hr_task_reminders():
    from datetime import datetime
    from flask_mail import Message
    from flask import render_template
    from models import UserHRTask
    from app import db, mail
    today = datetime.utcnow().date()

    tasks = UserHRTask.query.filter(
        UserHRTask.status != 'Completed',
        UserHRTask.due_date != None
    ).all()

    for task in tasks:
        days_left = (task.due_date.date() - today).days

        if days_left == 2:
            subject = f"Reminder: HR Task '{task.task_template.name}' due in 2 days"
            template = 'emails/hr_task_reminder.html'
        elif days_left < 0:
            subject = f"Overdue: HR Task '{task.task_template.name}'"
            template = 'emails/hr_task_overdue.html'
        else:
            continue

        if task.task_template.responsible_email:
            msg = Message(
                subject=subject,
                recipients=[task.task_template.responsible_email],
                html=render_template(template, task=task)
            )
            mail.send(msg)
