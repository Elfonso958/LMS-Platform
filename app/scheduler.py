from flask_apscheduler import APScheduler

scheduler = APScheduler()

@scheduler.task('cron', id='send_reminders', hour=1, minute=5)
def scheduled_tasks():
    print("[INFO] Running scheduled send_course_reminders()...")
    from app.email_utils import send_course_reminders  # 🔁 Delayed import to avoid circular
    send_course_reminders()
