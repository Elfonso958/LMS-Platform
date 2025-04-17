from flask import current_app
from datetime import datetime, timedelta
from app import scheduler, db
from app.models import User, EmailConfig
from app.email_utils import send_email

@scheduler.task('cron', id='medical_expiry_alert', hour=6)
def daily_medical_expiry_check():
    with current_app.app_context():
        config = EmailConfig.query.first()
        if not config or not config.medical_expiry_email:
            return

        days = config.medical_expiry_days or 30
        threshold_date = datetime.utcnow().date() + timedelta(days=days)

        users_due = User.query.filter(
            User.medical_expiry != None,
            User.medical_expiry <= threshold_date
        ).order_by(User.medical_expiry.asc()).all()

        if not users_due:
            return

        body = f"The following users have medical certificates expiring within {days} days:\n\n"
        for user in users_due:
            expiry_str = user.medical_expiry.strftime('%Y-%m-%d')
            body += f"• {user.username} — {expiry_str}\n"

        send_email(
            subject="Upcoming Medical Expiry Alert",
            recipients=[config.medical_expiry_email],
            body=body
        )
