import os
import sys
from app.models import JobTitle

# Add the parent directory to the system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db  # Import from app/__init__.py

app = create_app()

with app.app_context():
    db.create_all()
    print("Tables created successfully!")

def populate_job_titles():
    job_titles = ["Pilot", "Flight Attendant", "Ground Crew", "Operations Manager"]
    for title in job_titles:
        if not JobTitle.query.filter_by(title=title).first():
            db.session.add(JobTitle(title=title))
    db.session.commit()