from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectMultipleField, SubmitField, TextAreaField, DateField, FloatField
from wtforms.validators import DataRequired, Email

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

class LineTrainingFormEditForm(FlaskForm):
    name = StringField('Form Name', validators=[DataRequired()])
    roles = SelectMultipleField('Roles Assigned', coerce=int, choices=[])  # Multiple roles
    submit = SubmitField('Save Changes')

    def __init__(self, *args, **kwargs):
        super(LineTrainingFormEditForm, self).__init__(*args, **kwargs)

class LineTrainingEmailConfigForm(FlaskForm):
    thresholds = StringField('Line Training Update Sector Update (comma-separated)', validators=[DataRequired()])
    line_training_roles = SelectMultipleField('Line Training Roles', choices=[], coerce=int)
    submit = SubmitField('Update Line Training Configuration')

class CourseReminderEmailConfigForm(FlaskForm):
    course_reminder_days = StringField('Course Reminder Days (comma-separated)', validators=[DataRequired()])
    course_reminder_email = StringField('Course Reminder Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Course Reminder Configuration')

class TimesheetForm(FlaskForm):
    date = DateField('Date', validators=[DataRequired()])
    hours_worked = FloatField('Hours Worked', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Submit')

CREW_CHECK_FIELDS = [
    ('candidate_name', 'Candidate Name'),
    ('licence_type', 'Licence Type'),
    ('licence_number', 'Licence Number'),
    ('medical_expiry', 'Medical Expiry'),
    ('date_of_test', 'Date of Test'),
    ('aircraft_type', 'Aircraft Type'),
    ('aircraft_registration', 'Aircraft Registration'),
    ('type_of_check', 'Type of Check'),
    ('comments', 'Comments'),
    ('flight_times', 'Flight Times'),
    ('current_check_due', 'Current Check Due'),
    ('test_result', 'Test Result'),
    ('logbook_sticker_issued', 'Logbook Sticker Issued'),
    ('next_check_due', 'Next Check Due'),
    ('examiner_name', 'Examiner Name'),
    ('examiner_licence_number', 'Examiner Licence Number'),
]
