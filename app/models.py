from flask_login import UserMixin
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, ForeignKey, func
from sqlalchemy import event
from sqlalchemy.dialects.mysql import BIGINT
from app.extensions import db
from sqlalchemy.dialects.mysql import BIGINT as MYSQL_BIGINT

# Association Table for User and RoleType (Many-to-Many)
user_role = db.Table(
    'user_role',
    db.Column('user_id', BIGINT(unsigned=True), db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_type_id', BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), primary_key=True)
    
)

# Association Table for Course and RoleType (Many-to-Many)
course_role = db.Table(
    'course_role',
    db.Column('course_id', BIGINT(unsigned=True), db.ForeignKey('course.id'), primary_key=True),
    db.Column('role_id', BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), primary_key=True)
)

# Association Table for CrewCheck and RoleType
crew_check_role = db.Table(
    'crew_check_role',
    db.Column('crew_check_id', BIGINT(unsigned=True), db.ForeignKey('crew_checks.id'), primary_key=True),
    db.Column('role_id', BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), primary_key=True)
)

check_items = db.relationship(
    'CheckItem',
    backref='crew_check_meta',
    lazy='dynamic',
    primaryjoin='CheckItem.crew_check_id == CrewCheckMeta.crew_check_id'
)

# Association Table for LineTrainingForm and RoleType
line_training_form_role = db.Table(
    'line_training_form_role',
    db.Column('line_training_form_id', BIGINT(unsigned=True), db.ForeignKey('line_training_form.id'), primary_key=True),
    db.Column('role_type_id', BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), primary_key=True)
)

#Association Table for taskid and job title
hr_task_template_job_title = db.Table(
    'hr_task_template_job_title',
    db.Column('task_template_id', db.Integer, db.ForeignKey('hr_task_template.id'), primary_key=True),
    db.Column('job_title_id', BIGINT(unsigned=True), db.ForeignKey('job_title.id'), primary_key=True)
)


class RoleType(db.Model):
    __tablename__ = 'role_type'
    roleID = db.Column(BIGINT(unsigned=True), primary_key=True)
    role_name = db.Column(db.String(100), nullable=False)
    role_description = db.Column(db.String(100), nullable=False)
    pulled_from_envision = db.Column(db.Boolean, default=True) #New Field to archive users. 
    # Many-to-Many Relationship with Users
    users = db.relationship('User', secondary=user_role, back_populates='roles')

    # Many-to-Many Relationship with Courses
    courses = db.relationship('Course', secondary=course_role, back_populates='roles')

    # Many-to-Many Relationship with LineTrainingForm
    line_training_forms = db.relationship('LineTrainingForm', secondary=line_training_form_role, back_populates='roles')
    
    # Relationship with CrewCheck
    crew_checks = db.relationship('CrewCheck', secondary=crew_check_role, back_populates='roles')

    def __repr__(self):
        return f"<RoleType {self.role_name}>"

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    crew_code = db.Column(db.String(150), unique=True, nullable=False)
    employee_id = db.Column(BIGINT(unsigned=True), unique=True, nullable=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)
    next_of_kin = db.Column(db.String(150), nullable=True)
    kin_phone_number = db.Column(db.String(20), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    license_type = db.Column(db.String(50), nullable=True)  # License Type
    license_number = db.Column(db.String(50), nullable=True)  # License Number
    medical_expiry = db.Column(db.Date, nullable=True)  # Medical Expiry Date
    is_active = db.Column(db.Boolean, default=True)  # Field to archive users
    auth_type = db.Column(db.String(20), nullable=False, default='local')
    onboarding_start_date = db.Column(db.Date)
    offboarding_end_date = db.Column(db.Date)

    # ✅ Many-to-Many Relationship with RoleType
    roles = db.relationship('RoleType', secondary=user_role, back_populates='users')

    # ✅ Relationships
    slide_progress = db.relationship('UserSlideProgress', back_populates='user', cascade='all, delete-orphan')
    exam_attempts = db.relationship('UserExamAttempt', back_populates='user')
    payroll_information = db.relationship('PayrollInformation', uselist=False, back_populates='user')
    courses = db.relationship('Course', secondary='user_slide_progress', back_populates='users', overlaps="slide_progress")
    crew_checks = db.relationship('CrewCheckMeta', back_populates='candidate', cascade='all, delete-orphan')
    user_line_training_forms = db.relationship('UserLineTrainingForm', back_populates='user', lazy=True)

    # ✅ Correct Foreign Key Definition for Job Title
    job_title_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('job_title.id'), nullable=True)
    job_title = db.relationship('JobTitle', back_populates='users', foreign_keys=[job_title_id])

    # ✅ Correct Foreign Key for Location (Remove Duplicates)
    location_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('location.id'))  # ✅ User's assigned location
    location = db.relationship('Location', back_populates='users',overlaps="location")

    # ✅ Timesheets relationship
    timesheets = db.relationship('Timesheet', back_populates='user')

    def get_id(self):
        return str(self.id)

    def has_completed_course(self, course_id):
        # Logic to check if the user has completed the course
        completed_courses = UserSlideProgress.query.filter_by(user_id=self.id, course_id=course_id, completed=True).count()
        return completed_courses > 0

    def __repr__(self):
        return f"<User {self.username} (Active: {self.is_active})>"
    
    def get_allowed_nav_items(self):
        role_ids = [role.roleID for role in self.roles]
        return db.session.query(NavItem).join(NavItemPermission).filter(NavItemPermission.role_id.in_(role_ids)).all()


class Course(db.Model):
    __tablename__ = 'course'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    ppt_file = db.Column(db.String(255), nullable=True)
    passing_mark = db.Column(BIGINT(unsigned=True), nullable=True)
    passing_percentage = db.Column(db.Float, nullable=True)
    valid_for_days = db.Column(BIGINT(unsigned=True), nullable=False, default=365)  # New field for validity in days
    available_before_expiry_days = db.Column(BIGINT(unsigned=True), nullable=False, default=30)
    is_resit = db.Column(db.Boolean, nullable=False, default=False)
    has_exam = db.Column(db.Boolean, default=False)
    # Many-to-Many Relationship with RoleType
    roles = db.relationship('RoleType', secondary=course_role, back_populates='courses')
    users = db.relationship('User', secondary='user_slide_progress', back_populates='courses',overlaps="slide_progress")
    # Relationship with Slide Progress and Exam Attempts
    slide_progress = db.relationship('UserSlideProgress', back_populates='course', cascade='all, delete-orphan',overlaps="courses,users")
    exam_attempts = db.relationship('UserExamAttempt', back_populates='course')

    def __repr__(self):
        return f"<Course {self.title}>"

class Enrollment(db.Model):
    """Enrollment model to track user-course relationships"""
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('course.id'), nullable=False)

    def __repr__(self):
        return f"<Enrollment User {self.user_id} Course {self.course_id}>"

class Questions(db.Model):
    __tablename__ = 'questions'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    text = db.Column(db.String(255), nullable=False)  # Matches your DB column name
    course_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('course.id'), nullable=False)
    answers = db.relationship('Answers', backref='question', lazy=True)

    def __repr__(self):
        return f"<Questions {self.text}>"

class Answers(db.Model):
    __tablename__ = 'answers'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    question_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('questions.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.String(255), nullable=False)  # Answer text
    is_correct = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f"<Answers {self.text} Correct: {self.is_correct}>"

class UserExamAttempt(db.Model):
    __tablename__ = 'user_exam_attempts'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('course.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    passed = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Correct usage
    expiry_date = db.Column(db.DateTime, nullable=True)  # New column
    certificate_path = db.Column(db.String(255), nullable=True)  # New column to store the certificate path
   
    user = db.relationship('User', back_populates='exam_attempts')
    course = db.relationship('Course', back_populates='exam_attempts')
    is_resit = db.Column(db.Boolean, nullable=False, default=False)  # New field
    # Add relationship to UserAnswer
    user_answers = db.relationship('UserAnswer', back_populates='exam_attempt', cascade="all, delete-orphan")

    def __repr__(self):
        return f"<UserExamAttempt User {self.user_id} Course {self.course_id} Score {self.score} Passed {self.passed}>"

class UserSlideProgress(db.Model):
    __tablename__ = 'user_slide_progress'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('course.id'), nullable=False)
    last_slide_viewed = db.Column(BIGINT(unsigned=True), default=0)
    completed = db.Column(db.Boolean, default=False)
    last_completed_date = db.Column(db.Date, nullable=True)  # Track when the user completed the course
    expiry_date = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', back_populates='slide_progress',overlaps="courses,users")
    course = db.relationship('Course', back_populates='slide_progress',overlaps="courses,users")

    def __repr__(self):
        return f"<UserSlideProgress User {self.user_id} Course {self.course_id} Completed {self.completed}>"

class UserAnswer(db.Model):
    __tablename__ = 'user_answers'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    attempt_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user_exam_attempts.id'), nullable=False)
    question_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('questions.id'), nullable=False)
    answer_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('answers.id'), nullable=True)
    is_correct = db.Column(db.Boolean, nullable=False)

    # Relationships
    exam_attempt = db.relationship('UserExamAttempt', back_populates='user_answers')
    question = db.relationship('Questions', backref='user_answers')
    answer = db.relationship('Answers', backref='user_answers')


   # PayrollInformation Model
class PayrollInformation(db.Model):
    __tablename__ = 'payroll_information'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False, unique=True)
    type_of_employment = db.Column(db.String(50), nullable=False)
    minimum_hours = db.Column(db.Boolean, default=False)
    hours = db.Column(BIGINT(unsigned=True), nullable=True)
    kiwisaver_attached = db.Column(db.Boolean, default=False)
    kiwisaver_type = db.Column(db.String(10), nullable=True)
    paye_attached = db.Column(db.Boolean, default=False)
    ir330_attached = db.Column(db.Boolean, default=False)
    ird_number = db.Column(db.String(15), nullable=True)
    bank_account_details = db.Column(db.String(50), nullable=True)

    # Relationship back to User
    user = db.relationship('User', back_populates='payroll_information')

class CrewCheck(db.Model):
    __tablename__ = 'crew_checks'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Name of the check
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Creation timestamp
    visible_headers = db.Column(db.Text, nullable=True)

    # Relationships
    crew_check_metadata = db.relationship('CrewCheckMeta', back_populates='check', cascade='all, delete-orphan',overlaps="check_item_grades,crew_check_meta_relation")
    items = db.relationship('CheckItem', back_populates='crew_check', cascade='all, delete-orphan')
    roles = db.relationship('RoleType', secondary=crew_check_role, back_populates='crew_checks')

    def __repr__(self):
        return f"<CrewCheck {self.name}>"


class CrewCheckMeta(db.Model):
    __tablename__ = 'crew_check_meta'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    crew_check_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('crew_checks.id'), nullable=False)
    candidate_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    date_of_test = db.Column(db.Date, nullable=False)
    aircraft_type = db.Column(db.String(50), nullable=True)
    aircraft_registration = db.Column(db.String(50), nullable=True)
    type_of_check = db.Column(db.String(50), nullable=True)
    comments = db.Column(db.Text, nullable=True)
    flight_time_day = db.Column(BIGINT(unsigned=True), nullable=True, default=0)
    flight_time_night = db.Column(BIGINT(unsigned=True), nullable=True, default=0)
    flight_time_if = db.Column(BIGINT(unsigned=True), nullable=True, default=0)
    current_check_due = db.Column(db.Date, nullable=True)
    test_result = db.Column(db.String(10), nullable=False)
    logbook_sticker_issued = db.Column(db.String(3), nullable=True)
    next_check_due = db.Column(db.Date, nullable=False)
    examiner_name = db.Column(db.String(150), nullable=False)
    examiner_license_number = db.Column(db.String(50), nullable=True)
    examiner_signed = db.Column(db.Boolean, nullable=False, default=False)
    candidate_signed = db.Column(db.Boolean, nullable=False, default=False)
    is_complete = db.Column(db.Boolean, nullable=False, default=False)
    template_version = db.Column(BIGINT(unsigned=True), nullable=False, default=1)  # Template version used

    # Relationships
    check = db.relationship('CrewCheck', back_populates='crew_check_metadata')
    candidate = db.relationship('User', back_populates='crew_checks')
    # Instead of two relationships, we define one for CheckItemGrade:
    grades = db.relationship("CheckItemGrade", backref="meta", cascade="all, delete-orphan")

    def get_grade(self, check_item_id):
        for grade in self.grades:
            if grade.check_item_id == check_item_id:
                return grade.grade
        return None
    def get_grade_comment(self, check_item_id):
        grade_entry = CheckItemGrade.query.filter_by(
            crew_check_meta_id=self.id, check_item_id=check_item_id
        ).first()
        
        return grade_entry.grade_comment if grade_entry and grade_entry.grade_comment else ""

    def __repr__(self):
        return f"<CrewCheckMeta {self.candidate_id} - {self.crew_check_id}>"

class CheckItem(db.Model):
    __tablename__ = 'check_items'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    crew_check_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('crew_checks.id'), nullable=False)
    # Remove crew_check_meta_id here if it is not needed (since CheckItem now is versioned by crew_check)
    item_name = db.Column(db.String(255), nullable=False)
    mandatory = db.Column(db.Boolean, default=False)
    manual_link = db.Column(db.String(255), nullable=True)
    grade = db.Column(BIGINT(unsigned=True), nullable=True)
    na = db.Column(db.Boolean, default=False)
    grader_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=True)
    graded_at = db.Column(db.DateTime, nullable=True)
    version = db.Column(BIGINT(unsigned=True), default=1)  # Version of the template this item belongs to
    deleted = db.Column(db.Boolean, default=False) 
    order = db.Column(BIGINT(unsigned=True), nullable=False, default=0)  # New column for sorting
    additional_info = db.Column(db.String(255), nullable=True)  # Additional information field

    # Relationships
    crew_check = db.relationship('CrewCheck', back_populates='items')
    grader = db.relationship('User', backref='graded_items')
    
    def __repr__(self):
        return f"<CheckItem {self.item_name}>"

# Automatically set the version when adding a new check item
from sqlalchemy import event, func

@event.listens_for(CheckItem, 'before_insert')
def set_check_item_version(mapper, connection, target):
    if target.crew_check_id:
        # Correct the syntax by wrapping the query with `connection.execute`
        highest_version = connection.execute(
            db.select(func.max(CrewCheckMeta.template_version))
            .filter(CrewCheckMeta.crew_check_id == target.crew_check_id)
        ).scalar()

        # If no version exists, default to 1
        target.version = (highest_version or 0) + 1


class CheckItemGrade(db.Model):
    __tablename__ = 'check_item_grade'
    
    id = db.Column(BIGINT(unsigned=True), primary_key=True, autoincrement=True)
    crew_check_meta_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('crew_check_meta.id'), nullable=False)
    check_item_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('check_items.id'), nullable=False)
    grade = db.Column(db.String(2), nullable=False)
    grader_id = db.Column(BIGINT(unsigned=True), nullable=False)
    graded_at = db.Column(db.DateTime, default=datetime.utcnow)
    grade_comment = db.Column(db.String(255), nullable=True)
    # Relationships: using backref "meta" already defined on CrewCheckMeta.grades
    check_item = db.relationship('CheckItem', backref=db.backref('grades', lazy=True))

# Adding a Many-to-Many relationship between LineTrainingForm and RoleType
class LineTrainingForm(db.Model):
    __tablename__ = 'line_training_form'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Name of the training form
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Creation timestamp

    # Many-to-Many Relationship with RoleType
    roles = db.relationship('RoleType', secondary=line_training_form_role, back_populates='line_training_forms')
    items = db.relationship('LineTrainingItem', back_populates='line_training_form', lazy='dynamic')
    topics = db.relationship('Topic', backref='line_training_form', lazy=True)

    def __repr__(self):
        return f"<LineTrainingForm {self.name}>"

class LineTrainingItem(db.Model):
    __tablename__ = 'line_training_items'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    form_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('line_training_form.id'), nullable=False)
    item_name = db.Column(db.String(255), nullable=False)  # Name of the item
    mandatory = db.Column(db.Boolean, default=False)  # Indicates if the item is mandatory
    manual_link = db.Column(db.String(255), nullable=True)  # Optional manual link
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp

    # Relationship with LineTrainingForm
    line_training_form = db.relationship('LineTrainingForm', back_populates='items')

    def __repr__(self):
        return f"<LineTrainingItem {self.item_name}>"

class Topic(db.Model):
    __tablename__ = 'topic'  # Ensure table name is consistent
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    line_training_form_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('line_training_form.id'), nullable=True)  # For template forms
    user_line_training_form_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user_line_training_forms.id'), nullable=True)  # For user-specific forms

    # Relationships
    tasks = db.relationship('Task', backref='topic', lazy=True, cascade='all, delete')  # Tasks linked to this topic
    user_line_training_form = db.relationship('UserLineTrainingForm', back_populates='topics')  # Link back to user form

    def __repr__(self):
        return f"<Topic {self.name}>"


class Task(db.Model):
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    topic_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('topic.id'), nullable=True)
    notes = db.Column(db.Text)

    # Modify the backref name to something unique like 'task_completions'
    completions = db.relationship('TaskCompletion', backref='task_ref', lazy='dynamic',overlaps="completions,task_ref")

    def __repr__(self):
        return f"<Task {self.name}>"

class TaskCompletion(db.Model):
    __tablename__ = 'task_completion'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    task_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('task.id'), nullable=False)
    form_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user_line_training_forms.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    trainer_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)  # New trainer field

    task = db.relationship('Task', backref='task_completions',overlaps="completions,task_ref")
    form = db.relationship('UserLineTrainingForm', backref='completions')
    trainer = db.relationship('User', backref='completed_tasks')  # New relationship to User

    def __repr__(self):
        return f"<TaskCompletion(task_id={self.task_id}, form_id={self.form_id}, trainer_id={self.trainer_id})>"

class UserLineTrainingForm(db.Model):
    __tablename__ = 'user_line_training_forms'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    template_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('line_training_form.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_sectors = db.Column(BIGINT(unsigned=True), default=0, nullable=False)
    total_hours = db.Column(db.Float, default=0.0, nullable=False)
    released = db.Column(db.Boolean, default=False)  # New column to track release status
    line_training_complete = db.Column(db.Boolean, default=False)  # New column to track release status
    # Relationships
    user = db.relationship('User', back_populates='user_line_training_forms')
    template = db.relationship('LineTrainingForm', backref='user_line_training_forms')
    topics = db.relationship('Topic', back_populates='user_line_training_form', lazy=True, cascade='all, delete')
    sectors = db.relationship('Sector', back_populates='form', lazy=True, cascade='all, delete')

    def __repr__(self):
        return f"<UserLineTrainingForm {self.id} for User {self.user_id} from Template {self.template_id}>"


class Sector(db.Model):
    __tablename__ = 'sectors'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    form_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user_line_training_forms.id'), nullable=False)  # Correct ForeignKey
    date = db.Column(db.Date, nullable=False)
    variant = db.Column(db.String(50), nullable=False)
    dep = db.Column(db.String(10), nullable=False)
    arr = db.Column(db.String(10), nullable=False)
    flight_time_sector = db.Column(db.Float, nullable=True)
    flight_time_total = db.Column(db.Float, nullable=True)
    if_time_sector = db.Column(db.Float, nullable=True)
    if_time_total = db.Column(db.Float, nullable=True)
    type = db.Column(db.String(20), nullable=True)
    takeoff_count = db.Column(BIGINT(unsigned=True), nullable=True)
    landing_count = db.Column(BIGINT(unsigned=True), nullable=True)
    sector_number = db.Column(BIGINT(unsigned=True), nullable=False)
    saved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.String(200), nullable=True)
    note_creator_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=True)
    

    # Correct Relationship with UserLineTrainingForm
    form = db.relationship('UserLineTrainingForm', back_populates='sectors')
    note_creator = db.relationship('User', backref='notes_created', foreign_keys=[note_creator_id])

class RosterChange(db.Model):
    __tablename__ = 'roster_changes'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    crew_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)  # Correct table name reference
    original_duty = db.Column(db.JSON, nullable=False)  # Store original duty details as JSON
    updated_duty = db.Column(db.JSON, nullable=False)  # Store new duty details as JSON
    published_at = db.Column(db.DateTime, nullable=True)  # When Ops published the change
    acknowledged = db.Column(db.Boolean, default=False)  # Acknowledgment status
    acknowledged_at = db.Column(db.DateTime, nullable=True)  # Timestamp for acknowledgment

    crew_member = db.relationship("User", backref="roster_changes")

class Flight(db.Model):
    id = db.Column(BIGINT(unsigned=True), primary_key=True) 
    flightid = db.Column(BIGINT(unsigned=True), nullable=False)  # Flight ID from Envision
    update_id = db.Column(db.String(50), unique=True, nullable=True)  # Unique ID for updates
    
    employee_id = db.Column(BIGINT(unsigned=True), nullable=True)  # Nullable if crew is not assigned
    
    parent_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('flight.id'), nullable=True)  # Links updates to original flight
    is_update = db.Column(db.Boolean, default=False)  # True if this is an update record


    flightStatusId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightStatusDescription = db.Column(db.String(50), nullable=True)
    flightDate = db.Column(db.DateTime, nullable=True)  # Flight operational date

    # Departure Information
    departurePlaceId = db.Column(BIGINT(unsigned=True), nullable=True)
    departurePlaceDescription = db.Column(db.String(100), nullable=True)
    departureScheduled = db.Column(db.DateTime, nullable=True)
    departureEstimate = db.Column(db.DateTime, nullable=True)
    departureActual = db.Column(db.DateTime, nullable=True)
    departureTakeOff = db.Column(db.DateTime, nullable=True)

    # Arrival Information
    arrivalPlaceId = db.Column(BIGINT(unsigned=True), nullable=True)
    arrivalPlaceDescription = db.Column(db.String(100), nullable=True)
    arrivalScheduled = db.Column(db.DateTime, nullable=True)
    arrivalEstimate = db.Column(db.DateTime, nullable=True)
    arrivalLanded = db.Column(db.DateTime, nullable=True)
    arrivalActual = db.Column(db.DateTime, nullable=True)

    # Diversion Details
    divertedPlaceId = db.Column(BIGINT(unsigned=True), nullable=True)
    divertedPlaceDescription = db.Column(db.String(100), nullable=True)
    divertedReason = db.Column(db.String(255), nullable=True)
    divertedArrivalTime = db.Column(db.DateTime, nullable=True)

    # Customer & Aircraft Details
    customerId = db.Column(BIGINT(unsigned=True), nullable=True)
    customerDescription = db.Column(db.String(100), nullable=True)
    flightModelId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightModelDescription = db.Column(db.String(100), nullable=True)
    flightLineId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightLineDescription = db.Column(db.String(100), nullable=True)
    flightTypeId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightTypeDescription = db.Column(db.String(100), nullable=True)
    flightNumberId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightNumberDescription = db.Column(db.String(50), nullable=True)
    flightRegistrationId = db.Column(BIGINT(unsigned=True), nullable=True)
    flightRegistrationDescription = db.Column(db.String(50), nullable=True)

    # Timing & Performance
    plannedFlightTime = db.Column(BIGINT(unsigned=True), nullable=True)  # Planned flight duration in minutes
    calculatedTakeOffTime = db.Column(db.DateTime, nullable=True)
    abortCancelCodeId = db.Column(BIGINT(unsigned=True), nullable=True)
    abortCancelCodeDescription = db.Column(db.String(255), nullable=True)

    # Crew Members Stored in JSON Format
    crew = db.Column(db.JSON, nullable=True)  
    # Example JSON:
    # [
    #   {"employeeId": 142, "firstName": "Alan", "surname": "Martin", "position": "Captain"},
    #   {"employeeId": 143, "firstName": "John", "surname": "Smith", "position": "First Officer"}
    # ]

    def acknowledge(self):
        """Mark the roster change as acknowledged."""
        self.acknowledged = True
        self.acknowledged_at = datetime.utcnow()

    def __repr__(self):
        return f"<Flight {self.id} - {self.flightNumberDescription} ({self.departurePlaceDescription} ➝ {self.arrivalPlaceDescription})>"


class FormTemplate(db.Model):
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(255), nullable=False, default="Untitled Template")
    template_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self):
        return f"<FormTemplate {self.name}>"

class RoutePermission(db.Model):
    __tablename__ = 'route_permissions'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    endpoint = db.Column(db.String(255), unique=True, nullable=False)

    # Many-to-Many Relationship with RoleType
    roles = db.relationship("RoleType", secondary="route_role", back_populates="permissions")


# Many-to-Many Table Between Routes and Roles
route_role = db.Table(
    'route_role',
    db.Column('route_permission_id', BIGINT(unsigned=True), db.ForeignKey('route_permissions.id'), primary_key=True),
    db.Column('role_type_id', BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), primary_key=True)
)

# Add relationship to RoleType
RoleType.permissions = db.relationship("RoutePermission", secondary="route_role", back_populates="roles")

class Qualification(db.Model):
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    employee_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    qualification_id = db.Column(BIGINT(unsigned=True), nullable=False)
    qualification = db.Column(db.String(255), nullable=False)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', back_populates='qualifications')

    def __repr__(self):
        return f'<Qualification {self.qualification}>'

# Add relationship to User model
User.qualifications = db.relationship('Qualification', back_populates='user', cascade='all, delete-orphan')

class EmployeeSkill(db.Model):
    __tablename__ = 'employee_skills'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    employee_id = db.Column(BIGINT(unsigned=True), nullable=False)
    skill_id = db.Column(BIGINT(unsigned=True), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    valid = db.Column(db.Boolean, default=True)
    priority = db.Column(BIGINT(unsigned=True), nullable=False)

    def __repr__(self):
        return f'<EmployeeSkill {self.description}>'
    
class EmailConfig(db.Model):
    __tablename__ = 'email_config'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    line_training_thresholds = db.Column(db.String(255), nullable=False, default="11,15,20,40,60,65,70,73")
    course_reminder_days = db.Column(db.String(255), nullable=False, default="60,30,15,10,5,4,3,2,1,0")
    line_training_roles = db.Column(db.String(255), nullable=False, default="")
    course_reminder_email = db.Column(db.String(255), nullable=False, default="")
    medical_expiry_days = db.Column(db.String(255))
    medical_expiry_email = db.Column(db.String(255), nullable=True)
    def get_line_training_thresholds(self):
        return [int(threshold) for threshold in self.line_training_thresholds.split(",")]

    def get_course_reminder_days(self):
        return [int(day) for day in self.course_reminder_days.split(",")]

    def get_line_training_roles(self):
        return [int(role_id) for role_id in self.line_training_roles.split(",") if role_id.strip()]

class Location(db.Model):
    __tablename__ = 'location'

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    # ✅ Rename backref to avoid conflict with User.location
    users = db.relationship('User', backref='user_location', lazy=True)
    job_titles = db.relationship('JobTitle', backref='job_location', lazy=True)


class Timesheet(db.Model):
    __tablename__ = 'timesheet'
    
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    payroll_period_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('payroll_period.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=True)
    finish_time = db.Column(db.Time, nullable=True)
    lunch_break = db.Column(db.Boolean, default=False)
    actual_hours = db.Column(db.Float, default=0.0)
    unpaid_break = db.Column(db.Float, default=0.0)
    paid_hours = db.Column(db.Float, default=0.0)
    call_in = db.Column(db.Boolean, default=False)
    runway_inspections = db.Column(BIGINT(unsigned=True), default=0)
    annual_leave = db.Column(db.Boolean, default=False)
    sick_leave = db.Column(db.Boolean, default=False)
    other_notes = db.Column(db.String(255), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ✅ Add status field
    status = db.Column(db.String(20), default="Pending")  # Pending, Approved, Rejected

    # ✅ Keep the relationship to User (Avoid InvalidRequestError)
    user = db.relationship('User', back_populates='timesheets')

    # ✅ Keep the relationship to PayrollPeriod
    payroll_period = db.relationship('PayrollPeriod', back_populates='timesheets')

class JobTitle(db.Model):
    __tablename__ = 'job_title'
    
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    title = db.Column(db.String(100), nullable=False, unique=True)

    # ✅ Explicit Foreign Key Reference for Manager
    manager_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=True)
    manager = db.relationship('User', foreign_keys=[manager_id], backref='managed_roles')

    # ✅ Define hierarchical reporting structure
    reports_to = db.Column(BIGINT(unsigned=True), db.ForeignKey('job_title.id'), nullable=True)
    parent_job = db.relationship('JobTitle', remote_side=[id], backref='child_jobs')

    # ✅ Define timesheet access reporting structure
    has_timesheet_access = db.Column(db.Boolean, default=False)  # ✅ New Field: Timesheet Access
    has_payroll_access = db.Column(db.Boolean, default=False)  # ✅ New Field: Payroll Access
   
    location_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('location.id'))  # ✅ Location-based job titles
    users = db.relationship('User', back_populates='job_title', foreign_keys="[User.job_title_id]")
        
    def get_all_subordinate_roles(self):
        """Recursively fetch all subordinate job roles under this job title"""
        subordinates = set()
        
        def fetch_subordinates(job):
            for child in job.child_jobs:
                subordinates.add(child.id)
                fetch_subordinates(child)
        
        fetch_subordinates(self)
        return list(subordinates)
    
class PayrollPeriod(db.Model):
    __tablename__ = 'payroll_period'
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    start_date = db.Column(db.Date, nullable=False, unique=True)
    end_date = db.Column(db.Date, nullable=False, unique=True)
    status = db.Column(db.String(10), default="Open")  # ✅ New Field: "Open" or "Closed"

    # Relationship to timesheets
    timesheets = db.relationship('Timesheet', back_populates='payroll_period')

class Crew(db.Model):
    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    flightId = db.Column(BIGINT(unsigned=True), db.ForeignKey('flight.id'), nullable=False)
    crewPositionId = db.Column(BIGINT(unsigned=True), nullable=False)
    employeeId = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    dutyStartTime = db.Column(db.DateTime, nullable=True)
    dutyFinishTime = db.Column(db.DateTime, nullable=True)
    isPilotFlying = db.Column(db.Boolean, nullable=True)
    isComplete = db.Column(db.Boolean, nullable=True)

    def __repr__(self):
        return f"<Crew {self.id} - Flight {self.flightId} - Employee {self.employeeId}>"

class Port(db.Model):
    __tablename__ = "ports"

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    port_name = db.Column(db.String(100), nullable=False, unique=True)
    icao_code = db.Column(db.String(10), nullable=False)  # Removed unique constraint
    iata_code = db.Column(db.String(10), nullable=True)
    country = db.Column(db.String(50), nullable=True)
    notes = db.Column(db.Text, nullable=True)  # Additional airport-specific notes

    # Relationship with ground handlers
    ground_handlers = db.relationship('GroundHandler', backref='port', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Port {self.port_name} ({self.icao_code})>"

class GroundHandler(db.Model):
    __tablename__ = "ground_handlers"

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    port_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('ports.id'), nullable=False)  # Link to ports table
    handling_agent = db.Column(db.String(100), nullable=False)
    contact_person = db.Column(db.String(100), nullable=True)
    agent_contact = db.Column(db.String(50), nullable=True)
    agent_frequency = db.Column(db.String(50), nullable=True)
    gpu_available = db.Column(db.Boolean, nullable=True)  # True if GPU is available
    fuel_details = db.Column(db.Text, nullable=True)  # Stores fuel availability details
    primary_email = db.Column(db.String(150), nullable=False, unique=False)
    additional_contacts = db.Column(db.String(500), nullable=False)  # Store multiple emails as a comma-separated string

    # Relationship with flight-handler mapping
    flight_mappings = db.relationship('HandlerFlightMap', backref='handler', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<GroundHandler {self.handling_agent} at {self.port.port_name}>"

class HandlerFlightMap(db.Model):
    __tablename__ = "handler_flight_map"

    id = db.Column(BIGINT(unsigned=True), primary_key=True)
    flight_number = db.Column(db.String(20), nullable=True)  # Flight number, can be NULL for default handler
    handler_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('ground_handlers.id'), nullable=False)  # Link to ground handler
    is_default = db.Column(db.Boolean, nullable=False, default=False)  # True if this is the default handler

    def __repr__(self):
        return f"<HandlerFlightMap Flight: {self.flight_number} -> Handler: {self.handler.handling_agent}>"

class NavItem(db.Model):
    __tablename__ = 'nav_item'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100), nullable=False)
    endpoint = db.Column(db.String(100), nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('nav_item.id'), nullable=True)
    order = db.Column(db.Integer, nullable=False, default=0)  # 👈 Added for drag-and-drop support
    parent = db.relationship('NavItem', remote_side=[id], backref='children')
    inherit_roles = db.Column(db.Boolean, default=False)



class NavItemPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nav_item_id = db.Column(db.Integer, db.ForeignKey('nav_item.id'), nullable=False)
    role_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('role_type.roleID'), nullable=False)

# models.py
class CrewAcknowledgement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    flight_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('flight.id'), nullable=False)
    crew_member_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.employee_id'), nullable=False)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_at = db.Column(db.DateTime)

    flight = db.relationship("Flight", backref="acknowledgements")
    crew_member = db.relationship("User", backref="crew_acknowledgements")

class DocumentReviewRequest(db.Model):
    __tablename__ = 'document_review_requests'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    reviewed_by_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'))

    document_type_id = db.Column(db.Integer, db.ForeignKey('document_types.id'), nullable=False)  # NEW
    document_expiry_date = db.Column(db.Date, nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending / approved / rejected
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    review_comment = db.Column(db.Text)

    # ✅ Explicitly state foreign_keys to resolve ambiguity
    user = db.relationship('User', foreign_keys=[user_id], backref='document_requests')
    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_id], backref='reviewed_documents')
    type = db.relationship('DocumentType', back_populates='documents')  # NEW
    def is_pending(self):
        return self.status == 'pending'

    def is_approved(self):
        return self.status == 'approved'

class DocumentType(db.Model):
    __tablename__ = 'document_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # e.g., 'Medical', 'Passport'
    description = db.Column(db.String(255), nullable=True)

    # Optional relationship to link to DocumentReviewRequest
    documents = db.relationship('DocumentReviewRequest', back_populates='type')

    def __repr__(self):
        return f"<DocumentType {self.name}>"

class HRTaskTemplate(db.Model):
    __tablename__ = 'hr_task_template'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    
    # ✅ One or many job titles
    assigned_job_titles = db.relationship(
        "JobTitle",
        secondary="hr_task_template_job_title",  # association table
        backref="hr_tasks"
    )
    
    responsible_job_title_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('job_title.id'))
    responsible_job_title = db.relationship("JobTitle", foreign_keys=[responsible_job_title_id])
    days_before = db.Column(db.Integer, default=0)  # Days before onboarding/offboarding date
    timing = db.Column(db.String(20), nullable=False, default="before")  # Options: before, after

    # ✅ Responsible manager (User model)
    responsible_manager_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'))
    responsible_manager = db.relationship("User")

    # ✅ Optional override or contact-specific address
    responsible_email = db.Column(db.String(150))

    phase = db.Column(db.String(20))  # "onboarding" or "offboarding"
    is_active = db.Column(db.Boolean, default=True)


class UserHRTask(db.Model):
    __tablename__ = 'user_hr_task'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('user.id'), nullable=False)
    task_template_id = db.Column(db.Integer, db.ForeignKey('hr_task_template.id'))
    status = db.Column(db.String(20), default="Pending")  # Pending / Completed
    completed_by = db.Column(db.String(150))
    completed_at = db.Column(db.DateTime)
    comment = db.Column(db.Text)  # Optional notes
    due_date = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref="hr_tasks")
    task_template = db.relationship("HRTaskTemplate", backref="user_tasks")

class Department(db.Model):
    __tablename__ = 'department'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

class EmploymentType(db.Model):
    __tablename__ = 'employment_type'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100), nullable=False, unique=True)

class RecruitmentRequest(db.Model):
    __tablename__ = 'recruitment_request'
    id = db.Column(db.Integer, primary_key=True)
    hiring_manager_name = db.Column(db.String(100), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    location_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('location.id'))
    job_title_id = db.Column(BIGINT(unsigned=True), db.ForeignKey('job_title.id'), nullable=False)
    number_of_positions = db.Column(db.Integer)
    employment_type_id = db.Column(db.Integer, db.ForeignKey('employment_type.id'))
    justification = db.Column(db.Text)
    has_position_description = db.Column(db.Boolean)
    remuneration_range = db.Column(db.String(100))
    submitted_by = db.Column(db.String(100))

    department = db.relationship('Department')
    location = db.relationship('Location')
    job_title = db.relationship('JobTitle')  # ✅ FK to JobTitle table
    employment_type = db.relationship('EmploymentType')

class RecruitmentType(db.Model):
    __tablename__ = 'recruitment_type'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(100), unique=True)
