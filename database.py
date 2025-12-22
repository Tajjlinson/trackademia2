from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, time, timedelta
import sys


# Create the SQLAlchemy instance
db = SQLAlchemy()

# Association table for many-to-many relationship between Student and Course
enrollments = db.Table('enrollments',
    db.Column('id', db.Integer, primary_key=True),
    db.Column('student_id', db.Integer, db.ForeignKey('students.id')),
    db.Column('course_id', db.Integer, db.ForeignKey('courses.id'))
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    user_type = db.Column(db.String(20), nullable=False)  # 'admin', 'lecturer', or 'student'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username} ({self.user_type})>'

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(50), default='administrator')  # administrator, super_admin, etc.
    
    # Relationship to User
    user = db.relationship('User', backref='admin_profile')
    
    def __repr__(self):
        return f'<Admin {self.user.name}>'

class Lecturer(db.Model):
    __tablename__ = 'lecturers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    department = db.Column(db.String(100))
    employee_id = db.Column(db.String(50), unique=True)
    office_location = db.Column(db.String(200))
    office_hours = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship to User
    user = db.relationship('User', backref='lecturer_profile')
    
    # Relationship to Course
    courses = db.relationship('Course', backref='lecturer', lazy=True)
    
    # Relationship to Session
    sessions = db.relationship('Session', backref='lecturer', lazy=True)
    
    def __repr__(self):
        return f'<Lecturer {self.user.name}>'

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    student_id = db.Column(db.String(50), unique=True)
    enrollment_year = db.Column(db.Integer)
    major = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship to User
    user = db.relationship('User', backref='student_profile')
    
    # Many-to-many relationship with Course through enrollments table
    courses = db.relationship('Course', 
                             secondary=enrollments, 
                             back_populates='students')
    
    # Relationship to Attendance
    attendances = db.relationship('Attendance', backref='student', lazy=True)
    
    def __repr__(self):
        return f'<Student {self.user.name}>'

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(50), unique=True)
    description = db.Column(db.Text, nullable=True)
    credits = db.Column(db.Integer, default=3)
    semester = db.Column(db.String(50))  # Fall 2024, Spring 2025, etc.
    max_capacity = db.Column(db.Integer, default=30)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('lecturers.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Many-to-many relationship with Student
    students = db.relationship('Student',
                              secondary=enrollments,
                              back_populates='courses')
    
    # Relationship to Session
    sessions = db.relationship('Session', backref='course', lazy=True)
    
    def __repr__(self):
        return f'<Course {self.code}: {self.name}>'

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'))
    name = db.Column(db.String(100))
    date = db.Column(db.Date)
    start_time = db.Column(db.Time)
    duration_minutes = db.Column(db.Integer)
    location = db.Column(db.String(200))
    allowed_distance_meters = db.Column(db.Integer, default=50)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('lecturers.id'))
    status = db.Column(db.String(20), default='upcoming')  # upcoming, active, past
    
    # Location verification fields
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    allowed_ip_range = db.Column(db.String(100), nullable=True)
    
    # Relationships
    attendance_records = db.relationship('Attendance', back_populates='session', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Session {self.name} ({self.date})>'
    
    @property
    def end_time(self):
        """Calculate end time based on start time and duration"""
        if self.start_time:
            start_datetime = datetime.combine(self.date, self.start_time)
            end_datetime = start_datetime + timedelta(minutes=self.duration_minutes)
            return end_datetime.time()
        return None
    
    def is_active_now(self):
        """Check if session is currently active"""
        now = datetime.now()
        session_datetime = datetime.combine(self.date, self.start_time)
        end_datetime = session_datetime + timedelta(minutes=self.duration_minutes)
        return session_datetime <= now <= end_datetime

class Attendance(db.Model):
    __tablename__ = 'attendances'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('sessions.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now())  # Uses local time
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default='present')  # present, absent, excused
    verified_by = db.Column(db.String(50), nullable=True)  # system, admin, lecturer
    
    # Relationships
    session = db.relationship('Session', back_populates='attendance_records')
    
    def __repr__(self):
        return f'<Attendance {self.student_id} for Session {self.session_id}>'

class RemovalRequest(db.Model):
    __tablename__ = 'removal_requests'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    lecturer_id = db.Column(db.Integer, db.ForeignKey('lecturers.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    student = db.relationship('Student')
    course = db.relationship('Course')
    lecturer = db.relationship('Lecturer')
    admin_reviewer = db.relationship('Admin', foreign_keys=[reviewed_by])
    
    def __repr__(self):
        return f'<RemovalRequest {self.id} - {self.status}>'

def init_db(app):
    """Initialize database with app context"""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if we need to create demo data
        if User.query.count() == 0:
            create_demo_data()

def create_demo_data():
    """Create demo users and data - Working version"""
    print("Creating demo data...")
    
    try:
        # Create admin user
        admin_user = User()
        admin_user.username = 'admin'
        admin_user.name = 'System Administrator'
        admin_user.email = 'admin@trackademia.edu'
        admin_user.user_type = 'admin'
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        db.session.commit()
        
        # Create admin profile
        admin = Admin()
        admin.user_id = admin_user.id
        admin.role = 'super_admin'
        db.session.add(admin)
        db.session.commit()
        
        # Create lecturer user
        lecturer_user = User()
        lecturer_user.username = 'lecturer'
        lecturer_user.name = 'Dr. Ricardo Anderson'
        lecturer_user.email = 'ricardo.anderson@trackademia.edu'
        lecturer_user.user_type = 'lecturer'
        lecturer_user.set_password('password123')
        db.session.add(lecturer_user)
        db.session.commit()
        
        # Create lecturer profile
        lecturer = Lecturer()
        lecturer.user_id = lecturer_user.id
        lecturer.department = 'Computer Science'
        lecturer.employee_id = 'EMP001'
        lecturer.office_location = 'CS Building Room 205'
        lecturer.office_hours = 'Mon-Wed 10AM-12PM'
        db.session.add(lecturer)
        db.session.commit()
        
        # Create student 1
        student_user1 = User()
        student_user1.username = 'student'
        student_user1.name = 'John Doe'
        student_user1.email = 'john.doe@student.trackademia.edu'
        student_user1.user_type = 'student'
        student_user1.set_password('password123')
        db.session.add(student_user1)
        db.session.commit()
        
        student1 = Student()
        student1.user_id = student_user1.id
        student1.student_id = '620163325'
        student1.enrollment_year = 2024
        student1.major = 'Computer Science'
        db.session.add(student1)
        db.session.commit()
        
        # Create student 2
        student_user2 = User()
        student_user2.username = 'student2'
        student_user2.name = 'Jane Smith'
        student_user2.email = 'jane.smith@student.trackademia.edu'
        student_user2.user_type = 'student'
        student_user2.set_password('password123')
        db.session.add(student_user2)
        db.session.commit()
        
        student2 = Student()
        student2.user_id = student_user2.id
        student2.student_id = '620163326'
        student2.enrollment_year = 2024
        student2.major = 'Information Technology'
        db.session.add(student2)
        db.session.commit()
        
        # Create student 3
        student_user3 = User()
        student_user3.username = 'student3'
        student_user3.name = 'Robert Johnson'
        student_user3.email = 'robert.johnson@student.trackademia.edu'
        student_user3.user_type = 'student'
        student_user3.set_password('password123')
        db.session.add(student_user3)
        db.session.commit()
        
        student3 = Student()
        student3.user_id = student_user3.id
        student3.student_id = '620163327'
        student3.enrollment_year = 2024
        student3.major = 'Software Engineering'
        db.session.add(student3)
        db.session.commit()
        
        # Create student 4
        student_user4 = User()
        student_user4.username = 'student4'
        student_user4.name = 'Emily Davis'
        student_user4.email = 'emily.davis@student.trackademia.edu'
        student_user4.user_type = 'student'
        student_user4.set_password('password123')
        db.session.add(student_user4)
        db.session.commit()
        
        student4 = Student()
        student4.user_id = student_user4.id
        student4.student_id = '620163328'
        student4.enrollment_year = 2024
        student4.major = 'Computer Science'
        db.session.add(student4)
        db.session.commit()
        
        # Create course 1
        course1 = Course()
        course1.name = 'Software Engineering'
        course1.code = 'COMP2140'
        course1.description = 'Introduction to software engineering principles and practices'
        course1.credits = 3
        course1.semester = 'Fall 2024'
        course1.max_capacity = 40
        course1.lecturer_id = lecturer.id
        db.session.add(course1)
        db.session.commit()
        
        # Enroll students in course 1 using the association table
        student1.courses.append(course1)
        student2.courses.append(course1)
        student3.courses.append(course1)
        db.session.commit()
        
        # Create sessions for course 1
        # Past session
        session1 = Session()
        session1.course_id = course1.id
        session1.name = 'Introduction to Software Engineering'
        session1.date = date.today() - timedelta(days=2)
        session1.start_time = time(10, 0)
        session1.duration_minutes = 90
        session1.location = 'Computer Lab 3'
        session1.allowed_distance_meters = 100
        session1.lecturer_id = lecturer.id
        session1.latitude = 18.0060
        session1.longitude = -76.7468
        session1.status = 'past'
        db.session.add(session1)
        db.session.commit()
        
        # Active session
        session2 = Session()
        session2.course_id = course1.id
        session2.name = 'Requirements Engineering'
        session2.date = date.today()
        session2.start_time = time(14, 0)
        session2.duration_minutes = 90
        session2.location = 'Lecture Hall A'
        session2.allowed_distance_meters = 100
        session2.lecturer_id = lecturer.id
        session2.latitude = 18.0060
        session2.longitude = -76.7468
        session2.status = 'active'
        db.session.add(session2)
        db.session.commit()
        
        # Upcoming session
        session3 = Session()
        session3.course_id = course1.id
        session3.name = 'Software Design'
        session3.date = date.today() + timedelta(days=2)
        session3.start_time = time(11, 30)
        session3.duration_minutes = 90
        session3.location = 'Room 101'
        session3.allowed_distance_meters = 100
        session3.lecturer_id = lecturer.id
        session3.latitude = 18.0060
        session3.longitude = -76.7468
        session3.status = 'upcoming'
        db.session.add(session3)
        db.session.commit()
        
        # Create attendance for past session
        attendance1 = Attendance()
        attendance1.student_id = student1.id
        attendance1.session_id = session1.id
        attendance1.latitude = 18.0060
        attendance1.longitude = -76.7468
        attendance1.status = 'present'
        db.session.add(attendance1)
        db.session.commit()
        
        # Create course 2
        course2 = Course()
        course2.name = 'Database Systems'
        course2.code = 'COMP2210'
        course2.description = 'Fundamentals of database design and management'
        course2.credits = 3
        course2.semester = 'Fall 2024'
        course2.max_capacity = 35
        course2.lecturer_id = lecturer.id
        db.session.add(course2)
        db.session.commit()
        
        # Enroll students in course 2
        student1.courses.append(course2)
        student3.courses.append(course2)
        student4.courses.append(course2)
        db.session.commit()
        
        # Create active session for course 2
        session4 = Session()
        session4.course_id = course2.id
        session4.name = 'Introduction to Databases'
        session4.date = date.today()
        session4.start_time = time(9, 0)
        session4.duration_minutes = 90
        session4.location = 'Database Lab'
        session4.allowed_distance_meters = 100
        session4.lecturer_id = lecturer.id
        session4.latitude = 18.0060
        session4.longitude = -76.7468
        session4.status = 'active'
        db.session.add(session4)
        db.session.commit()
        
        # Create course 3 (unassigned to lecturer yet)
        course3 = Course()
        course3.name = 'Data Structures'
        course3.code = 'COMP2120'
        course3.description = 'Introduction to fundamental data structures'
        course3.credits = 3
        course3.semester = 'Fall 2024'
        course3.max_capacity = 45
        course3.lecturer_id = lecturer.id  # Assign to same lecturer for demo
        db.session.add(course3)
        db.session.commit()
        
        print("Demo data created successfully!")
        print(f"  - Users: {User.query.count()}")
        print(f"  - Admins: {Admin.query.count()}")
        print(f"  - Courses: {Course.query.count()}")
        print(f"  - Sessions: {Session.query.count()}")
        print(f"  - Students: {Student.query.count()}")
        print(f"  - Attendances: {Attendance.query.count()}")
        
        # Print demo credentials
        print("\nDemo Credentials:")
        print("  Admin: username='admin', password='admin123'")
        print("  Lecturer: username='lecturer', password='password123'")
        print("  Student: username='student', password='password123'")
        print("  Student 2: username='student2', password='password123'")
        print("  Student 3: username='student3', password='password123'")
        print("  Student 4: username='student4', password='password123'")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating demo data: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)