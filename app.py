import re
import string
from flask import Flask, render_template, request, jsonify, session as flask_session, redirect, url_for, flash, send_file, abort
from flask_cors import CORS
from datetime import datetime, timedelta
from database import InstitutionSignupRequest, db, Notification, User, Admin, Lecturer, Student, Course, Session as SessionModel, Attendance, RemovalRequest
from werkzeug.security import generate_password_hash
from sqlalchemy import or_
import secrets
import ipaddress
import io
import csv
import threading
import time
import os
from urllib.parse import urlparse



app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY_VALUE", secrets.token_hex(16))
CORS(app)

# Database configuration
if os.environ.get('DATABASE_URL'):
    # For PostgreSQL (Railway/Fly.io)
    db_url = os.environ.get('DATABASE_URL')
    result = urlparse(db_url)
    
    # SQLAlchemy 1.4.x uses postgresql:// not postgres://
    if result.scheme == 'postgres':
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'max_overflow': 20,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'pool_timeout': 30,
    }
else:
    # Local SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trackademia.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Authentication middleware
@app.before_request
def require_login():
    allowed_routes = ['login', 'static', 'health', 'institution_signup']
    if request.endpoint not in allowed_routes and 'user_id' not in flask_session:
        return redirect(url_for('login'))

# Context processor for pending requests count
@app.context_processor
def inject_pending_requests():
    """Inject pending requests count into all templates"""
    if flask_session.get('user_type') == 'admin':
        pending_count = db.session.query(RemovalRequest).filter_by(status='pending').count()
        return dict(pending_requests_count=pending_count)
    return dict(pending_requests_count=0)

# Check admin access
def require_admin():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))

# Routes
@app.route("/")
def index():
    user_id = flask_session.get("user_id")
    user_type = flask_session.get("user_type")

    # Not logged in → return 200 (prevents Railway health failure)
    if not user_id:
        return render_template("login.html"), 200

    if user_type == "super_admin":
        return redirect(url_for("super_admin_dashboard"))
    elif user_type == "admin":
        return redirect(url_for("admin_dashboard"))
    elif user_type == "lecturer":
        return redirect(url_for("lecturer_dashboard"))
    else:
        return redirect(url_for("student_dashboard"))




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = db.session.query(User).filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact administrator.', 'error')
                return render_template('login.html', error='Account deactivated')
            
            flask_session['user_id'] = user.id
            flask_session['user_type'] = user.user_type
            flask_session['name'] = user.name
            
            if user.user_type == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))
            elif user.user_type == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.user_type == 'lecturer':
                return redirect(url_for('lecturer_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        
        flash('Invalid credentials', 'error')
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    flask_session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Admin Routes

from functools import wraps
from datetime import datetime, date, timedelta

from flask import render_template, request, redirect, url_for, flash, session
from database import db, User, Student, Lecturer, Course, Session as ClassSession, Attendance, InstitutionSignupRequest


def require_super_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in.", "error")
            return redirect(url_for('login'))
        if session.get('user_type') != 'super_admin':
            flash("Unauthorized access.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


from math import ceil

from datetime import datetime, timedelta, date, time
from sqlalchemy import func, and_

from datetime import datetime, timedelta, time as dt_time

@app.route("/super-admin/dashboard")
def super_admin_dashboard():
    if "user_id" not in session or session.get("user_type") != "super_admin":
        flash("Unauthorized.", "error")
        return redirect(url_for("login"))

    view = request.args.get("view", "requests")

    # ---------- Top stats ----------
    total_users = User.query.count()
    total_students = User.query.filter_by(user_type="student").count()
    total_lecturers = User.query.filter_by(user_type="lecturer").count()
    total_courses = Course.query.count()
    total_sessions = SessionModel.query.count()
    pending_institution_count = InstitutionSignupRequest.query.filter_by(status="pending").count()

    # ---------- Today/This Week metrics ----------
    now = datetime.now()
    start_of_today = datetime.combine(now.date(), dt_time.min)
    start_of_tomorrow = start_of_today + timedelta(days=1)
    start_of_week = start_of_today - timedelta(days=6)

    # Sessions today (uses Session.date which is a DATE column)
    sessions_today = SessionModel.query.filter(SessionModel.date == now.date()).count()

    # Attendance check-ins today (uses Attendance.timestamp)
    checkins_today = Attendance.query.filter(
        Attendance.timestamp >= start_of_today,
        Attendance.timestamp < start_of_tomorrow
    ).count()

    # Late check-ins today (simple definition: any attendance marked 'late')
    # If your Attendance.status uses other values, tweak this.
    late_checkins_today = Attendance.query.filter(
        Attendance.timestamp >= start_of_today,
        Attendance.timestamp < start_of_tomorrow,
        Attendance.status == "late"
    ).count()

    # Failed verifications today (simple definition: status == 'failed')
    failed_verifications_today = Attendance.query.filter(
        Attendance.timestamp >= start_of_today,
        Attendance.timestamp < start_of_tomorrow,
        Attendance.status == "failed"
    ).count()

    # New users last 7 days
    new_users_week = User.query.filter(User.created_at >= start_of_week).count()

    # Courses created last 7 days
    courses_created_week = Course.query.filter(Course.created_at >= start_of_week).count()

    # ---------- Data for views ----------
    pending_institution_requests = []
    institutions_filtered = []
    all_accounts = []
    countries = []

    # Requests
    if view == "requests":
        pending_institution_requests = InstitutionSignupRequest.query.filter_by(status="pending") \
            .order_by(InstitutionSignupRequest.created_at.desc()).all()

    # Institutions
    if view == "institutions":
        inst_status = request.args.get("inst_status", "approved")
        inst_country = request.args.get("inst_country", "")
        inst_q = request.args.get("inst_q", "").strip()

        q = InstitutionSignupRequest.query

        if inst_status != "all":
            q = q.filter(InstitutionSignupRequest.status == inst_status)
        if inst_country:
            q = q.filter(InstitutionSignupRequest.country == inst_country)
        if inst_q:
            like = f"%{inst_q}%"
            q = q.filter(
                (InstitutionSignupRequest.institution_name.ilike(like)) |
                (InstitutionSignupRequest.contact_email.ilike(like)) |
                (InstitutionSignupRequest.contact_name.ilike(like))
            )

        institutions_filtered = q.order_by(InstitutionSignupRequest.created_at.desc()).all()
        countries = [c[0] for c in db.session.query(InstitutionSignupRequest.country).distinct().all() if c[0]]

    # Accounts
    if view == "accounts":
        acc_role = request.args.get("acc_role", "all")
        acc_status = request.args.get("acc_status", "all")
        acc_q = request.args.get("acc_q", "").strip()

        q = User.query

        if acc_role != "all":
            q = q.filter(User.user_type == acc_role)
        if acc_status == "active":
            q = q.filter(User.is_active.is_(True))
        elif acc_status == "disabled":
            q = q.filter(User.is_active.is_(False))

        if acc_q:
            like = f"%{acc_q}%"
            q = q.filter(
                (User.name.ilike(like)) |
                (User.username.ilike(like)) |
                (User.email.ilike(like))
            )

        all_accounts = q.order_by(User.created_at.desc()).all()

    return render_template(
        "super_admin_dashboard.html",
        view=view,

        # top stats
        total_users=total_users,
        total_students=total_students,
        total_lecturers=total_lecturers,
        total_courses=total_courses,
        total_sessions=total_sessions,
        pending_institution_count=pending_institution_count,

        # metrics
        sessions_today=sessions_today,
        checkins_today=checkins_today,
        late_checkins_today=late_checkins_today,
        failed_verifications_today=failed_verifications_today,
        new_users_week=new_users_week,
        courses_created_week=courses_created_week,

        # view data
        pending_institution_requests=pending_institution_requests,
        institutions_filtered=institutions_filtered,
        all_accounts=all_accounts,
        countries=countries,

        # pass back filter values so template keeps them
        inst_status=request.args.get("inst_status", "approved"),
        inst_country=request.args.get("inst_country", ""),
        inst_q=request.args.get("inst_q", ""),
        acc_role=request.args.get("acc_role", "all"),
        acc_status=request.args.get("acc_status", "all"),
        acc_q=request.args.get("acc_q", ""),
    )





def _make_temp_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

@app.route("/super-admin/institutions/<int:req_id>/approve", methods=["POST"])
@require_super_admin
def super_admin_approve_institution(req_id):
    req = InstitutionSignupRequest.query.get_or_404(req_id)

    if req.status != "pending":
        flash("This request is not pending.", "warning")
        return redirect(url_for("super_admin_dashboard", view="requests"))

    # Safety: ensure username is still free
    if User.query.filter_by(username=req.requested_admin_username).first():
        flash("Cannot approve: requested username is already taken.", "error")
        return redirect(url_for("super_admin_dashboard", view="requests"))

    temp_password = _make_temp_password()

    # Create the school admin user DISABLED
    new_admin = User(
        name=req.contact_name,
        username=req.requested_admin_username,
        email=req.contact_email,
        user_type="admin",
        is_active=False,  # ✅ disabled by default
        password_hash=generate_password_hash(temp_password),
        created_at=datetime.utcnow()
    )

    db.session.add(new_admin)
    db.session.flush()  # gives new_admin.id without commit

    req.status = "approved"
    req.reviewed_at = datetime.utcnow()
    req.reviewed_by_user_id = session.get("user_id")
    req.admin_user_id = new_admin.id

    db.session.commit()

    # MVP delivery: show temp password once (later you can email it)
    flash(
        f"Approved {req.institution_name}. Admin account created (DISABLED). "
        f"Username: {new_admin.username} | Temporary password: {temp_password}",
        "success"
    )
    return redirect(url_for("super_admin_dashboard", view="requests"))


@app.route('/super-admin/institutions/<int:req_id>/reject', methods=['POST'])
@require_super_admin
def super_admin_reject_institution(req_id):
    req = InstitutionSignupRequest.query.get_or_404(req_id)
    if req.status != 'pending':
        flash("This request is not pending.", "warning")
        return redirect(url_for('super_admin_dashboard', view='requests'))

    req.status = 'rejected'
    db.session.commit()
    flash(f"Rejected: {req.institution_name}", "success")
    return redirect(url_for('super_admin_dashboard', view='requests'))

@app.route("/super-admin/accounts/<int:user_id>/toggle-active", methods=["POST"])
@require_super_admin
def super_admin_toggle_user_active(user_id):
    u = User.query.get_or_404(user_id)

    # do not allow disabling yourself
    if session.get("user_id") == u.id:
        flash("You cannot change your own active status.", "warning")
        return redirect(safe_return_to(view="accounts"))

    u.is_active = not bool(u.is_active)
    db.session.commit()
    flash(f"Updated status for {u.username}.", "success")
    return redirect(safe_return_to(view="accounts"))


@app.route("/super-admin/accounts/<int:user_id>/reset-password", methods=["POST"])
@require_super_admin
def super_admin_reset_password(user_id):
    u = User.query.get_or_404(user_id)

    # Prevent resetting your own password accidentally from this screen
    if u.id == session.get("user_id"):
        flash("For safety, you can't reset your own password from here.", "error")
        return redirect(url_for("super_admin_dashboard", view="accounts"))

    temp_password = _make_temp_password()

    u.password_hash = generate_password_hash(temp_password)

    # ✅ Recommended: after reset, disable account until they confirm credentials
    u.is_active = False

    db.session.commit()

    flash(
        f"Password reset for {u.username}. Temporary password: {temp_password} "
        f"(Account has been DISABLED until you enable it.)",
        "success"
    )
    return redirect(safe_return_to(view="accounts"))

from urllib.parse import urlparse
from flask import request

def safe_return_to(default_endpoint="super_admin_dashboard", **default_kwargs):
    """
    Redirect back to a safe same-host URL sent by forms via return_to.
    Falls back to default endpoint.
    """
    return_to = request.form.get("return_to") or request.args.get("return_to")
    if return_to:
        # only allow relative paths to prevent open redirects
        parsed = urlparse(return_to)
        if parsed.scheme == "" and parsed.netloc == "":
            return return_to
    
    return url_for(default_endpoint, **default_kwargs)


@app.route("/super-admin/accounts/bulk", methods=["POST"], endpoint="super_admin_bulk_accounts_action")
def super_admin_bulk_accounts_action():
    if "user_id" not in session or session.get("user_type") != "super_admin":
        flash("Unauthorized.", "error")
        return redirect(url_for("login"))

    action = request.form.get("action", "").strip()
    user_ids = request.form.getlist("user_ids")

    if not user_ids:
        flash("No accounts selected.", "warning")
        return redirect(url_for("super_admin_dashboard", view="accounts"))

    users = User.query.filter(User.id.in_(user_ids)).all()

    if action == "disable":
        for u in users:
            if u.user_type == "super_admin":
                continue
            u.is_active = False
        db.session.commit()
        flash(f"Disabled {len(users)} account(s).", "success")

    elif action == "enable":
        for u in users:
            u.is_active = True
        db.session.commit()
        flash(f"Enabled {len(users)} account(s).", "success")

    elif action == "delete":
        for u in users:
            if u.user_type == "super_admin":
                continue
            db.session.delete(u)
        db.session.commit()
        flash(f"Deleted {len(users)} account(s).", "success")

    else:
        flash("Invalid bulk action.", "error")

    return redirect(url_for("super_admin_dashboard", view="accounts"))


@app.route("/super-admin/institutions/<int:req_id>")
@require_super_admin
def super_admin_institution_detail(req_id):
    inst = InstitutionSignupRequest.query.get_or_404(req_id)
    admin_user = User.query.get(inst.admin_user_id) if inst.admin_user_id else None
    return render_template("super_admin_institution_detail.html", inst=inst, admin_user=admin_user)



def _valid_username(u: str) -> bool:
    # allow letters, numbers, underscore, dot, dash
    return bool(re.fullmatch(r"[A-Za-z0-9._-]{3,30}", u or ""))

@app.route("/institution/signup", methods=["GET", "POST"])
def institution_signup():
    if request.method == "GET":
        return render_template("institution_signup.html")

    institution_name = (request.form.get("institution_name") or "").strip()
    contact_name = (request.form.get("contact_name") or "").strip()
    contact_email = (request.form.get("contact_email") or "").strip().lower()
    country = (request.form.get("country") or "").strip()
    requested_admin_username = (request.form.get("requested_admin_username") or "").strip()

    # Basic validation
    if not institution_name or not contact_name or not contact_email or not requested_admin_username:
        flash("Please fill in all required fields.", "error")
        return redirect(url_for("institution_signup"))

    if not _valid_username(requested_admin_username):
        flash("Username must be 3–30 characters and only letters, numbers, . _ -", "error")
        return redirect(url_for("institution_signup"))

    # Username must be unique across USERS and across existing REQUESTS
    existing_user = User.query.filter_by(username=requested_admin_username).first()
    if existing_user:
        flash("That username is already taken. Please choose another.", "error")
        return redirect(url_for("institution_signup"))

    existing_req = InstitutionSignupRequest.query.filter_by(requested_admin_username=requested_admin_username).first()
    if existing_req:
        flash("That username is already requested. Please choose another.", "error")
        return redirect(url_for("institution_signup"))

    # Optional: avoid spam duplicates by email+institution pending
    duplicate = InstitutionSignupRequest.query.filter_by(
        contact_email=contact_email,
        institution_name=institution_name,
        status="pending"
    ).first()
    if duplicate:
        flash("You already submitted a request for this institution. Please wait for review.", "warning")
        return redirect(url_for("login"))

    req = InstitutionSignupRequest(
        institution_name=institution_name,
        contact_name=contact_name,
        contact_email=contact_email,
        country=country or None,
        requested_admin_username=requested_admin_username,
        status="pending",
        created_at=datetime.utcnow()
    )
    db.session.add(req)
    db.session.commit()

    flash("Signup request submitted! You’ll be notified once it’s approved.", "success")
    return redirect(url_for("login"))


@app.route('/admin/dashboard')
def admin_dashboard():
    if flask_session.get('user_type') not in ['admin', 'super_admin']:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))


    # Get statistics
    total_users = db.session.query(User).count()
    total_students = db.session.query(Student).count()
    total_lecturers = db.session.query(Lecturer).count()
    total_courses = db.session.query(Course).count()
    total_sessions = db.session.query(SessionModel).count()

    pending_requests = db.session.query(RemovalRequest).filter_by(status='pending').count()

    recent_users = db.session.query(User).order_by(User.created_at.desc()).limit(5).all()
    recent_courses = db.session.query(Course).order_by(Course.created_at.desc()).limit(5).all()

    # ✅ Today / This Week summary
    now = datetime.now()
    today = now.date()
    start_of_today = datetime.combine(today, datetime.min.time())
    week_start = now - timedelta(days=7)

    sessions_today = db.session.query(SessionModel).filter(SessionModel.date == today).count()
    checkins_today = db.session.query(Attendance).filter(Attendance.timestamp >= start_of_today).count()

    new_users_week = db.session.query(User).filter(User.created_at >= week_start).count()
    courses_created_week = db.session.query(Course).filter(Course.created_at >= week_start).count()

    # NOTE: Your DB currently doesn't store "late" or "failed verification" explicitly,
    # so we'll show 0 for now until you add tracking.
    late_checkins_today = 0
    failed_verifications_today = 0

    return render_template(
        'admin_dashboard.html',
        total_users=total_users,
        total_students=total_students,
        total_lecturers=total_lecturers,
        total_courses=total_courses,
        total_sessions=total_sessions,
        pending_requests=pending_requests,
        recent_users=recent_users,
        recent_courses=recent_courses,

        # ✅ new summary vars
        sessions_today=sessions_today,
        checkins_today=checkins_today,
        late_checkins_today=late_checkins_today,
        failed_verifications_today=failed_verifications_today,
        new_users_week=new_users_week,
        courses_created_week=courses_created_week
    )


@app.route('/admin/users')
def admin_users():
    if flask_session.get('user_type') not in ['admin', 'super_admin']:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))

    
    users = db.session.query(User).order_by(User.user_type, User.name).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/create', methods=['GET', 'POST'])
def admin_create_user():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        name = request.form.get('name')
        email = request.form.get('email')
        user_type = request.form.get('user_type')
        password = request.form.get('password')
        
        # Check if username already exists
        existing_user = db.session.query(User).filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('admin_create_user.html')
        
        # Create user
        user = User(
            username=username,
            name=name,
            email=email,
            user_type=user_type,
            is_active=True
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Create profile based on user type
        if user_type == 'student':
            student = Student(
                user_id=user.id,
                student_id=request.form.get('student_id'),
                enrollment_year=request.form.get('enrollment_year'),
                major=request.form.get('major')
            )
            db.session.add(student)
        elif user_type == 'lecturer':
            lecturer = Lecturer(
                user_id=user.id,
                department=request.form.get('department'),
                employee_id=request.form.get('employee_id'),
                office_location=request.form.get('office_location'),
                office_hours=request.form.get('office_hours')
            )
            db.session.add(lecturer)
        elif user_type in ['admin', 'super_admin']:
            admin = Admin(
                user_id=user.id,
                role=request.form.get('role', 'administrator')
            )
            db.session.add(admin)

        
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin_create_user.html')

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('admin_users'))
    
    if request.method == 'POST':
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.is_active = request.form.get('is_active') == 'true'
        
        # Update profile based on user type
        if user.user_type == 'student':
            student = db.session.query(Student).filter_by(user_id=user.id).first()
            if student:
                student.student_id = request.form.get('student_id')
                student.enrollment_year = request.form.get('enrollment_year')
                student.major = request.form.get('major')
        elif user.user_type == 'lecturer':
            lecturer = db.session.query(Lecturer).filter_by(user_id=user.id).first()
            if lecturer:
                lecturer.department = request.form.get('department')
                lecturer.employee_id = request.form.get('employee_id')
                lecturer.office_location = request.form.get('office_location')
                lecturer.office_hours = request.form.get('office_hours')
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_users'))
    
    # Get profile data
    profile = None
    if user.user_type == 'student':
        profile = db.session.query(Student).filter_by(user_id=user.id).first()
    elif user.user_type == 'lecturer':
        profile = db.session.query(Lecturer).filter_by(user_id=user.id).first()
    elif user.user_type == 'admin':
        profile = db.session.query(Admin).filter_by(user_id=user.id).first()
    
    return render_template('admin_edit_user.html', user=user, profile=profile)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    user = db.session.get(User, user_id)
    if user:
        # Delete profile based on user type
        if user.user_type == 'student':
            student = db.session.query(Student).filter_by(user_id=user.id).first()
            if student:
                db.session.delete(student)
        elif user.user_type == 'lecturer':
            lecturer = db.session.query(Lecturer).filter_by(user_id=user.id).first()
            if lecturer:
                db.session.delete(lecturer)
        elif user.user_type == 'admin':
            admin = db.session.query(Admin).filter_by(user_id=user.id).first()
            if admin:
                db.session.delete(admin)
        
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/import', methods=['GET', 'POST'])
def admin_import_users():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'csv_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)  # Removed extra return
        
        if file and file.filename.endswith('.csv'):
            try:
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.DictReader(stream)
                
                imported_count = 0
                for row in csv_input:
                    # Check if username exists
                    existing_user = db.session.query(User).filter_by(username=row.get('username')).first()
                    if existing_user:
                        flash(f"Username {row.get('username')} already exists", 'warning')
                        continue
                    
                    # Create user
                    user = User(
                        username=row.get('username'),
                        name=row.get('name'),
                        email=row.get('email'),
                        user_type=row.get('user_type'),
                        is_active=True
                    )
                    user.set_password(row.get('password', 'password123'))
                    db.session.add(user)
                    db.session.commit()  # Commit to get user.id
                    
                    # Create profile
                    if user.user_type == 'student':
                        student = Student(
                            user_id=user.id,
                            student_id=row.get('student_id'),
                            enrollment_year=row.get('enrollment_year'),
                            major=row.get('major')
                        )
                        db.session.add(student)
                    elif user.user_type == 'lecturer':
                        lecturer = Lecturer(
                            user_id=user.id,
                            department=row.get('department'),
                            employee_id=row.get('employee_id'),
                            office_location=row.get('office_location'),
                            office_hours=row.get('office_hours')
                        )
                        db.session.add(lecturer)
                    elif user.user_type == 'admin':
                        admin = Admin(
                            user_id=user.id,
                            role=row.get('role', 'administrator')
                        )
                        db.session.add(admin)
                    
                    imported_count += 1
                
                db.session.commit()
                flash(f'Successfully imported {imported_count} users', 'success')
                return redirect(url_for('admin_users'))
                
            except Exception as e:
                flash(f'Error importing CSV: {str(e)}', 'error')
                return redirect(request.url)
    
    return render_template('admin_import_users.html')

@app.route('/admin/courses')
def admin_courses():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    courses = db.session.query(Course).order_by(Course.code).all()
    return render_template('admin_courses.html', courses=courses)

@app.route('/admin/courses/create', methods=['GET', 'POST'])
def admin_create_course():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    lecturers = db.session.query(Lecturer).all()
    
    if request.method == 'POST':
        course = Course(
            name=request.form.get('name'),
            code=request.form.get('code'),
            description=request.form.get('description'),
            credits=int(request.form.get('credits', 3)),
            semester=request.form.get('semester'),
            max_capacity=int(request.form.get('max_capacity', 30)),
            lecturer_id=int(request.form.get('lecturer_id')),
            is_active=request.form.get('is_active') == 'true'
        )
        
        db.session.add(course)
        db.session.commit()
        flash('Course created successfully', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin_create_course.html', lecturers=lecturers)

@app.route('/admin/courses/<int:course_id>/edit', methods=['GET', 'POST'])
def admin_edit_course(course_id):
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    course = db.session.get(Course, course_id)
    lecturers = db.session.query(Lecturer).all()
    
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('admin_courses'))
    
    if request.method == 'POST':
        course.name = request.form.get('name')
        course.code = request.form.get('code')
        course.description = request.form.get('description')
        course.credits = int(request.form.get('credits', 3))
        course.semester = request.form.get('semester')
        course.max_capacity = int(request.form.get('max_capacity', 30))
        course.lecturer_id = int(request.form.get('lecturer_id'))
        course.is_active = request.form.get('is_active') == 'true'
        
        db.session.commit()
        flash('Course updated successfully', 'success')
        return redirect(url_for('admin_courses'))
    
    return render_template('admin_edit_course.html', course=course, lecturers=lecturers)

@app.route('/admin/courses/<int:course_id>/enrollments')
def admin_course_enrollments(course_id):
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    course = db.session.get(Course, course_id)
    if not course:
        flash('Course not found', 'error')
        return redirect(url_for('admin_courses'))
    
    all_students = db.session.query(Student).all()
    enrolled_students = course.students
    available_students = [s for s in all_students if s not in enrolled_students]
    
    return render_template('admin_course_enrollments.html',
                         course=course,
                         enrolled_students=enrolled_students,
                         available_students=available_students)

@app.route('/admin/courses/enroll', methods=['POST'])
def admin_enroll_student():
    print(f"DEBUG: Enroll request - user_type: {flask_session.get('user_type')}")
    print(f"DEBUG: Request method: {request.method}")
    print(f"DEBUG: Request content type: {request.content_type}")
    print(f"DEBUG: Request form: {request.form}")
    print(f"DEBUG: Request json: {request.get_json(silent=True)}")
    
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Try to get data from both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    print(f"DEBUG: Parsed data: {data}")
    
    course_id = data.get('course_id')
    student_id = data.get('student_id')
    
    print(f"DEBUG: Course ID: {course_id}, Student ID: {student_id}")
    
    if not course_id or not student_id:
        return jsonify({'success': False, 'message': 'Missing course_id or student_id'}), 400
    
    course = db.session.get(Course, course_id)
    student = db.session.get(Student, student_id)
    
    if not course:
        return jsonify({'success': False, 'message': 'Course not found'}), 404
    if not student:
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    
    if len(course.students) >= course.max_capacity:
        return jsonify({'success': False, 'message': 'Course has reached maximum capacity'})
    
    if student not in course.students:
        course.students.append(student)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Student enrolled successfully'})
    else:
        return jsonify({'success': False, 'message': 'Student already enrolled in course'})

@app.route('/admin/courses/unenroll', methods=['POST'])
def admin_unenroll_student():
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Try to get data from both JSON and form data
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form
    
    course_id = data.get('course_id')
    student_id = data.get('student_id')
    
    if not course_id or not student_id:
        return jsonify({'success': False, 'message': 'Missing course_id or student_id'}), 400
    
    course = db.session.get(Course, course_id)
    student = db.session.get(Student, student_id)
    
    if not course:
        return jsonify({'success': False, 'message': 'Course not found'}), 404
    if not student:
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    
    if student in course.students:
        course.students.remove(student)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Student removed from course successfully'})
    else:
        return jsonify({'success': False, 'message': 'Student not enrolled in course'})

@app.route('/admin/removal-requests')
def admin_removal_requests():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Get all requests
    all_requests = db.session.query(RemovalRequest).order_by(RemovalRequest.created_at.desc()).all()
    
    # Separate pending and processed requests
    pending_requests = [r for r in all_requests if r.status == 'pending']
    recent_requests = [r for r in all_requests if r.status != 'pending'][:10]  # Last 10 processed
    
    return render_template('admin_removal_requests.html', 
                         pending_requests=pending_requests,
                         recent_requests=recent_requests)

# API endpoints for removal requests
@app.route('/api/removal-request/details/<int:request_id>')
def api_removal_request_details(request_id):
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    removal_request = db.session.get(RemovalRequest, request_id)
    if not removal_request:
        return jsonify({'success': False, 'message': 'Request not found'}), 404
    
    # Prepare response data
    data = {
        'success': True,
        'request': {
            'id': removal_request.id,
            'created_at': removal_request.created_at.isoformat(),
            'status': removal_request.status,
            'reason': removal_request.reason,
            'review_notes': removal_request.review_notes,
            'course': {
                'id': removal_request.course.id,
                'code': removal_request.course.code,
                'name': removal_request.course.name
            },
            'student': {
                'id': removal_request.student.id,
                'user': {
                    'name': removal_request.student.user.name,
                    'username': removal_request.student.user.username
                },
                'student_id': removal_request.student.student_id
            },
            'lecturer': {
                'id': removal_request.lecturer.id,
                'user': {
                    'name': removal_request.lecturer.user.name
                }
            },
            'admin_reviewer': {
                'user': {
                    'name': removal_request.admin_reviewer.user.name if removal_request.admin_reviewer else None
                }
            } if removal_request.admin_reviewer else None
        }
    }
    
    return jsonify(data)

@app.route('/api/admin/removal-request/reject/<int:request_id>', methods=['POST'])
def api_reject_removal_request(request_id):
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    removal_request = db.session.get(RemovalRequest, request_id)
    if not removal_request:
        return jsonify({'success': False, 'message': 'Request not found'}), 404
    
    # Get data from JSON
    if request.is_json:
        data = request.get_json()
        notes = data.get('notes', '')
    else:
        notes = request.form.get('notes', '')
    
    if not notes.strip():
        return jsonify({'success': False, 'message': 'Please provide a reason for rejection'}), 400
    
    # Update request status
    removal_request.status = 'rejected'
    removal_request.reviewed_by = flask_session.get('user_id')
    removal_request.reviewed_at = datetime.now()
    removal_request.review_notes = notes
    
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Request rejected successfully'})

@app.route('/api/admin/removal-request/approve/<int:request_id>', methods=['POST'])
def api_approve_removal_request(request_id):
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    removal_request = db.session.get(RemovalRequest, request_id)
    if not removal_request:
        return jsonify({'success': False, 'message': 'Request not found'}), 404

    # Get notes (optional)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        notes = data.get('notes', '')
    else:
        notes = request.form.get('notes', '')

    # Update request status
    removal_request.status = 'approved'
    removal_request.reviewed_by = flask_session.get('user_id')
    removal_request.reviewed_at = datetime.now()   # ✅ NOT datetime.now()
    removal_request.review_notes = notes

    # Remove student from course
    course = removal_request.course
    student = removal_request.student
    if student in course.students:
        course.students.remove(student)

    db.session.commit()
    return jsonify({'success': True, 'message': 'Request approved successfully'})

@app.route('/admin/reports')
def admin_reports():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Generate reports data
    total_attendance = db.session.query(Attendance).count()
    attendance_by_course = {}
    
    courses = db.session.query(Course).all()
    for course in courses:
        course_sessions = len(course.sessions)
        course_attendance = 0
        for session in course.sessions:
            course_attendance += len(session.attendance_records)
        attendance_by_course[course.name] = {
            'sessions': course_sessions,
            'attendance': course_attendance
        }
    
    # Get statistics for the template
    total_courses = db.session.query(Course).count()
    total_sessions = db.session.query(SessionModel).count()
    total_students = db.session.query(Student).count()
    total_lecturers = db.session.query(Lecturer).count()
    
    return render_template('admin_reports.html',
                         total_attendance=total_attendance,
                         attendance_by_course=attendance_by_course,
                         total_courses=total_courses,
                         total_sessions=total_sessions,
                         total_students=total_students,
                         total_lecturers=total_lecturers)

# Add these API endpoints that the template expects
@app.route('/api/reports/top-students')
def api_top_students():
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    offset = (page - 1) * limit
    
    # Get all students with their attendance statistics
    students = db.session.query(Student).all()
    student_data = []
    
    for student in students:
        # Calculate attendance statistics
        total_sessions = 0
        attended_sessions = 0
        
        for course in student.courses:
            total_sessions += len([s for s in course.sessions if s.status == 'past'])
            attended_sessions += db.session.query(Attendance).filter_by(
                student_id=student.id,
                status='present'
            ).join(SessionModel).filter(SessionModel.course_id == course.id).count()
        
        attendance_rate = 0
        if total_sessions > 0:
            attendance_rate = round((attended_sessions / total_sessions) * 100, 1)
        
        student_data.append({
            'id': student.id,
            'student_id': student.student_id,
            'name': student.user.name,
            'courses_count': len(student.courses),
            'total_sessions': total_sessions,
            'attended_sessions': attended_sessions,
            'attendance_rate': attendance_rate,
            'is_active': student.user.is_active
        })
    
    # Sort by attendance rate (highest first)
    student_data.sort(key=lambda x: x['attendance_rate'], reverse=True)
    
    # Apply pagination
    paginated_data = student_data[offset:offset + limit]
    
    return jsonify({
        'success': True,
        'students': paginated_data,
        'total': len(student_data),
        'page': page,
        'total_pages': (len(student_data) + limit - 1) // limit
    })

@app.route('/api/reports/export-all')
def export_all_reports():
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Create CSV data
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Course Code', 'Course Name', 'Lecturer', 'Enrolled', 'Sessions', 'Attendance', 'Attendance Rate'])
    
    # Write data
    courses = db.session.query(Course).all()
    for course in courses:
        course_sessions = len(course.sessions)
        course_attendance = 0
        for session in course.sessions:
            course_attendance += len(session.attendance_records)
        
        attendance_rate = 0
        if course_sessions > 0 and len(course.students) > 0:
            attendance_rate = round((course_attendance / (course_sessions * len(course.students))) * 100, 1)
        
        writer.writerow([
            course.code,
            course.name,
            course.lecturer.user.name if course.lecturer else 'N/A',
            len(course.students),
            course_sessions,
            course_attendance,
            f"{attendance_rate}%"
        ])
    
    # Return CSV file
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='trackademia_reports.csv'
    )

@app.route('/admin/reports/export')
def export_reports():
    if flask_session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    # Create CSV data
    output = io.StringIO()  # Changed from BytesIO to StringIO
    writer = csv.writer(output, delimiter=',')
    
    # Write header
    writer.writerow(['Course Name', 'Sessions', 'Attendance Records', 'Average Attendance'])
    
    # Get all courses
    courses = db.session.query(Course).all()
    
    # Write data for each course
    for course in courses:
        course_sessions = len(course.sessions)
        course_attendance = 0
        
        for session in course.sessions:
            course_attendance += len(session.attendance_records)
        
        # Calculate average attendance per session
        avg_attendance = 0
        if course_sessions > 0:
            avg_attendance = course_attendance / course_sessions
        
        writer.writerow([
            course.name,
            course_sessions,
            course_attendance,
            f"{avg_attendance:.1f}"
        ])
    
    # Add summary row
    writer.writerow([])  # Empty row
    writer.writerow(['SUMMARY', '', '', ''])
    total_sessions = db.session.query(SessionModel).count()  # Fixed: SessionModel instead of session
    total_attendance = db.session.query(Attendance).count()
    writer.writerow(['Total Sessions', total_sessions, '', ''])
    writer.writerow(['Total Attendance Records', total_attendance, '', ''])
    
    # Prepare response
    output.seek(0)
    
    # Convert to bytes
    csv_bytes = output.getvalue().encode('utf-8')
    
    return send_file(
        io.BytesIO(csv_bytes),
        as_attachment=True,
        download_name='trackademia_reports.csv',
        mimetype='text/csv'
    )
    

@app.route('/api/reports/custom')
def custom_report():
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Get parameters
    report_type = request.args.get('type', 'attendance')
    format_type = request.args.get('format', 'csv')
    
    # For now, just return the full export
    if format_type == 'csv':
        return export_all_reports()
    else:
        # For PDF or other formats, return a placeholder
        flash(f'Custom {report_type} report in {format_type.upper()} format requested', 'info')
        return redirect(url_for('admin_reports'))


# Lecturer Routes
@app.route('/lecturer/dashboard')
def lecturer_dashboard():
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        flask_session.clear()
        return redirect(url_for('login'))
    
    courses = db.session.query(Course).filter_by(lecturer_id=lecturer.id).all()
    total_sessions = db.session.query(SessionModel).filter_by(lecturer_id=lecturer.id).count()
    
    total_students = 0
    for course in courses:
        total_students += len(course.students)
    
    active_sessions = db.session.query(SessionModel).filter_by(
        lecturer_id=lecturer.id, 
        status='active'
    ).all()
    
    return render_template('lecturer_dashboard.html', 
                         lecturer=lecturer,
                         courses=courses,
                         total_sessions=total_sessions,
                         total_students=total_students,
                         active_sessions=active_sessions)

@app.route('/lecturer/create-session', methods=['GET', 'POST'])
def create_session():
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        flash('Please login as a lecturer', 'error')
        return redirect(url_for('login'))
    
    # Get lecturer's courses for dropdown
    courses = db.session.query(Course).filter_by(lecturer_id=lecturer.id).all()
    
    if request.method == 'POST':
        course_id = request.form.get('course_id')
        session_name = request.form.get('session_name')
        date = request.form.get('date')
        start_time = request.form.get('start_time')
        duration = request.form.get('duration')
        location = request.form.get('location')
        allowed_distance = request.form.get('allowed_distance_meters')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        allowed_ip_range = request.form.get('allowed_ip_range')
        
        if not latitude or not longitude:
            flash('Please capture the lecture room location first', 'error')
            return render_template('create_session.html', 
                                 courses=courses,
                                 error='Please capture the lecture room location first')

        new_session = SessionModel(
            course_id=int(course_id),
            name=session_name,
            date=datetime.strptime(date, '%Y-%m-%d').date(),
            start_time=datetime.strptime(start_time, '%H:%M').time(),
            duration_minutes=int(duration),
            location=location,
            allowed_distance_meters=int(allowed_distance) if allowed_distance else 50,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None,
            allowed_ip_range=allowed_ip_range if allowed_ip_range else None,
            lecturer_id=lecturer.id,
            status='upcoming'
        )
        
        db.session.add(new_session)
        db.session.commit()
        flash('Session created successfully', 'success')
        return redirect(url_for('my_sessions'))
    
    return render_template('create_session.html', courses=courses)

@app.route('/lecturer/my-sessions')
def my_sessions():
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        flash('Please login as a lecturer', 'error')
        return redirect(url_for('login'))
    
    # Get all sessions for this lecturer
    sessions = db.session.query(SessionModel).filter_by(lecturer_id=lecturer.id).order_by(SessionModel.date.desc(), SessionModel.start_time.desc()).all()
    
    # Categorize sessions
    now = datetime.now()
    for session_obj in sessions:
        session_datetime = datetime.combine(session_obj.date, session_obj.start_time)
        end_datetime = session_datetime + timedelta(minutes=session_obj.duration_minutes)
        
        if session_obj.status == 'active':
            if now > end_datetime:
                session_obj.status = 'past'
                db.session.commit()
        elif session_obj.status == 'upcoming':
            if session_datetime <= now <= end_datetime:
                session_obj.status = 'active'
                db.session.commit()
            elif now > end_datetime:
                session_obj.status = 'past'
                db.session.commit()
    
    return render_template('my_sessions.html', sessions=sessions)

@app.route('/lecturer/attendance-report/<int:session_id>')
def attendance_report(session_id):
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        flash('Please login as a lecturer', 'error')
        return redirect(url_for('login'))
    
    session_obj = db.session.get(SessionModel, session_id)
    
    if not session_obj:
        flash('Session not found', 'error')
        return redirect(url_for('my_sessions'))
    
    # Security check: ensure lecturer owns this session
    if session_obj.lecturer_id != lecturer.id:
        flash('You do not have permission to view this session', 'error')
        return redirect(url_for('my_sessions'))
    
    # Get all students enrolled in the course
    course_students = session_obj.course.students
    
    # Get attendance records for this session
    attendance_records = db.session.query(Attendance).filter_by(session_id=session_id).all()
    
    # Create a dictionary for quick lookup
    attendance_dict = {record.student_id: record for record in attendance_records}
    
    # Prepare report data
    report_data = []
    for student in course_students:
        attendance = attendance_dict.get(student.id)
        report_data.append({
            'student': student,
            'attendance': attendance,
            'status': attendance.status if attendance else 'absent',
            'marked_time': attendance.timestamp if attendance else None,
            'location': f"{attendance.latitude:.6f}, {attendance.longitude:.6f}" if attendance else 'N/A'
        })
    
    # Sort by student name
    report_data.sort(key=lambda x: x['student'].user.name)
    
    # Calculate statistics
    total_students = len(course_students)
    present_count = len([r for r in report_data if r['status'] == 'present'])
    absent_count = total_students - present_count
    attendance_rate = (present_count / total_students * 100) if total_students > 0 else 0
    
    return render_template('attendance_report.html',
                         session=session_obj,
                         report_data=report_data,
                         total_students=total_students,
                         present_count=present_count,
                         absent_count=absent_count,
                         attendance_rate=round(attendance_rate, 1))

@app.route('/api/session/update-status', methods=['POST'])
def update_session_status():
    session_id = request.json.get('session_id')
    new_status = request.json.get('status')
    
    session_obj = db.session.get(SessionModel, session_id)
    if session_obj:
        session_obj.status = new_status
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False}), 400

@app.route('/lecturer/manage-students/<int:course_id>')
def manage_students(course_id):
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        flash('Please login as a lecturer', 'error')
        return redirect(url_for('login'))
    
    course = db.session.get(Course, course_id)
    
    # Check if lecturer owns this course
    if course.lecturer_id != lecturer.id:
        flash('You do not have permission to manage this course', 'error')
        return redirect(url_for('lecturer_dashboard'))
    
    all_students = db.session.query(Student).all()
    
    # Get students not in this course
    available_students = [s for s in all_students if s not in course.students]
    
    return render_template('manage_students.html', 
                         course=course,
                         available_students=available_students)

@app.route('/api/course/add-student', methods=['POST'])
def add_student_to_course():
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    course_id = request.json.get('course_id')
    student_id = request.json.get('student_id')
    
    course = db.session.get(Course, course_id)
    student = db.session.get(Student, student_id)
    
    # Check if lecturer owns this course
    if course.lecturer_id != lecturer.id:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if course and student:
        if len(course.students) >= course.max_capacity:
            return jsonify({'success': False, 'message': 'Course has reached maximum capacity'})
        
        if student not in course.students:
            course.students.append(student)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Student already in course'})
    
    return jsonify({'success': False, 'message': 'Invalid course or student'}), 400

@app.route('/api/course/remove-student', methods=['POST'])
def remove_student_from_course():
    lecturer_id = flask_session.get('user_id')
    lecturer = db.session.query(Lecturer).filter_by(user_id=lecturer_id).first()
    
    if not lecturer:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    course_id = request.json.get('course_id')
    student_id = request.json.get('student_id')
    
    course = db.session.get(Course, course_id)
    student = db.session.get(Student, student_id)
    
    # Check if lecturer owns this course
    if course.lecturer_id != lecturer.id:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    if course and student:
        if student in course.students:
            # Create removal request for admin review
            removal_request = RemovalRequest(
                student_id=student.id,
                course_id=course.id,
                lecturer_id=lecturer.id,
                reason=request.json.get('reason', 'No reason provided'),
                status='pending'
            )
            db.session.add(removal_request)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Removal request submitted for admin review'})
        else:
            return jsonify({'success': False, 'message': 'Student not enrolled in course'})
    
    return jsonify({'success': False, 'message': 'Invalid course or student'}), 400

@app.route('/student/dashboard')
def student_dashboard():
    student_id = flask_session.get('user_id')
    student = db.session.query(Student).filter_by(user_id=student_id).first()
    
    if not student:
        flask_session.clear()
        flash('Please login as a student', 'error')
        return redirect(url_for('login'))
    
    # Get upcoming sessions for student's courses
    upcoming_sessions = []
    for course in student.courses:
        for session_obj in course.sessions:
            if session_obj.status == 'upcoming':
                upcoming_sessions.append(session_obj)
    
    # Get today's active sessions for quick access
    today = datetime.now().date()
    today_active_sessions = []
    for course in student.courses:
        for session_obj in course.sessions:
            if session_obj.status == 'active' and session_obj.date == today:
                today_active_sessions.append(session_obj)
    
    # NEW: sessions starting in the next 15 minutes
    now = datetime.now()
    time_threshold = now + timedelta(minutes=15)
    soon_sessions = []
    for s in upcoming_sessions:
        session_dt = datetime.combine(s.date, s.start_time)
        if now <= session_dt <= time_threshold:
            soon_sessions.append(s)
    
    return render_template(
        'student_dashboard.html',
        student=student,
        upcoming_sessions=upcoming_sessions,
        today_active_sessions=today_active_sessions,
        soon_sessions=soon_sessions,   # pass this to the template
    )


@app.route('/student/mark-attendance')
def mark_attendance():
    student_id = flask_session.get('user_id')
    student = db.session.query(Student).filter_by(user_id=student_id).first()

    if not student:
        flash('Please login as a student', 'error')
        return redirect(url_for('login'))

    requested_session_id = request.args.get('session_id', type=int)  # <-- ADD THIS

    active_sessions_list = []
    for course in student.courses:
        for session_obj in course.sessions:
            if session_obj.status == 'active':
                existing = db.session.query(Attendance).filter_by(
                    student_id=student.id,
                    session_id=session_obj.id
                ).first()

                active_sessions_list.append({
                    'id': session_obj.id,
                    'name': session_obj.name,
                    'course_name': course.name,
                    'location': session_obj.location,
                    'already_marked': existing is not None,
                    'marked_time': existing.timestamp if existing else None
                })

    return render_template(
        'mark_attendance.html',
        sessions=active_sessions_list,
        requested_session_id=requested_session_id  # <-- PASS IT
    )


@app.route('/api/student/details/<int:student_id>')
def api_student_details(student_id):
    if flask_session.get('user_type') != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    student = db.session.get(Student, student_id)
    if not student:
        return jsonify({'success': False, 'message': 'Student not found'}), 404
    
    return jsonify({
        'success': True,
        'student': {
            'id': student.id,
            'student_id': student.student_id,
            'major': student.major,
            'enrollment_year': student.enrollment_year,
            'user': {
                'name': student.user.name,
                'email': student.user.email,
                'is_active': student.user.is_active
            },
            'courses_count': len(student.courses)
        }
    })

from location_check import check_attendance_location

@app.route('/api/attendance/mark', methods=['POST'])
def mark_attendance_api():
    student_id = flask_session.get('user_id')
    student = db.session.query(Student).filter_by(user_id=student_id).first()
    session_id = request.json.get('session_id')
    
    if not student:
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    # Get session
    session_obj = db.session.get(SessionModel, session_id)
    
    # 1. Get student's location from browser
    student_lat = request.json.get('latitude')
    student_lon = request.json.get('longitude')
    accuracy = request.json.get('accuracy')
    
    if not student_lat or not student_lon:
        return jsonify({
            'success': False,
            'message': 'Could not get your location. Please enable location services.'
        }), 400
    
    # 2. Check location - make sure session has coordinates
    if not session_obj.latitude or not session_obj.longitude:
        return jsonify({
            'success': False,
            'message': 'This session does not have location data configured.'
        }), 400
    
    is_within_range, distance = check_attendance_location(
        student_lat, student_lon,
        session_obj.latitude, session_obj.longitude,
        session_obj.allowed_distance_meters,
        accuracy
    )
    
    # 3. Optional: Check network (simplified)
    ip_valid = True
    if session_obj.allowed_ip_range:
        client_ip = request.remote_addr
        try:
            network = ipaddress.ip_network(session_obj.allowed_ip_range)
            ip_valid = ipaddress.ip_address(client_ip) in network
        except:
            ip_valid = False
    
    # 4. Mark attendance if valid
    if is_within_range and ip_valid:
        # Check if already marked attendance
        existing = db.session.query(Attendance).filter_by(
            student_id=student.id,
            session_id=session_id
        ).first()
        
        if existing:
            return jsonify({
                'success': False,
                'message': 'You have already marked attendance for this session.'
            }), 400
        
        attendance = Attendance(
            student_id=student.id,
            session_id=session_id,
            latitude=student_lat,
            longitude=student_lon,
            status='present',
            verified_by='system',
            timestamp=datetime.now()  # Changed from datetime.utcnow()
        )
        db.session.add(attendance)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Attendance marked! You were {distance:.1f}m from the lecture room.',
            'distance': distance,
            'timestamp': attendance.timestamp.strftime('%Y-%m-%d %H:%M:%S')  # Add formatted timestamp
        })
    else:
        return jsonify({
            'success': False,
            'message': f'Cannot mark attendance: {"Too far from lecture room" if not is_within_range else "Not on campus network"}',
            'distance': distance,
            'max_allowed': session_obj.allowed_distance_meters,
            'within_range': is_within_range,
            'network_valid': ip_valid
        }), 403

@app.route('/student/attendance-analytics')
def attendance_analytics():
    student_id = flask_session.get('user_id')
    student = db.session.query(Student).filter_by(user_id=student_id).first()
    
    if not student:
        flash('Please login as a student', 'error')
        return redirect(url_for('login'))
    
    # Calculate attendance statistics
    analytics = []
    for course in student.courses:
        # Count only past sessions
        past_sessions = [s for s in course.sessions if s.status == 'past']
        total_sessions = len(past_sessions)
        
        attended_sessions = db.session.query(Attendance).filter_by(
            student_id=student.id,
            status='present'
        ).join(SessionModel).filter(SessionModel.course_id == course.id).count()
        
        percentage = (attended_sessions / total_sessions * 100) if total_sessions > 0 else 0
        
        analytics.append({
            'course_name': course.name,
            'total_sessions': total_sessions,
            'attended_sessions': attended_sessions,
            'percentage': round(percentage, 1)
        })
    
    return render_template('attendance_analytics.html', analytics=analytics)

@app.route("/student/attendance-history")
def student_attendance_history():
    if flask_session.get("user_type") != "student":
        flash("Access denied", "error")
        return redirect(url_for("login"))

    user_id = flask_session.get("user_id")
    student = db.session.query(Student).filter_by(user_id=user_id).first()
    if not student:
        flash("Student profile not found", "error")
        return redirect(url_for("login"))

    today = date.today()

    course_summaries = []
    for course in student.courses:
        # Past sessions for this course
        past_sessions = (
            db.session.query(SessionModel)
            .filter(
                SessionModel.course_id == course.id,
                SessionModel.status == "past"
            )
            .order_by(SessionModel.date.desc(), SessionModel.start_time.desc())
            .all()
        )

        # Attendance records for this student in this course
        records = (
            db.session.query(Attendance, SessionModel)
            .join(SessionModel, Attendance.session_id == SessionModel.id)
            .filter(
                Attendance.student_id == student.id,
                SessionModel.course_id == course.id
            )
            .order_by(SessionModel.date.desc(), SessionModel.start_time.desc())
            .all()
        )

        # Quick lookup: session_id -> attendance
        att_by_session = {s.id: a for (a, s) in records}

        present = sum(1 for (a, _s) in records if a.status == "present")
        late = sum(1 for (a, _s) in records if a.status == "late")
        excused = sum(1 for (a, _s) in records if a.status == "excused")
        attended = present + late + excused

        total_past = len(past_sessions)
        absent = max(total_past - attended, 0)
        rate = round((attended / total_past) * 100, 1) if total_past else 0

        # Build a detailed list (every past session + status)
        detailed = []
        for s in past_sessions:
            a = att_by_session.get(s.id)
            detailed.append({
                "session": s,
                "status": a.status if a else "absent",
                "marked_time": a.timestamp if a else None
            })

        course_summaries.append({
            "course": course,
            "rate": rate,
            "total_past": total_past,
            "present": present,
            "late": late,
            "excused": excused,
            "absent": absent,
            "detailed": detailed
        })

    return render_template(
        "student_attendance_history.html",
        student=student,
        course_summaries=course_summaries
    )

@app.route("/student/notifications")
def student_notifications():
    if flask_session.get("user_type") != "student":
        flash("Access denied", "error")
        return redirect(url_for("login"))

    user_id = flask_session.get("user_id")
    notifications = (
        db.session.query(Notification)
        .filter(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
        .all()
    )
    unread_count = sum(1 for n in notifications if not n.is_read)

    return render_template(
        "student_notifications.html",
        notifications=notifications,
        unread_count=unread_count
    )

@app.route("/api/notifications/mark-read/<int:notif_id>", methods=["POST"])
def api_mark_notification_read(notif_id):
    user_id = flask_session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    notif = db.session.get(Notification, notif_id)
    if not notif or notif.user_id != user_id:
        return jsonify({"success": False, "message": "Not found"}), 404

    notif.is_read = True
    db.session.commit()
    return jsonify({"success": True})




# Profiles______________________________________________________
# Profile Routes
@app.route('/profile')
def profile():
    """Main profile page - redirects to appropriate profile based on user type"""
    user_type = flask_session.get('user_type')
    
    if not user_type:
        flash('Please login to view profile', 'error')
        return redirect(url_for('login'))
    
    if user_type == 'admin':
        return redirect(url_for('admin_profile'))
    elif user_type == 'lecturer':
        return redirect(url_for('lecturer_profile'))
    elif user_type == 'student':
        return redirect(url_for('student_profile'))
    else:
        flash('Please login to view profile', 'error')
        return redirect(url_for('login'))

@app.route('/profile/admin')
def admin_profile():
    """Admin profile page"""
    print(f"DEBUG ADMIN PROFILE: User type: {flask_session.get('user_type')}")
    print(f"DEBUG ADMIN PROFILE: User ID: {flask_session.get('user_id')}")
    
    if flask_session.get('user_type') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    user_id = flask_session.get('user_id')
    user = db.session.get(User, user_id)
    
    print(f"DEBUG ADMIN PROFILE: User found: {user}")
    print(f"DEBUG ADMIN PROFILE: User username: {user.username if user else 'None'}")
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    admin_profile = db.session.query(Admin).filter_by(user_id=user.id).first()
    print(f"DEBUG ADMIN PROFILE: Admin profile found: {admin_profile}")
    
    # Make sure admin_profile exists
    if not admin_profile:
        print(f"DEBUG ADMIN PROFILE: Creating admin profile for user_id: {user.id}")
        # Create admin profile if it doesn't exist
        admin_profile = Admin(user_id=user.id, role='administrator')
        db.session.add(admin_profile)
        db.session.commit()
        print(f"DEBUG ADMIN PROFILE: Admin profile created: {admin_profile}")
    
    print(f"DEBUG ADMIN PROFILE: Rendering template...")
    return render_template('admin_profile.html',
                            user=user, admin=admin_profile)

@app.route('/profile/lecturer')
def lecturer_profile():
    """Lecturer profile page"""
    if flask_session.get('user_type') != 'lecturer':
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    user_id = flask_session.get('user_id')
    user = db.session.get(User, user_id)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    lecturer_profile = db.session.query(Lecturer).filter_by(user_id=user.id).first()
    
    if not lecturer_profile:
        flash('Lecturer profile not found', 'error')
        return redirect(url_for('login'))
    
    # Get lecturer's courses
    courses = db.session.query(Course).filter_by(lecturer_id=lecturer_profile.id).all()
    
    return render_template('lecturer_profile.html', 
                         user=user, 
                         lecturer=lecturer_profile,
                         courses=courses)

@app.route('/profile/student')
def student_profile():
    """Student profile page"""
    if flask_session.get('user_type') != 'student':
        flash('Access denied', 'error')
        return redirect(url_for('login'))
    
    user_id = flask_session.get('user_id')
    user = db.session.get(User, user_id)
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    student_profile = db.session.query(Student).filter_by(user_id=user.id).first()
    
    # Get student's courses and attendance statistics
    courses = []
    if student_profile:
        for course in student_profile.courses:
            # Count past sessions
            past_sessions = [s for s in course.sessions if s.status == 'past']
            total_sessions = len(past_sessions)
            
            # Count attended sessions
            attended_sessions = db.session.query(Attendance).filter_by(
                student_id=student_profile.id,
                status='present'
            ).join(SessionModel).filter(SessionModel.course_id == course.id).count()
            
            attendance_rate = 0
            if total_sessions > 0:
                attendance_rate = round((attended_sessions / total_sessions) * 100, 1)
            
            courses.append({
                'course': course,
                'total_sessions': total_sessions,
                'attended_sessions': attended_sessions,
                'attendance_rate': attendance_rate
            })
    
    return render_template('student_profile.html', 
                         user=user, 
                         student=student_profile,
                         courses=courses)

@app.route('/profile/update', methods=['POST'])
def update_profile():
    """Update user profile information for all user types"""
    user_id = flask_session.get('user_id')
    user_type = flask_session.get('user_type')
    
    if not user_id:
        return jsonify({'success': False, 'message': 'Not logged in'}), 401
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    try:
        # Update basic user info
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form
        
        print(f"DEBUG UPDATE PROFILE: Data received: {data}")
        print(f"DEBUG UPDATE PROFILE: User type: {user_type}")
        
        # Update basic user fields
        if 'name' in data:
            user.name = data.get('name')
            flask_session['name'] = user.name  # Update session name
        
        if 'email' in data:
            user.email = data.get('email')
        
        # Update password if provided
        new_password = data.get('new_password')
        if new_password:
            current_password = data.get('current_password')
            if not current_password:
                return jsonify({'success': False, 'message': 'Current password required'}), 400
            
            if not user.check_password(current_password):
                return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
            
            if len(new_password) < 6:
                return jsonify({'success': False, 'message': 'New password must be at least 6 characters'}), 400
            
            user.set_password(new_password)
        
        # Update profile based on user type
        if user_type == 'student':
            student = db.session.query(Student).filter_by(user_id=user.id).first()
            if student:
                if 'major' in data:
                    student.major = data.get('major')
                if 'enrollment_year' in data:
                    student.enrollment_year = data.get('enrollment_year')
                if 'student_id' in data:
                    student.student_id = data.get('student_id')
        
        elif user_type == 'lecturer':
            lecturer = db.session.query(Lecturer).filter_by(user_id=user.id).first()
            if lecturer:
                if 'department' in data:
                    lecturer.department = data.get('department')
                if 'office_location' in data:
                    lecturer.office_location = data.get('office_location')
                if 'office_hours' in data:
                    lecturer.office_hours = data.get('office_hours')
                if 'employee_id' in data:
                    lecturer.employee_id = data.get('employee_id')
        
        elif user_type == 'admin':
            admin = db.session.query(Admin).filter_by(user_id=user.id).first()
            if admin:
                if 'role' in data:
                    admin.role = data.get('role')
            else:
                # Create admin profile if it doesn't exist
                admin = Admin(user_id=user.id, role=data.get('role', 'administrator'))
                db.session.add(admin)
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Profile updated successfully',
            'name': user.name  # Return updated name for session update
        })
    
    except Exception as e:
        db.session.rollback()
        print(f"DEBUG UPDATE PROFILE: Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error updating profile: {str(e)}'}), 500



def check_upcoming_sessions():
    """Check for sessions starting in 15 minutes and send notifications"""
    with app.app_context():
        try:
            now = datetime.now()
            time_threshold = now + timedelta(minutes=15)
            
            # Find sessions starting within the next 15 minutes
            upcoming_sessions = db.session.query(SessionModel).filter(
                SessionModel.status == 'upcoming',
                SessionModel.date == now.date(),
                SessionModel.start_time.between(
                    now.time(),
                    time_threshold.time()
                )
            ).all()
            
            for session in upcoming_sessions:
                # For each student in the course
                for student in session.course.students:
                    # Here you would implement actual notification logic
                    # For now, we'll just log it
                    print(f"NOTIFICATION: {student.user.name} - {session.course.name} starts in 15 minutes at {session.start_time}")
                    
                    # You could add this to a notifications table:
                    notification = Notification(
                        user_id=student.user_id,
                        message=f"Upcoming: {session.course.name} ({session.name}) starts in 15 minutes",
                        type='reminder',
                    )
                    db.session.add(notification)
            
            db.session.commit()
            
        except Exception as e:
            print(f"Error checking upcoming sessions: {e}")

# Add this to run the notification checker in a separate thread
def start_notification_checker():
    """Start background thread to check for notifications"""
    def notification_loop():
        while True:
            check_upcoming_sessions()
            time.sleep(60)  # Check every minute
    
    thread = threading.Thread(target=notification_loop, daemon=True)
    thread.start()



def initialize_database():
    """Initialize the database tables and data"""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✅ Database tables created/checked")
            
            # Check if we need to create demo data
            from database import create_demo_data
            if db.session.query(User).count() == 0:
                print("📊 Creating demo data...")
                create_demo_data()
                print("✅ Demo data created")
            else:
                print("ℹ️ Database already has data")
                
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
     # Initialize database BEFORE starting the server
    print("🚀 Initializing Trackademia...")
    print(f"📊 Database URI: {app.config['SQLALCHEMY_DATABASE_URI'][:30]}...")
    
    # Initialize database
    initialize_database()
    
    print(f"✅ Starting server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
    