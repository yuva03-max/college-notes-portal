import os
import logging
import secrets
import smtplib
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, render_template, redirect, url_for, flash, request, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

if not os.environ.get("SESSION_SECRET"):
    os.environ["SESSION_SECRET"] = "dev-secret-key-change-in-production-12345"

if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite:///database.db"

EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")

logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'xls', 'xlsx', 'zip', 'rar'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    enrollment_number = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    otp_code = db.Column(db.String(6), nullable=True)
    otp_created_at = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0)
    
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_created_at = db.Column(db.DateTime, nullable=True)
    
    notes = db.relationship('Note', backref='uploader', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(100))
    semester = db.Column(db.String(50))
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    file_size = db.Column(db.Integer)
    description = db.Column(db.Text)


with app.app_context():
    db.create_all()


def send_email(to_email, subject, html_content):
    if not EMAIL_USER or not EMAIL_PASSWORD:
        logging.warning("Email credentials not configured - email not sent")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = to_email
        
        part = MIMEText(html_content, 'html')
        msg.attach(part)
        
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)
        
        return True
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return False


def send_otp_email(email, otp_code, username):
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                <h2 style="color: #4361ee;">College Notes Portal</h2>
                <p>Hello {username},</p>
                <p>Your One-Time Password (OTP) for login is:</p>
                <div style="background-color: white; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
                    <h1 style="color: #4361ee; letter-spacing: 5px; margin: 0;">{otp_code}</h1>
                </div>
                <p>This OTP is valid for 10 minutes.</p>
                <p style="color: #dc2626; font-weight: bold;">Do not share this OTP with anyone.</p>
                <p>If you didn't request this OTP, please ignore this email.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e2e8f0;">
                <p style="color: #64748b; font-size: 12px;">College Notes Portal</p>
            </div>
        </body>
    </html>
    """
    return send_email(email, 'College Notes Portal - Login OTP', html)


def send_reset_email(email, reset_link, username):
    html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                <h2 style="color: #4361ee;">College Notes Portal</h2>
                <p>Hello {username},</p>
                <p>We received a request to reset your password. Click the button below to set a new password:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background-color: #4361ee; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold;">Reset Password</a>
                </div>
                <p>Or copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #4361ee;">{reset_link}</p>
                <p>This link is valid for 1 hour.</p>
                <p style="color: #dc2626; font-weight: bold;">If you didn't request a password reset, please ignore this email.</p>
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #e2e8f0;">
                <p style="color: #64748b; font-size: 12px;">College Notes Portal</p>
            </div>
        </body>
    </html>
    """
    return send_email(email, 'College Notes Portal - Password Reset', html)


def generate_otp():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])


def generate_reset_token():
    return secrets.token_urlsafe(32)


def is_otp_valid(user):
    if not user.otp_created_at:
        return False
    expiry_time = user.otp_created_at + timedelta(minutes=10)
    return datetime.utcnow() < expiry_time


def is_reset_token_valid(user):
    if not user.reset_token_created_at:
        return False
    expiry_time = user.reset_token_created_at + timedelta(hours=1)
    return datetime.utcnow() < expiry_time


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            user = current_user()
            if user.role != role:
                flash('You are not authorized to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.context_processor
def inject_user():
    return dict(current_user=current_user())


@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        role = request.form.get('role', '')
        
        if role not in ['student', 'professor']:
            flash('Invalid role selected.', 'danger')
            return render_template('register.html')
        
        enrollment_number = None
        if role == 'student':
            enrollment_number = request.form.get('enrollment_number', '').strip().upper()
            if not enrollment_number:
                flash('Enrollment number is required for students.', 'danger')
                return render_template('register.html')
        
        if not all([username, email, password, confirm_password, role]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        if role == 'student' and enrollment_number:
            existing_user = User.query.filter(
                (User.username == username) | 
                (User.email == email) | 
                (User.enrollment_number == enrollment_number)
            ).first()
        else:
            existing_user = User.query.filter(
                (User.username == username) | 
                (User.email == email)
            ).first()
        
        if existing_user:
            if existing_user.username == username:
                flash('Username already exists.', 'danger')
            elif existing_user.email == email:
                flash('Email already registered.', 'danger')
            elif role == 'student' and existing_user.enrollment_number == enrollment_number:
                flash('Enrollment number already registered.', 'danger')
            return render_template('register.html')
        
        new_user = User(
            username=username,
            enrollment_number=enrollment_number,
            email=email,
            role=role
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        password = request.form.get('password', '')
        login_method = request.form.get('login_method', 'password')
        
        if not login_id:
            flash('Please enter your email (or enrollment number for students).', 'danger')
            return render_template('login.html')
        
        user = None
        if '@' in login_id:
            user = User.query.filter_by(email=login_id.lower()).first()
        else:
            user = User.query.filter_by(enrollment_number=login_id.upper()).first()
            if not user:
                flash('Enrollment number not found. Professors should login with email.', 'danger')
                return render_template('login.html')
        
        if not user:
            flash('Account not found. Please check your credentials or register first.', 'danger')
            return render_template('login.html')
        
        if login_method == 'otp':
            otp_code = generate_otp()
            user.otp_code = otp_code
            user.otp_created_at = datetime.utcnow()
            user.otp_attempts = 0
            db.session.commit()
            
            if send_otp_email(user.email, otp_code, user.username):
                session['otp_user_id'] = user.id
                flash(f'OTP sent to {user.email[:3]}***@{user.email.split("@")[1]}', 'success')
                return redirect(url_for('verify_otp'))
            else:
                flash('Could not send OTP. Please try password login or contact support.', 'warning')
                return render_template('login.html')
        else:
            if not password:
                flash('Please enter your password.', 'danger')
                return render_template('login.html')
            
            if user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password. Please try again.', 'danger')
                return render_template('login.html')
    
    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if 'otp_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['otp_user_id'])
    if not user:
        session.pop('otp_user_id', None)
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        
        if not otp_input:
            flash('Please enter the OTP.', 'danger')
            return render_template('verify_otp.html')
        
        if user.otp_attempts >= 3:
            user.otp_code = None
            user.otp_created_at = None
            user.otp_attempts = 0
            db.session.commit()
            session.pop('otp_user_id', None)
            flash('Too many failed attempts. Please request a new OTP.', 'danger')
            return redirect(url_for('login'))
        
        if not is_otp_valid(user):
            user.otp_code = None
            user.otp_created_at = None
            user.otp_attempts = 0
            db.session.commit()
            session.pop('otp_user_id', None)
            flash('OTP expired. Please request a new one.', 'danger')
            return redirect(url_for('login'))
        
        if user.otp_code == otp_input:
            user.otp_code = None
            user.otp_created_at = None
            user.otp_attempts = 0
            db.session.commit()
            
            session.pop('otp_user_id', None)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            user.otp_attempts += 1
            db.session.commit()
            remaining = 3 - user.otp_attempts
            flash(f'Invalid OTP. {remaining} attempt(s) remaining.', 'danger')
            return render_template('verify_otp.html')
    
    return render_template('verify_otp.html')


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if 'otp_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['otp_user_id'])
    if not user:
        session.pop('otp_user_id', None)
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
    otp_code = generate_otp()
    user.otp_code = otp_code
    user.otp_created_at = datetime.utcnow()
    user.otp_attempts = 0
    db.session.commit()
    
    if send_otp_email(user.email, otp_code, user.username):
        flash('New OTP sent successfully!', 'success')
    else:
        flash('Failed to send OTP. Please try again.', 'danger')
    
    return redirect(url_for('verify_otp'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        
        if not login_id:
            flash('Please enter your email or enrollment number.', 'danger')
            return render_template('forgot_password.html')
        
        user = None
        if '@' in login_id:
            user = User.query.filter_by(email=login_id.lower()).first()
        else:
            user = User.query.filter_by(enrollment_number=login_id.upper()).first()
        
        if user:
            reset_token = generate_reset_token()
            user.reset_token = reset_token
            user.reset_token_created_at = datetime.utcnow()
            db.session.commit()
            
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_reset_email(user.email, reset_link, user.username)
        
        flash('If an account exists with that email/enrollment number, you will receive a password reset link.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not is_reset_token_valid(user):
        flash('Invalid or expired reset link. Please request a new one.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not password or not confirm_password:
            flash('Please fill in all fields.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_created_at = None
        db.session.commit()
        
        flash('Password reset successful! Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('home'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    
    if user.role == 'professor':
        my_notes = Note.query.filter_by(uploaded_by=user.id).order_by(Note.upload_time.desc()).limit(5).all()
        total_notes = Note.query.filter_by(uploaded_by=user.id).count()
        return render_template('dashboard_professor.html', 
                             username=user.username, 
                             my_notes=my_notes,
                             total_notes=total_notes)
    else:
        recent_notes = Note.query.order_by(Note.upload_time.desc()).limit(5).all()
        total_notes = Note.query.count()
        return render_template('dashboard_student.html', 
                             username=user.username, 
                             recent_notes=recent_notes,
                             total_notes=total_notes)


@app.route('/upload', methods=['GET', 'POST'])
@login_required
@role_required('professor')
def upload_note():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        subject = request.form.get('subject', '').strip()
        semester = request.form.get('semester', '').strip()
        description = request.form.get('description', '').strip()
        
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return render_template('upload.html')
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected.', 'danger')
            return render_template('upload.html')
        
        if not title:
            flash('Title is required.', 'danger')
            return render_template('upload.html')
        
        if file and allowed_file(file.filename):
            original_filename = file.filename
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
            unique_filename = timestamp + filename
            
            filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
            file.save(filepath)
            
            file_size = os.path.getsize(filepath)
            
            new_note = Note(
                title=title,
                subject=subject,
                semester=semester,
                filename=unique_filename,
                original_filename=original_filename,
                uploaded_by=current_user().id,
                file_size=file_size,
                description=description
            )
            
            db.session.add(new_note)
            db.session.commit()
            
            flash('Note uploaded successfully!', 'success')
            return redirect(url_for('list_notes'))
        else:
            flash('Invalid file type. Allowed types: PDF, DOC, DOCX, PPT, PPTX, TXT, XLS, XLSX, ZIP, RAR', 'danger')
            return render_template('upload.html')
    
    return render_template('upload.html')


@app.route('/notes')
@login_required
def list_notes():
    subject_filter = request.args.get('subject', '')
    semester_filter = request.args.get('semester', '')
    search_query = request.args.get('search', '')
    
    query = Note.query
    
    if subject_filter:
        query = query.filter(Note.subject.ilike(f'%{subject_filter}%'))
    if semester_filter:
        query = query.filter(Note.semester.ilike(f'%{semester_filter}%'))
    if search_query:
        query = query.filter(
            (Note.title.ilike(f'%{search_query}%')) | 
            (Note.subject.ilike(f'%{search_query}%'))
        )
    
    notes = query.order_by(Note.upload_time.desc()).all()
    
    subjects = db.session.query(Note.subject).distinct().filter(Note.subject != '').filter(Note.subject != None).all()
    subjects = [s[0] for s in subjects if s[0]]
    
    semesters = db.session.query(Note.semester).distinct().filter(Note.semester != '').filter(Note.semester != None).all()
    semesters = [s[0] for s in semesters if s[0]]
    
    return render_template('notes.html', 
                         notes=notes, 
                         subjects=subjects, 
                         semesters=semesters,
                         current_subject=subject_filter,
                         current_semester=semester_filter,
                         search_query=search_query)


@app.route('/download/<int:note_id>')
@login_required
def download_note(note_id):
    note = Note.query.get(note_id)
    
    if not note:
        flash('Note not found.', 'danger')
        return redirect(url_for('list_notes'))
    
    try:
        return send_from_directory(
            UPLOAD_FOLDER, 
            note.filename, 
            as_attachment=True,
            download_name=note.original_filename
        )
    except FileNotFoundError:
        flash('File not found on server.', 'danger')
        return redirect(url_for('list_notes'))


@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    return render_template('note_detail.html', note=note)


@app.route('/delete/<int:note_id>', methods=['POST'])
@login_required
@role_required('professor')
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    
    if note.uploaded_by != current_user().id:
        flash('You can only delete your own notes.', 'danger')
        return redirect(url_for('list_notes'))
    
    try:
        filepath = os.path.join(UPLOAD_FOLDER, note.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
    
    db.session.delete(note)
    db.session.commit()
    
    flash('Note deleted successfully.', 'success')
    return redirect(url_for('list_notes'))


def format_file_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


app.jinja_env.filters['filesize'] = format_file_size


if __name__ == "__main__":
    db_url = os.environ.get('DATABASE_URL', '')
    if 'postgresql' in db_url:
        db_display = 'PostgreSQL (configured)'
    elif 'sqlite' in db_url:
        db_display = 'SQLite (local)'
    else:
        db_display = 'Database configured'
    
    print("=" * 60)
    print("  COLLEGE NOTES PORTAL - STARTING SERVER")
    print("=" * 60)
    print(f"  Environment: Development")
    print(f"  Database: {db_display}")
    print(f"  Email configured: {'Yes' if EMAIL_USER else 'No'}")
    print(f"  Server URL: http://0.0.0.0:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)
