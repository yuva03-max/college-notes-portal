College Notes Portal
A web application for sharing course notes between professors and students.

Overview
This Flask-based web application provides:

Password-based and OTP-based authentication
Role-based access control (Student/Professor)
Note upload and download functionality
Forgot password with email reset links
Dark mode support
Project Structure
/
├── main.py                 # Flask application entry point
├── templates/              # HTML templates
│   ├── base.html          # Base template with navigation
│   ├── home.html          # Landing page
│   ├── login.html         # Login with password/OTP tabs
│   ├── register.html      # Registration form
│   ├── verify_otp.html    # OTP verification
│   ├── forgot_password.html # Request password reset
│   ├── reset_password.html # Set new password
│   ├── dashboard_professor.html # Professor dashboard
│   ├── dashboard_student.html   # Student dashboard
│   ├── notes.html         # Notes library with filters
│   ├── upload.html        # Note upload form
│   └── note_detail.html   # Individual note view
├── uploads/               # Uploaded files directory
└── .gitignore            # Git ignore rules

Database Schema
User Model
id, username, email, password_hash, role
enrollment_number (students only, nullable for professors)
OTP fields: otp_code, otp_created_at, otp_attempts
Reset fields: reset_token, reset_token_created_at
Note Model
id, title, subject, semester, description
filename, original_filename, file_size
uploaded_by (FK to User), upload_time
Environment Variables
Required:

DATABASE_URL - PostgreSQL connection string
SESSION_SECRET - Flask session secret key
Optional (for email functionality):

EMAIL_USER - Gmail address for sending emails
EMAIL_PASSWORD - Gmail app password
EMAIL_HOST - SMTP host (default: smtp.gmail.com)
EMAIL_PORT - SMTP port (default: 587)
Features
Authentication

Password-based login
OTP-based login via email
Secure password hashing with Werkzeug
Students: login with email or enrollment number
Professors: login with email only
Password Reset

Forgot password with email reset link
Time-limited reset tokens (1 hour)
Role-Based Access

Students: Browse and download notes
Professors: Upload, manage, and delete notes
Note Management

Upload files (PDF, DOC, PPT, etc. up to 16MB)
Filter by subject and semester
Search by title or subject
Running the Application
The application runs on port 5000:

python main.py

Recent Changes
December 2024: Updated enrollment number to be required only for students (not professors)
December 2024: Initial implementation with password authentication, OTP login, forgot password, and role-based access