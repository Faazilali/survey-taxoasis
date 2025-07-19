# app.py
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import threading
import time
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from flask import send_from_directory
from flask_apscheduler import APScheduler
import random
from flask import session


load_dotenv() # Load environment variables from .env file
EMAIL_ADDRESS = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASS')


app = Flask(__name__)
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key_here') # Use a strong, random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///documents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads' # Folder to store uploaded documents

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect unauthenticated users to the login page

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # NEW
    password_hash = db.Column(db.String(120), nullable=False)
    documents = db.relationship('Document', backref='owner', lazy=True)


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False) # To store original name for display
    document_type = db.Column(db.String(100), nullable=False) # e.g., "Trade License", "Emirates ID", "Passport"
    issue_date = db.Column(db.Date, nullable=True)
    expiry_date = db.Column(db.Date, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    reminder_sent = db.Column(db.Boolean, default=False) # To track if reminder has been sent for this document

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash('Username or Email already exists.', 'danger')
            return redirect(url_for('register'))

        # Generate OTP and store temp user data in session
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['temp_username'] = username
        session['temp_email'] = email
        session['temp_password'] = password

        # Send OTP email
        send_otp_email(email, otp)
        flash('An OTP has been sent to your email. Please verify it.', 'info')
        return redirect(url_for('verify_otp'))

    return render_template('register.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            new_user = User(
                username=session.get('temp_username'),
                email=session.get('temp_email')
            )
            new_user.set_password(session.get('temp_password'))
            db.session.add(new_user)
            db.session.commit()

            # Clear session
            session.pop('otp', None)
            session.pop('temp_username', None)
            session.pop('temp_email', None)
            session.pop('temp_password', None)

            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

from datetime import datetime, date # Import date
# ... existing code ...

@app.route('/dashboard')
@login_required
def dashboard():
    user_documents = Document.query.filter_by(user_id=current_user.id).order_by(Document.expiry_date.asc()).all()
    return render_template('dashboard.html', documents=user_documents, now=datetime.now()) # Pass datetime.now() as 'now'

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['document']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        document_type = request.form['document_type']
        expiry_date_str = request.form['expiry_date']
        issue_date_str = request.form.get('issue_date') # Optional

        try:
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
            issue_date = datetime.strptime(issue_date_str, '%Y-%m-%d').date() if issue_date_str else None
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(request.url)

        if file:
            original_filename = file.filename
            filename = f"{current_user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{original_filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            new_document = Document(
                user_id=current_user.id,
                filename=filename,
                original_filename=original_filename,
                document_type=document_type,
                issue_date=issue_date,
                expiry_date=expiry_date
            )
            db.session.add(new_document)
            db.session.commit()
            flash('Document uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
    return render_template('upload_document.html')

@app.route('/documents/<int:doc_id>/delete', methods=['POST'])
@login_required
def delete_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.user_id != current_user.id:
        flash('You are not authorized to delete this document.', 'danger')
        return redirect(url_for('dashboard'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], document.filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    db.session.delete(document)
    db.session.commit()
    flash('Document deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/uploads/<path:filename>')
@login_required
def download_document(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/reset_reminders')
def reset_reminders():
    for doc in Document.query.all():
        doc.reminder_sent = False
    db.session.commit()
    return "Reminders reset."


def send_email_reminder(user_email, document_name, expiry_date):
    subject = "Document Renewal Reminder"
    body = f"""Dear User,

    Your document '{document_name}' is due for renewal on {expiry_date.strftime('%Y-%m-%d')}.

    Please ensure it is renewed on time to avoid any penalties.

    Regards,
    UAE Document App
    """

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = user_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[EMAIL SENT] {user_email} - {document_name}")
    except Exception as e:
        print(f"[EMAIL FAILED] {e}")


def send_otp_email(to_email, otp):
    subject = "Email Verification OTP"
    body = f"""Dear User,

    Your OTP for email verification is: {otp}

    Please enter this code to complete your registration.

    If you did not request this, please ignore this email.

    Regards,
    UAE Document App
    """

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"[✅ OTP EMAIL SENT] {to_email}")
    except Exception as e:
        print(f"[❌ OTP EMAIL FAILED] {e}")


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No user found with that email.', 'danger')
            return redirect(url_for('forgot_password'))

        otp = str(random.randint(100000, 999999))
        session['reset_email'] = email
        session['reset_otp'] = otp

        send_otp_email(email, otp)

        flash('An OTP has been sent to your email.', 'info')
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        new_password = request.form['new_password']

        if entered_otp != session.get('reset_otp'):
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('reset_password'))

        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()

        if user:
            user.set_password(new_password)
            db.session.commit()

        # Clear session
        session.pop('reset_email', None)
        session.pop('reset_otp', None)

        flash('Password reset successful. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')



@scheduler.task('interval', id='check_renewals', seconds=60)
def scheduled_check_for_renewals():
    with app.app_context():
        print("🔄 Scheduled: Checking for document renewals...")
        reminder_thresholds = [30, 15, 7, 2, 1, 0]

        for doc in Document.query.filter_by(reminder_sent=False).all():
            days_until_expiry = (doc.expiry_date - datetime.now().date()).days
            print(f"📄 {doc.original_filename} → Expires in {days_until_expiry} day(s)")

            if days_until_expiry in reminder_thresholds:
                user = db.session.get(User, doc.user_id)
                if user:
                    print(f"📧 Sending reminder to: {user.email}")
                    send_email_reminder(user.email, doc.original_filename, doc.expiry_date)
                    doc.reminder_sent = True
                    db.session.commit()




# --- Run the application ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create tables if they don't exist

    scheduler.start()

    app.run(debug=True) # debug=True allows hot-reloading and better error messages