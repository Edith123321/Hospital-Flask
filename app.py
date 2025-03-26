from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_socketio import SocketIO, emit
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
socketio = SocketIO(app)

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # patient, nurse, doctor, admin
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    department = db.Column(db.String(50))
    license_number = db.Column(db.String(50))  # For medical staff
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    blood_type = db.Column(db.String(5))
    allergies = db.Column(db.Text)
    primary_physician = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', foreign_keys=[user_id])

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    staff_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer)  # Minutes
    reason = db.Column(db.Text)
    status = db.Column(db.String(20))  # scheduled, completed, cancelled
    patient = db.relationship('Patient')
    staff = db.relationship('User')

    def serialize(self):
        return {
            'id': self.id,
            'patient': self.patient.user.get_full_name(),
            'doctor': self.staff.get_full_name(),
            'datetime': self.date_time.isoformat(),
            'reason': self.reason,
            'status': self.status
        }

# Authentication
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

# Error Handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for(redirect_based_on_role(user.role)))
        flash('Invalid email or password')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def redirect_based_on_role(role):
    return {
        'admin': 'admin_dashboard',
        'doctor': 'doctor_dashboard',
        'nurse': 'nurse_dashboard',
        'patient': 'patient_dashboard'
    }.get(role, 'index')

# Patient Routes
@app.route('/patient/dashboard')
@login_required
@role_required('patient')
def patient_dashboard():
    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.date_time).all()
    return render_template('patient/dashboard.html', patient=patient, appointments=appointments)

@app.route('/patient/appointments')
@login_required
@role_required('patient')
def patient_appointments():
    patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
    appointments = Appointment.query.filter_by(patient_id=patient.id).all()
    return render_template('patient/appointments.html', appointments=appointments)

@app.route('/patient/appointments/book', methods=['GET', 'POST'])
@login_required
@role_required('patient')
def book_appointment():
    if request.method == 'POST':
        try:
            new_appt = Appointment(
                patient_id=current_user.patient.id,
                staff_id=request.form['doctor_id'],
                date_time=datetime.strptime(request.form['datetime'], '%Y-%m-%dT%H:%M'),
                reason=request.form['reason'],
                status='scheduled'
            )
            db.session.add(new_appt)
            db.session.commit()
            flash('Appointment booked successfully!')
            return redirect(url_for('patient_appointments'))
        except ValueError:
            flash('Invalid date/time format')
    doctors = User.query.filter_by(role='doctor').all()
    return render_template('patient/book_appointment.html', doctors=doctors)

# Doctor Routes
@app.route('/doctor/dashboard')
@login_required
@role_required('doctor')
def doctor_dashboard():
    appointments = Appointment.query.filter_by(staff_id=current_user.id).order_by(Appointment.date_time).all()
    return render_template('doctor/dashboard.html', appointments=appointments)

@app.route('/doctor/patients')
@login_required
@role_required('doctor')
def doctor_patients():
    patients = Patient.query.filter_by(primary_physician=current_user.id).all()
    return render_template('doctor/patients.html', patients=patients)

@app.route('/doctor/patients/<int:patient_id>')
@login_required
@role_required('doctor')
def view_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    appointments = Appointment.query.filter_by(patient_id=patient.id, staff_id=current_user.id).all()
    return render_template('doctor/patient_detail.html', patient=patient, appointments=appointments)

# Nurse Routes
@app.route('/nurse/dashboard')
@login_required
@role_required('nurse')
def nurse_dashboard():
    return render_template('nurse/dashboard.html')

@app.route('/nurse/vitals', methods=['POST'])
@login_required
@role_required('nurse')
def record_vitals():
    data = request.get_json()
    if not data or 'patient_id' not in data:
        return jsonify({'error': 'Invalid data'}), 400
    
    # In a real app, you'd store this in a database
    socketio.emit('vitals_update', data, broadcast=True)
    return jsonify({'status': 'success'})

# Admin Routes
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    if request.method == 'POST':
        try:
            user = User(
                email=request.form['email'],
                password=generate_password_hash(request.form['password']),
                role=request.form['role'],
                first_name=request.form.get('first_name', ''),
                last_name=request.form.get('last_name', '')
            )
            db.session.add(user)
            db.session.commit()
            flash('User created successfully')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}')
    users = User.query.order_by(User.role, User.last_name).all()
    return render_template('admin/manage_users.html', users=users)

# API Routes
@app.route('/api/appointments')
@login_required
def api_appointments():
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first_or_404()
        appointments = Appointment.query.filter_by(patient_id=patient.id)
    elif current_user.role in ['doctor', 'nurse']:
        appointments = Appointment.query.filter_by(staff_id=current_user.id)
    else:
        appointments = Appointment.query
    return jsonify([a.serialize() for a in appointments])

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        emit('message', {'data': f'User {current_user.email} connected'})

# Initialize Database
def create_admin_user():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@hospital.com').first():
            admin = User(
                email='admin@hospital.com',
                password=generate_password_hash('admin123'),
                role='admin',
                first_name='Admin',
                last_name='User'
            )
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")

if __name__ == '__main__':
    create_admin_user()
    socketio.run(app, debug=True)