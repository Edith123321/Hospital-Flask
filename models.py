from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

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