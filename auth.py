from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Invalid credentials')
            return redirect(url_for('auth.login'))
        
        login_user(user, remember=remember)
        
        # Redirect based on role
        if user.role == 'admin':
            return redirect(url_for('main.admin_dashboard'))
        elif user.role in ['doctor', 'nurse']:
            return redirect(url_for('main.staff_dashboard'))
        else:
            return redirect(url_for('main.patient_dashboard'))
    
    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))