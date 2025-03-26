from app import app, db
from models import User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Create all tables
    db.create_all()
    
    # Create admin user
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
        print("Database initialized with admin user")