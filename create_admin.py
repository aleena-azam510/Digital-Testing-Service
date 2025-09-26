from app import app, db, User

with app.app_context():
    username = 'admin_user'
    password = 'admin_password'

    # Check if the user already exists to prevent duplicates
    if not User.query.filter_by(username=username).first():
        admin_user = User(username=username, role='admin')
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user '{username}' created successfully!")
    else:
        print(f"Admin user '{username}' already exists.")