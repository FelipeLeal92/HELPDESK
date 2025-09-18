from dotenv import load_dotenv
load_dotenv()

from app import app, db, User, hash_password

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        email = 'admin@example.com'
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                name='Admin',
                email=email,
                password=hash_password('admin'),
                role='admin',
                is_admin=True
            )
            db.session.add(user)
            db.session.commit()
            print("Seeded admin user: admin@example.com / admin")
        else:
            print("Admin user already exists: admin@example.com")