from app import app, db
from models import User

if __name__ == '__main__':
    username = input("Enter existing username: ")

    with app.app_context():
        db.create_all()
        user = db.session.get(User, username)

        if user is not None:
            user.is_admin = True
            db.session.commit()
            print(f"User '{user.id}' has been made admin.")
        else:
            print(f"User '{username}' does not exist. Please signup with the username and try again.")
