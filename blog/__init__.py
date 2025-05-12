import bcrypt
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from blog.extensions import db
from blog.models import User
from flask_migrate import Migrate
bcrypt = Bcrypt()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__)
    app.config.from_pyfile("settings.py")
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "users.login"
    login_manager.login_message_category = "info"
    migrate = Migrate(app, db)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from blog.main.routes import(main)
    from blog.user.routes import (users)

    app.register_blueprint(main)
    app.register_blueprint(users)

    return app