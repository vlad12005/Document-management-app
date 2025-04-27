from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, login_required
from blog import db, bcrypt
from blog.models import User
from blog.user.forms import Registrationform, LoginForm
users = Blueprint('users', __name__)


@users.route("/sign", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.blog"))
    form = Registrationform()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data,password = hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Ваш аккаунт был создан.")
        return redirect(url_for('users.login'))
    return render_template("sign.html", form = form)

@users.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('users.account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('users.account'))
    return render_template("login.html", form = form)


@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    return render_template("account.html")
