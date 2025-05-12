from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, login_required
from blog import db, bcrypt
from blog.models import User, UserFile, UserFileAccess, Notification
from blog.user.forms import Registrationform, LoginForm, FileUploadForm
from flask import abort
from flask import send_from_directory
from werkzeug.utils import secure_filename
import os
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
UPLOAD_FOLDER = r"C:\Users\Vlad12005\PycharmProjects\university_2\blog\uploads"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',"doc","docx","json"}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template("account.html", notifications=notifications)
@users.route("/downolads", methods=['GET', 'POST'])
def downolads():
    form = FileUploadForm()
    form.users.choices = [(user.id, user.username) for user in User.query.all() if user.id != current_user.id]

    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)

            # Сохраняем файл в базу
            user_file = UserFile(
                filename=filename,
                file_path=save_path,
                user_id=current_user.id
            )
            db.session.add(user_file)
            db.session.commit()
            # Даем доступ выбранным пользователям
            if not form.is_public.data:
                for user_id in form.users.data:
                    db.session.add(UserFileAccess(file_id=user_file.id, user_id=user_id))

                    # Создаем уведомление для каждого получателя
                db.session.add(Notification(
                    user_id=user_id,
                    from_user_id=current_user.id,
                    message=f'Вам предоставлен доступ к файлу "{filename}".',
                    type='file'  # указание типа
                ))

            db.session.commit()
            flash("Файл успешно загружен и доступ предоставлен.", "success")
            return redirect(url_for('users.account'))

    return render_template("downloads.html", form=form)


@users.route('/uploads/<filename>')
def uploaded_file(filename):
    file = UserFile.query.filter_by(filename=filename).first()
    if file:
        file_path = file.file_path
        if os.path.exists(file_path):
            directory = os.path.dirname(file_path)
            return send_from_directory(directory, filename, as_attachment=False)
        else:
            abort(404)  # Файл не найден на диске
    else:
        abort(404)
@users.route("/all_files")
def all_files():
    user_files = UserFile.query.filter(
        UserFile.accessible_users.any(id=current_user.id)
    ).all()
    return render_template("all_documents.html", files=user_files)

@users.route("/mark_read/<int:notification_id>", methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.user_id != current_user.id:
        abort(403)

    notification.status = 'read'
    db.session.commit()

    # Только если это уведомление О ФАЙЛЕ, сообщаем отправителю
    if notification.type == 'file' and notification.from_user_id:
        db.session.add(Notification(
            user_id=notification.from_user_id,
            from_user_id=current_user.id,
            message=f'Пользователь {current_user.username} прочитал ваш файл.',
            type='read_receipt'  # тип уведомления
        ))
        db.session.commit()

    flash("Уведомление отмечено как прочитанное.", "success")
    return redirect(url_for('users.account'))
