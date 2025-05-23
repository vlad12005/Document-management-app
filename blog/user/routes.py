from flask import abort
from flask import send_from_directory
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, login_required
from blog import db, bcrypt
from blog.models import User, UserFile, UserFileAccess, Notification, UserFile_2
from blog.user.digital_signature import sign, PUBLIC_KEY, SECRET_KEY
from blog.user.forms import Registrationform, LoginForm, FileUploadForm
from werkzeug.utils import secure_filename
import os
import mimetypes
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



@users.route("/downolads_2", methods=['GET', 'POST'])
@login_required
def downolads_2():
    form = FileUploadForm()
    form.users.choices = [(user.id, user.username) for user in User.query.all() if user.id != current_user.id]

    if request.method == 'POST' and form.validate_on_submit():
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)

            user_file_2 = UserFile_2(
                filename=filename,
                file_path=save_path,
                user_id=current_user.id,
                is_public=form.is_public.data
            )
            db.session.add(user_file_2)
            db.session.commit()

            if not form.is_public.data:
                for user_id in form.users.data:
                    db.session.add(UserFileAccess(file_id=user_file_2.id, user_id=user_id))
                db.session.commit()

            return redirect(url_for('users.account'))

    return render_template("Download documents.html", form=form)



@users.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template("account.html", notifications=notifications)
@users.route("/downoloads", methods=['GET', 'POST'])
@login_required
def downoloads():
    form = FileUploadForm()
    form.users.choices = [(user.id, user.username) for user in User.query.all() if user.id != current_user.id]

    if request.method == 'POST' and form.validate_on_submit():
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(save_path)

            user_file = UserFile(
                filename=filename,
                file_path=save_path,
                user_id=current_user.id,
                is_public=form.is_public.data
            )
            db.session.add(user_file)
            db.session.commit()

            if form.is_public.data:
                for user in User.query.all():
                    if user.id != current_user.id:
                        db.session.add(Notification(
                            user_id=user.id,
                            from_user_id=current_user.id,
                            message=f'{current_user.username}Вам предоставлен доступ к файлу  "{filename}"',
                            type='file'
                        ))
            else:

                for user_id in form.users.data:
                    db.session.add(UserFileAccess(file_id=user_file.id, user_id=user_id))
                    db.session.add(Notification(
                        user_id=user_id,
                        from_user_id=current_user.id,
                        message=f'Вам предоставлен доступ к файлу "{filename}".',
                        type='file'
                    ))

            db.session.commit()
            flash("Файл успешно загружен и доступ предоставлен.", "success")
            return redirect(url_for('users.account'))

    return render_template("downloads.html", form=form)
@users.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file = UserFile.query.filter_by(filename=filename).first()
    if not file:
        abort(404)

    if file.user_id != current_user.id and current_user not in file.accessible_users:
        abort(403)

    directory = os.path.dirname(file.file_path)
    filename_safe = os.path.basename(file.file_path)

    mime_type, _ = mimetypes.guess_type(filename_safe)
    if not mime_type:
        mime_type = 'application/octet-stream'

    return send_from_directory(directory, filename_safe, mimetype=mime_type)


@users.route("/all_files", methods=['GET', 'POST'])
@login_required
def all_files():
    files = UserFile.query.filter(
        UserFile.accessible_users.any(id=current_user.id)
    ).all()

    message = None

    if request.method == 'POST':

        if 'sign_file_id' in request.form:
            file_id = int(request.form['sign_file_id'])
            file_to_sign = UserFile.query.get_or_404(file_id)

            if file_to_sign.user_id != current_user.id and current_user not in file_to_sign.accessible_users:
                abort(403)

            if file_to_sign.signature:
                message = "Файл уже подписан."
            else:
                signature = sign(PUBLIC_KEY, SECRET_KEY)
                file_to_sign.signature = signature
                db.session.commit()
                if file_to_sign.user_id != current_user.id:
                    notification = Notification(
                        user_id=file_to_sign.user_id,
                        from_user_id=current_user.id,
                        message=f'Пользователь {current_user.username} подписал ваш файл "{file_to_sign.filename}".',
                        type='file_signed'
                    )
                    db.session.add(notification)
                    db.session.commit()



    return render_template("all_documents.html", files=files, message=message)


@users.route("/mark_read/<int:notification_id>", methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)

    if notification.user_id != current_user.id:
        abort(403)

    notification.status = 'read'
    db.session.commit()

    if notification.type == 'file' and notification.from_user_id:

        all_users = User.query.filter(User.id != current_user.id).all()
        for user in all_users:
            db.session.add(Notification(
                user_id=user.id,
                from_user_id=current_user.id,
                message=f'Пользователь {current_user.username} получил файл.',
                type='info'
            ))
        db.session.commit()

    flash("Уведомление отмечено как прочитанное.", "success")
    return redirect(url_for('users.account'))


@users.route("/help")
@login_required
def help_page():
    return render_template("help.html")

@users.route("/all_uploaded_files")
@login_required
def all_uploaded_files():
    files = UserFile.query.filter_by(user_id=current_user.id).all()
    files_2 = UserFile_2.query.filter_by(user_id=current_user.id).all()
    return render_template("all_uploaded_files.html", files=files, files_2=files_2)



