from flask import flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from sqlalchemy.testing.pickleable import User
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.fields.choices import SelectMultipleField
from wtforms.validators import DataRequired,EqualTo,Length,ValidationError
from blog.models import User


class Registrationform(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(),Length(min =4,max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirn_password = PasswordField('Подтвердить пароль', validators=[DataRequired(),EqualTo("password")])
    submit = SubmitField("Войти")

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            flash("Это имя уже занято. Пожалуйсто выберите другое", "danger")
            raise ValidationError("That username is taken. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(),Length(min =4,max=20)])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class FileUploadForm(FlaskForm):
    file = FileField('Файл', validators=[DataRequired()])
    users = SelectMultipleField('Пользователи с доступом', coerce=int)
    is_public = BooleanField('Доступно всем', default=False)
    submit = SubmitField('Загрузить файл')