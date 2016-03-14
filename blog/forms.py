from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo


class LoginForm(Form):
    email = StringField(label="Email Adress", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    login = SubmitField(label="Login")


class RegisterForm(Form):
    email = StringField(label="Email Adress", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    password_confirm = PasswordField(label="Password Confirmation", validators=[DataRequired(), EqualTo('password')])
    register = SubmitField(label="Register")


class PasswordRequestForm(Form):
    email = StringField(label="Email Adress", validators=[DataRequired(), Email()])
    reset = SubmitField(label="Reset")


class PasswordResetForm(Form):
    pid = HiddenField(validators=[DataRequired()])
    email = HiddenField(validators=[DataRequired(), Email()])
    token = HiddenField(validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    password_confirm = PasswordField(label="Password Confirmation", validators=[DataRequired(), EqualTo('password')])
    reset = SubmitField(label="Reset")
