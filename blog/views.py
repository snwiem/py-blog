from datetime import datetime
import hashlib

from blog import app, db
from blog.forms import LoginForm, RegisterForm, PasswordRequestForm, PasswordResetForm
from blog.models import User, Registration, PasswordReset
from flask import render_template, flash, redirect, url_for, request
from flask.ext.login import login_user
from werkzeug.security import generate_password_hash, check_password_hash


def create_registration_token(registration):
    md5 = hashlib.md5()
    md5.update(registration.email.encode('utf-8'))
    md5.update(registration.password.encode('utf-8'))
    md5.update(registration.address.encode('utf-8'))
    md5.update(str(registration.modified).encode('utf-8'))
    return md5.hexdigest()


def create_password_token(password_request):
    md5 = hashlib.md5()
    md5.update(password_request.email.encode('utf-8'))
    md5.update(password_request.address.encode('utf-8'))
    md5.update(str(password_request.retries).encode('utf-8'))
    md5.update(str(password_request.modified).encode('utf-8'))
    return md5.hexdigest()


@app.route("/")
@app.route("/index/")
def index():
    return render_template("index.html")


@app.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter(User.email == email).first()
        # TODO: check password hashed
        if user is not None and check_password_hash(user.password, password):
            user.login = datetime.utcnow()
            user.address = request.remote_addr

            remember = False
            force = False
            fresh = False
            login_user(user, remember=remember, force=force, fresh=fresh)
            flash("You have successfully logged in.")
            return redirect(url_for("index"))
        else:
            flash("Invalid login data", "danger")
    return render_template("login.html", form=form)


@app.route("/register/", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter(User.email == email).first()
        if user is None:
            # TODO: validate if password matched certain rules ?! (should be done below)
            registration = Registration.query.filter(Registration.email == email).first()
            if registration is None:
                registration = Registration()
                registration.email = email
            registration.password = generate_password_hash(password)
            registration.address = request.remote_addr
            registration.modified = datetime.utcnow()
            registration.nickname = None
            registration.token = create_registration_token(registration)
            if registration.id is None:
                registration.created = registration.modified
                db.session.add(registration)
            db.session.commit()
            # TODO: send registration email
            url = url_for("register_confirm", rid=registration.id, token=registration.token)
            print("URL: %s" % url)
            flash("You have successfully registered. Please check you email inbox.", "success")
        else:
            flash("This email address is already registered.", "danger")
    return render_template("register.html", form=form)


@app.route("/register_confirm/<int:rid>/<token>", methods=['GET'])
def register_confirm(rid, token):
    registration = Registration.query.get(rid)
    if registration is None or registration.token != token:
        flash("Invalid registration link. Please try again", "danger")
        return redirect(url_for("register"))
    user = User()
    user.email = registration.email
    user.password = registration.password
    user.address = request.remote_addr
    user.created = user.modified = datetime.utcnow()
    user.nickname = registration.nickname
    db.session.add(user)
    db.session.delete(registration)
    db.session.commit()
    flash("You have successfully registered. Please login now.", "success")
    return redirect(url_for("login"))


@app.route("/password_request/", methods=['GET', 'POST'])
def password_request():
    form = PasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter(User.email == email).first()
        if user is not None:
            pw_request = PasswordReset.query.filter(PasswordReset.email == email).first()
            if pw_request is None:
                pw_request = PasswordReset()
                pw_request.email = email
                pw_request.retries = 1
            else:
                pw_request.retries += 1
            pw_request.address = request.remote_addr
            pw_request.modified = datetime.utcnow()
            pw_request.token = create_password_token(pw_request)
            if pw_request.id is None:
                pw_request.created = pw_request.modified
                db.session.add(pw_request)
            db.session.commit()
            # TODO: send password email
            url = url_for("password_request_confirm", pid=pw_request.id, token=pw_request.token)
            print("URL: %s" % url)
        flash("You will receive a link per email to finish your password reset.", "success")
        return redirect(url_for("index"))
    return render_template("reset.html", form=form)


@app.route("/password_confirm/<int:pid>/<token>", methods=['GET'])
def password_request_confirm(pid, token):
    pw_request = PasswordReset.query.get(pid)
    if pw_request is None or pw_request.token != token:
        flash("Invalid link. Please try again.", "danger")
        return redirect(url_for("password_request"))
    flash("Please enter you new password and save it with the button.", "message")
    form = PasswordResetForm()
    form.pid.data = pw_request.id
    form.email.data = pw_request.email
    form.token.data = pw_request.token
    return render_template("reset.html", form=form, action=url_for("password_reset"))


@app.route("/password_reset/", methods=['GET', 'POST'])
def password_reset():
    form = PasswordResetForm()
    if form.validate_on_submit():
        pid = int(form.pid.data)
        email = form.email.data
        token = form.token.data
        password = form.password.data

        pw_request = PasswordReset.query.get(pid)
        if pw_request is not None and pw_request.email == email and pw_request.token == token:
            user = User.query.filter(User.email == email).first()
            if user is not None:
                # TODO: check if password matches rules
                user.password = generate_password_hash(password)
                db.session.delete(pw_request)
                db.session.commit()
                flash("Your password has been changed. Please try to login now.")
                return redirect(url_for("login"))
        flash("Invalid link. Please try again.", "danger")
        return redirect(url_for("request"))
    return render_template("reset.html", form=form)