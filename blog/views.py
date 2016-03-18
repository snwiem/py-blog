import glob
import os
from datetime import datetime
import hashlib
import logging

from PIL import Image
from blog import app, db, mail, login
from blog.forms import LoginForm, RegisterForm, PasswordRequestForm, PasswordResetForm
from blog.models import User, Registration, PasswordReset
from flask import render_template, flash, redirect, url_for, request, abort, send_file
from flask.ext.login import login_user, login_required, logout_user
from flask.ext.mail import Message
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


def send_registration_email(registration):
    url = "http://" + app.config["SERVER_NAME"] + url_for("register_confirm", rid=registration.id, token=registration.token)

    msg = Message()
    msg.subject = "PY-Blog Registration"
    msg.recipients = [registration.email]
    msg.sender = "noreply@py-blog.com"
    msg.body = render_template("mails/registration.txt", registration=registration, url=url)
    # msg.html = render_template("mails/registration.html", registration=registration, url=url)
    mail.send(msg)


def send_password_email(password):
    url = "http://" + app.config["SERVER_NAME"] + url_for("password_request_confirm", pid=password.id, token=password.token)

    msg = Message()
    msg.subject = "PY-Blog Password Reset"
    msg.recipients = [password.email]
    msg.sender = "noreply@py-blog.com"
    msg.body = render_template("mails/password.txt", password=password, url=url)
    # msg.html = render_template("mails/password.html", password=password, url=url)
    mail.send(msg)


@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))


@app.route("/")
@app.route("/index/")
def index():
    return render_template("index.html")


@app.route("/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


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
            return redirect(request.args.get('next') or url_for('index'))
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
            send_registration_email(registration)
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
                # To prevent spamming we check the last modification timestamp of this password reset request.
                # Reset requests are allowed only after a certain amount of time
                pw_request_minage_in_seconds = app.config["PW_REQUEST_AGE_IN_SECONDS"]
                pw_request_age_in_seconds = (datetime.utcnow() - pw_request.modified).total_seconds()
                if pw_request_age_in_seconds < pw_request_minage_in_seconds:
                    flash("Password resets are only allowed every %d minutes. You need to wait at least %d seconds before you can request a password reset." % ((pw_request_minage_in_seconds/60), (pw_request_minage_in_seconds-pw_request_age_in_seconds)))
                    return render_template("reset.html", form=form)
                pw_request.retries += 1
            pw_request.address = request.remote_addr
            pw_request.modified = datetime.utcnow()
            pw_request.token = create_password_token(pw_request)
            if pw_request.id is None:
                pw_request.created = pw_request.modified
                db.session.add(pw_request)
            db.session.commit()
            send_password_email(pw_request)
        # WARN: this message will also given for emails not being registered users.
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


@app.route("/password_reset/", methods=['POST'])
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


@app.route("/blog/")
@login_required
def blog():
    return render_template("blog.html")


@app.route("/album/<path:path>")
@login_required
def album(path):
    root_abs = os.path.abspath(app.config['ALBUM_ROOT'])
    album_dir = os.path.join(root_abs, path)
    logging.debug("ALBUM_DIR: %s" % album_dir)
    if not os.path.isdir(album_dir):
        # requested directory does not exist...just abort
        abort(404)
    # scan directory for images
    images = [i[len(root_abs):] for ext in app.config['IMAGE_EXTS'] for i in glob.iglob(album_dir + "/*." + ext)]
    subs = [(path+"/"+i, i) for i in next(os.walk(album_dir))[1] if not i.startswith(".")]
    #return json.dumps(images) + json.dumps(subs)
    return render_template('album.html', images=images, subs=subs)


@app.route('/thumb/<path:path>')
@login_required
def thumbnail(path):
    # if there is no such image, we do not need to generate a thumbnail
    image_file = os.path.join(os.path.abspath(app.config['ALBUM_ROOT']), path)
    if not os.path.exists(image_file):
        abort(404)
        return

    album_dir = os.path.dirname(path)
    album_root = os.path.abspath(app.config['ALBUM_ROOT'])
    album_dir = os.path.join(album_root, album_dir)
    thumb_dir = os.path.join(album_dir, ".thumbs")
    thumb_file = os.path.splitext(os.path.join(thumb_dir, os.path.basename(path)))[0]+".png"

    create_thumb = False
    if not os.path.exists(thumb_file) or os.path.getmtime(image_file) > os.path.getmtime(thumb_file):
        create_thumb = True

    if create_thumb:
        if not os.path.exists(thumb_dir):
            os.makedirs(thumb_dir)
        img = Image.open(image_file)
        img.thumbnail(app.config['THUMB_DIMS'])
        logging.debug("*** saving " + thumb_file)
        img.save(thumb_file, "PNG")
    return send_file(thumb_file)

@app.route('/image/<path:path>')
@login_required
def image(path):
    image_file = os.path.join(os.path.abspath(app.config['ALBUM_ROOT']), path)
    if not os.path.exists(image_file):
        abort(404)
        return
    return send_file(image_file)