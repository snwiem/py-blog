from blog import db


class User(db.Model):
    __tablename__ = "blog_users"

    id = db.Column(db.Integer, name="user_id", primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), name="user_email", unique=True, nullable=False)
    password = db.Column(db.String(1024), name="user_password", nullable=True)
    nickname = db.Column(db.String(255), name="user_nickname", unique=True, nullable=True)
    login = db.Column(db.DateTime, name="user_login", nullable=True)
    address = db.Column(db.String(255), name="user_address", unique=False, nullable=False)
    created = db.Column(db.DateTime, name="user_created", nullable=False)
    modified = db.Column(db.DateTime, name="user_modified", nullable=False)

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return "<%r %r>" % (type(self).__name__, self.email)


class Registration(db.Model):
    __tablename__ = "blog_registrations"

    id = db.Column(db.Integer, name="registration_id", primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), name="registration_email", unique=True, nullable=False)
    password = db.Column(db.String(1024), name="registration_password", nullable=True)
    nickname = db.Column(db.String(255), name="registration_nickname", unique=True, nullable=True)
    token = db.Column(db.String(255), name="registration_token", unique=True, nullable=False)
    address = db.Column(db.String(255), name="registration_address", unique=False, nullable=False)
    retries = db.Column(db.Integer, name="registration_retries", nullable=False, default=0)
    created = db.Column(db.DateTime, name="registration_created", nullable=False)
    modified = db.Column(db.DateTime, name="registration_modified", nullable=False)

    def __repr__(self):
        return "<%r %r>" % (type(self).__name__, self.email)


class PasswordReset(db.Model):
    __tablename__ = "blog_password_resets"

    id = db.Column(db.Integer, name="pwreset_id", primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), name="pwreset_email", unique=True, nullable=False)
    token = db.Column(db.String(255), name="pwreset_token", unique=True, nullable=False)
    address = db.Column(db.String(255), name="pwreset_address", unique=False, nullable=False)
    retries = db.Column(db.Integer, name="pwreset_retries", nullable=False, default=0)
    created = db.Column(db.DateTime, name="pwreset_created", nullable=False)
    modified = db.Column(db.DateTime, name="pwreset_modified", nullable=False)

    def __repr__(self):
        return "<%r %r>" % (type(self).__name__, self.email)