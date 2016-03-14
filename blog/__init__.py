from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager
from flask.ext.mail import Mail
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object('blog.defaults')
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)
mail = Mail(app)

login.login_view = "login"
login.login_message = u"You need to login to access this page."
login.login_message_category = "info"

import blog.models, blog.views