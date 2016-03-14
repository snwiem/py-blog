from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import LoginManager
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object('blog.defaults')
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login = LoginManager(app)

import blog.models, blog.views