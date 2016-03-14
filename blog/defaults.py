import os

basedir = os.path.abspath(os.path.dirname(__file__))

DEBUG = True
SECRET_KEY = "MySecretKey!"

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "../blog.db")
SQLALCHEMY_ECHO = True