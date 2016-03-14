import os

import sys, os

basedir = os.path.abspath(os.path.dirname(__file__))

SERVER_NAME = "localhost:5000"

MAIL_USERNAME = os.getenv("SMTP_USERNAME")
MAIL_PASSWORD = os.getenv("SMTP_PASSWORD")

DEBUG = True
SECRET_KEY = "MySecretKey!"

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "../blog.db")
SQLALCHEMY_ECHO = True


ALBUM_ROOT = "./albums"
IMAGE_EXTS = ["png", "gif", "jpg", "jpeg", "bmp"]
THUMB_ROOT = "./cache/thumbs"
THUMB_DIMS = (400, 300)

# WTF
WTF_CSRF_ENABLED = True
#WTF_CSRF_SECRET_KEY = Same as SECRET_KEY
WTF_CSRF_TIME_LIMIT = 3600
WTF_CSRF_SSL_STRICT = True

# FLASK-MAIL
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_DEBUG = True
MAIL_DEFAULT_SENDER = None
MAIL_MAX_EMAILS = None
MAIL_SUPPRESS_SEND = True
MAIL_ASCII_ATTACHMENTS = False
