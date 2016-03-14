#!env/bin/python
import logging

from flask.ext.script import Manager

from blog import app, db, models
manager = Manager(app)


@manager.shell
def make_shell_context():
    return dict(app=app, db=db, models=models)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    manager.run()
