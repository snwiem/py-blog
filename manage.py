from flask.ext.script import Manager

from blog import app, db
manager = Manager(app)


@manager.shell
def make_shell_context():
    return dict(app=app, db=db)


if __name__ == "__main__":
    manager.run()