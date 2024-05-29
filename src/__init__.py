"""
Module name: Authentication
Authors: IMS Promo Dev Team <imspromo@yncrea.fr>
"""
__version__ = "1.0.0"

import atexit
import logging
import sys
from os import environ, makedirs, getenv, path, getcwd
from flask import Flask
from flask_login import LoginManager
from flask_simpleldap import LDAP
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileChangeHandler(FileSystemEventHandler):
    def __init__(self, app, config_env_path, ldap_env_path):
        self.app = app
        self.config_env_path = config_env_path
        self.ldap_env_path = ldap_env_path

    def on_modified(self, event):
        if event.src_path == self.config_env_path or event.src_path == self.ldap_env_path:
            self.load_app_config(event.src_path)
        else:
            raise ValueError("Invalid config_type.")

    def load_app_config(self, config_path):
        with open(config_path, 'r') as f:
            for line in f:
                name, value = line.strip().split('=', 1)
                if value.isdigit():
                    self.app.config[name] = int(value)
                elif value.lower() in ['true', 'false']:
                    self.app.config[name] = value.lower() == 'true'
                else:
                    self.app.config[name] = value


def start_watchdog(app):
    config_env_path = path.join(getcwd(), 'config.env')
    ldap_env_path = "/usr/ldap.env"
    event_handler = FileChangeHandler(app, config_env_path, ldap_env_path)
    observer = Observer()
    observer.schedule(event_handler, path=config_env_path, recursive=False)
    observer.schedule(event_handler, path=ldap_env_path, recursive=False)
    observer.start()
    event_handler.load_app_config(config_env_path)
    event_handler.load_app_config(ldap_env_path)

    def stop_observer():
        observer.stop()
        observer.join()

    atexit.register(stop_observer)


def init_app_config(app: Flask) -> None:
    app.secret_key = environ.get('SECRET_KEY')


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    start_watchdog(app)
    init_app_config(app)

    db = SQLAlchemy(app)
    CORS(app, supports_credentials=True)
    LoginManager(app)
    ldap = LDAP(app)
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    try:
        makedirs(app.instance_path)
    except OSError:
        pass

    with app.app_context():
        app.db = db
        app.ldap = ldap
        from . import routes

    return app


app = create_app()


if __name__ == "__main__":
    app.run()
