"""
Module name: Authentication
Authors: IMS Promo Dev Team <imspromo@yncrea.fr>
"""
__version__ = "1.0.0"

import logging
import sys
from os import environ, makedirs
from flask import Flask
from flask_login import LoginManager
from flask_simpleldap import LDAP
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS


def init_app_config(app: Flask) -> None:
    app.config['SQLALCHEMY_DATABASE_URI'] = \
        f"postgresql://{environ.get('DB_USER')}:{environ.get('DB_PASSWORD')}@{environ.get('DB_HOST')}:{environ.get('DB_PORT')}/{environ.get('DB_NAME')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

    app.secret_key = environ.get('SECRET_KEY')

    # Flask-SimpleLDAP configuration
    # Documentation: https://pypi.org/project/Flask-SimpleLDAP/
    app.config['LDAP_HOST'] = environ.get('LDAP_HOST')
    app.config['LDAP_PORT'] = int(environ.get('LDAP_PORT'))
    app.config['LDAP_BASE_DN'] = environ.get('LDAP_BASE_DN')
    app.config['LDAP_USERNAME'] = environ.get('LDAP_USERNAME')
    app.config['LDAP_PASSWORD'] = environ.get('LDAP_PASSWORD')
    app.config['LDAP_USER_OBJECT_FILTER'] = environ.get('LDAP_USER_OBJECT_FILTER')


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

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
