"""
Module name: Stock
Authors: IMS Promo Dev Team <imspromo@yncrea.fr>
"""
__version__ = "1.0.0"

import logging
import sys
from os import environ, makedirs
from flask import Flask
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS


def init_app_config(app: Flask) -> None:
    app.config['SQLALCHEMY_DATABASE_URI'] = \
        f"postgresql://{environ.get('DB_USER')}:{environ.get('DB_PASSWORD')}@{environ.get('DB_HOST')}:{environ.get('DB_PORT')}/{environ.get('DB_NAME')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

    app.secret_key = environ.get('SECRET_KEY')

    # à modifier avec la configuration LDAP de votre serveur.
    # Pour plus d'informations, consultez la documentation de Flask-LDAP3-Login:
    # https://flask-ldap3-login.readthedocs.io/en/latest/
    app.config['LDAP_HOST'] = environ.get('LDAP_HOST')
    app.config['LDAP_PORT'] = int(environ.get('LDAP_PORT'))
    app.config['LDAP_BASE_DN'] = environ.get('LDAP_BASE_DN')
    app.config['LDAP_USER_DN'] = environ.get('LDAP_USER_DN')
    app.config['LDAP_GROUP_DN'] = environ.get('LDAP_GROUP_DN')
    app.config['LDAP_USER_RDN_ATTR'] = environ.get('LDAP_USER_RDN_ATTR')
    app.config['LDAP_USER_LOGIN_ATTR'] = environ.get('LDAP_USER_LOGIN_ATTR')
    app.config['LDAP_BIND_USER_DN'] = environ.get('LDAP_BIND_USER_DN')
    app.config['LDAP_BIND_USER_PASSWORD'] = environ.get('LDAP_BIND_USER_PASSWORD')
    app.config['LDAP_USE_SSL'] = bool(environ.get('LDAP_USE_SSL'))


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    init_app_config(app)

    db = SQLAlchemy(app)
    CORS(app, supports_credentials=True)
    LoginManager(app)
    ldap_manager = LDAP3LoginManager(app)
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    try:
        makedirs(app.instance_path)
    except OSError:
        pass

    with app.app_context():
        app.db = db
        app.ldap_manager = ldap_manager
        from . import routes  # Import routes after app is created

    return app


app = create_app()

if __name__ == "__main__":
    app.run()
