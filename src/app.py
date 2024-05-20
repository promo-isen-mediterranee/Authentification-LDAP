import logging
from os import environ
from flask import Flask
from flask_cors import CORS
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from pydap.wsgi.app import DapServer

# Create a new Flask application
app = Flask(__name__)

###############################
#                      Database                     #
###############################

app.config['SQLALCHEMY_DATABASE_URI'] = \
    f"postgresql://{environ.get('DB_USER')}:{environ.get('DB_PASSWORD')}@{environ.get('DB_HOST')}:{environ.get('DB_PORT')}/{environ.get('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

db = SQLAlchemy(app)

###############################
#                        Secret                        #
###############################

app.secret_key = environ.get('SECRET_KEY')

###############################
#                         LDAP                         #
###############################

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

#dap_server = DapServer('/path/to/my/data/files')

ldap_manager = LDAP3LoginManager(app)

#app.wsgi_app = dap_server

###############################
#                         CORS                        #
###############################

# Add CORS support for the response headers
# Set supports_credentials to True to allow credentials (cookies) to be sent with the requests
CORS(app, supports_credentials=True)

###############################
#                  Login Manager                 #
###############################

login_manager = LoginManager()
login_manager.init_app(app)

###############################
#                       Logging                      #
###############################

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.FileHandler('../app.log')

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
