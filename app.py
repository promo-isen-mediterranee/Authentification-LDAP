import logging
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from pydap.wsgi.app import DapServer
from flask_ldap3_login import LDAP3LoginManager

# Create a new Flask application
app = Flask(__name__)

###############################
#                      Database                     #
###############################

app.config['SQLALCHEMY_DATABASE_URI'] = \
    "postgresql://postgres:postgres@localhost:5432/logistisen_db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

###############################
#                        Secret                        #
###############################

# replace by app.secret_key = os.environ.get('SECRET_KEY') in production
app.secret_key = 'secret_key'

###############################
#                         LDAP                         #
###############################

# à modifier avec la configuration LDAP de votre serveur.
# Pour plus d'informations, consultez la documentation de Flask-LDAP3-Login:
# https://flask-ldap3-login.readthedocs.io/en/latest/
app.config['LDAP_HOST'] = 'ldap://your-ldap-server'
app.config['LDAP_PORT'] = 389
app.config['LDAP_BASE_DN'] = 'dc=example,dc=com'
app.config['LDAP_BIND_USER_DN'] = 'cn=admin,dc=example,dc=com'
app.config['LDAP_BIND_USER_PASSWORD'] = 'admin_password'
app.config['LDAP_USER_LOGIN_ATTR'] = 'username'

dap_server = DapServer('/path/to/my/data/files')

ldap_manager = LDAP3LoginManager(app)

app.wsgi_app = dap_server

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

handler = logging.FileHandler('app.log')

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)
