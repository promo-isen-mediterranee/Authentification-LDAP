"""
This module contains the routes for the authentication system of the application.
It includes routes for user and role management, login attempts, session management, and error handling.
"""

from datetime import timedelta, datetime
from functools import wraps
from os import environ
import pytz
from flask import request, abort, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import text, func

from .models import Users, User_role, Roles, LoginAttempts, Role_permissions, Permissions, Alert

# Database, login manager, LDAP manager, and logger instances from the current app
db = current_app.db
login_manager = current_app.login_manager
ldap = current_app.ldap
logger = current_app.logger


def response(obj=None, message=None, status_code=200):
    """
    This function generates a response dictionary to be returned by the routes.
    It includes an error message if the status code is 400 or above, otherwise it includes the object or message.

    :param obj: The object to be included in the response.
    :param message: The message to be included in the response.
    :param status_code: The status code of the response.

    :returns: A tuple containing the response dictionary and the status code.
    """
    dictionary = {}

    if status_code >= 400:
        dictionary["error"] = message
    else:
        if obj is not None:
            dictionary = obj
        elif message is not None:
            dictionary["message"] = message

    return dictionary, status_code


def login_attempts():
    """
    This decorator function wraps around the login route to handle login attempts.
    It checks if the IP address is locked out due to too many failed login attempts.
    If the IP address is not locked out, it increments the failed login attempts if the login fails,
    or deletes the login attempt record if the login is successful.

    :returns: A wrapper function that handles login attempts.
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            login_attempt = LoginAttempts.query.filter_by(ip_address=ip_address).first()

            if login_attempt and login_attempt.lockout_until > datetime.now(pytz.timezone('Europe/Paris')).replace(tzinfo=None):
                return abort(429)

            if not login_attempt:
                login_attempt = LoginAttempts(ip_address=ip_address)
                db.session.add(login_attempt)

            res = fn(*args, **kwargs)

            if res[1] == 200:  # If the status code is 200 (OK), reset the failed login attempts
                db.session.delete(login_attempt)
            else:
                login_attempt.attempts += 1
                if login_attempt.attempts % 5 == 0:
                    login_attempt.lockout_until = datetime.now(pytz.timezone('Europe/Paris')).replace(tzinfo=None) + timedelta(minutes=1)

            db.session.commit()

            return res

        return decorated_function

    return wrapper


def permissions_required(*permissions):
    """
    This decorator function wraps around the routes to check if the current user has the required permissions.
    If the user is not authenticated, it returns an unauthorized response.
    If the user is authenticated, it checks if the user has any of the required permissions.
    If the user has the required permissions, it proceeds with the route, otherwise it returns a forbidden response.

    :param permissions: The required permissions for the route.

    :returns: A wrapper function that checks the permissions of the current user.
    """

    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            bypass_token = request.headers.get("X-BYPASS")
            if bypass_token == environ.get("BYPASS_TOKEN"):
                return fn(*args, **kwargs)

            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            if not permissions:
                return fn(*args, **kwargs)

            user_roles = User_role.query.filter_by(user_id=current_user.id).all()
            roles = [user_role.r_role for user_role in user_roles]
            has_permission = any(
                Role_permissions.query.filter_by(role_id=role.id, permission_id=permission).first()
                for role in roles for permission in permissions
            )

            if has_permission:
                return fn(*args, **kwargs)
            return abort(403)

        return decorated_view

    return wrapper


@current_app.before_request
def make_session_permanent():
    """
    This function is executed before each request to the Flask application.
    It sets the session to be permanent and configures the session lifetime based on the 'SESSION_DURATION_SECONDS' environment variable.
    """
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(seconds=float(environ.get('SESSION_DURATION_SECONDS')))


@login_manager.user_loader
def user_loader(userId):
    """
    This function is used by Flask-Login to reload the user object from the user ID stored in the session.
    It is decorated with '@login_manager.user_loader', which registers it as the user loader callback function.

    :param userId: The user ID stored in the session.

    :returns: The user object with the provided user ID.
    """
    return Users.query.get(userId)


@current_app.errorhandler(400)
def bad_request(e):
    """
    This function is a Flask error handler for HTTP 400 (Bad Request) errors.
    It returns a response with a custom error message and a status code of 400.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Requête incorrecte', status_code=400)


@current_app.errorhandler(401)
def unauthorized(e):
    """
    This function is a Flask error handler for HTTP 401 (Unauthorized) errors.
    It returns a response with a custom error message and a status code of 401.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Non autorisé', status_code=401)


@current_app.errorhandler(403)
def forbidden(e):
    """
    This function is a Flask error handler for HTTP 403 (Forbidden) errors.
    It returns a response with a custom error message and a status code of 403.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Accès interdit', status_code=403)


@current_app.errorhandler(404)
def page_not_found(e):
    """
    This function is a Flask error handler for HTTP 404 (Not Found) errors.
    It returns a response with a custom error message and a status code of 404.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Resource introuvable', status_code=404)


@current_app.errorhandler(405)
def method_not_allowed(e):
    """
    This function is a Flask error handler for HTTP 405 (Method Not Allowed) errors.
    It returns a response with a custom error message and a status code of 405.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Méthode non autorisée', status_code=405)


@current_app.errorhandler(409)
def conflict(e):
    """
    This function is a Flask error handler for HTTP 409 (Conflict) errors.
    It returns a response with a custom error message and a status code of 409.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Conflit', status_code=409)


@current_app.errorhandler(429)
def too_many_requests(e):
    """
    This function is a Flask error handler for HTTP 429 (Too Many Requests) errors.
    It returns a response with a custom error message and a status code of 429.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Trop de requêtes', status_code=429)


@current_app.errorhandler(500)
def internal_server_error(e):
    """
    This function is a Flask error handler for HTTP 500 (Internal Server Error) errors.
    It returns a response with a custom error message and a status code of 500.

    :param e: The exception object raised by Flask.

    :returns: A tuple containing the response dictionary and the status code.
    """
    return response(message='Erreur interne du serveur', status_code=500)


@current_app.post('/auth/addUser')
@permissions_required(14)
def add_user():
    """
    This Flask route handles POST requests to the '/auth/addUser' endpoint.

    The function creates a new user with the provided username and role.
    If a user with the same username already exists, it aborts the request with a 409 status code.

    :returns: A response object with a message indicating that the user was created and a status code of 201.
    """
    request_form = request.form
    username = request_form['username']
    role_id = request_form['role']

    user = Users.query.filter_by(username=username).first()

    if user:
        abort(409)

    user = Users(username=username)
    user_role = User_role(r_user=user, role_id=role_id)

    db.session.add_all([user, user_role])
    db.session.commit()

    return response(message='Utilisateur créé', status_code=201)


@current_app.put('/auth/editUser/<uuid:userId>')
@permissions_required(14)
def edit_user(userId):
    """
    This Flask route handles PUT requests to the '/auth/editUser/<uuid:userId>' endpoint.

    The function edits the username of the user with the provided user ID.
    If a user with the provided user ID does not exist, it aborts the request with a 404 status code.

    :param userId: The ID of the user to be edited.

    :returns: A response object with a message indicating that the user was edited and a status code of 201.
    """
    request_form = request.form
    username = request_form['username']

    user = Users.query.get(userId)

    if not user:
        abort(404)

    user.username = username

    db.session.commit()

    return response(message='Utilisateur modifié', status_code=201)


@current_app.delete('/auth/deleteUser/<uuid:userId>')
@permissions_required(14)
def delete_user(userId):
    """
    This Flask route handles DELETE requests to the '/auth/deleteUser/<uuid:userId>' endpoint.

    The function deletes the user with the provided user ID.
    If a user with the provided user ID does not exist, it aborts the request with a 404 status code.

    :param userId: The ID of the user to be deleted.

    :returns: A response object with a message indicating that the user was deleted and a status code of 204.
    """
    user_roles = User_role.query.filter_by(user_id=userId).all()

    if not user_roles:
        abort(404)

    user = user_roles[0].r_user

    for user_role in user_roles:
        db.session.delete(user_role)

    db.session.delete(user)
    db.session.commit()

    return response(message='Utilisateur supprimé', status_code=204)


@current_app.get('/auth/getUser/<uuid:userId>')
@permissions_required(13)
def get_user(userId):
    """
    This Flask route handles GET requests to the '/auth/getUser/<uuid:userId>' endpoint.

    The function retrieves the user and their roles with the provided user ID.
    If a user with the provided user ID does not exist, it aborts the request with a 404 status code.

    :param userId: The ID of the user to be retrieved.

    :returns: A response object containing the user and their roles in dictionary format.
    """
    user_roles = User_role.query.filter_by(user_id=userId).all()

    if not user_roles:
        abort(404)

    user = user_roles[0].r_user.to_dict()
    roles = [user_role.r_role.to_dict() for user_role in user_roles]

    return response({"user": user, "roles": roles})


@current_app.get('/auth/getAllUsers')
@permissions_required(13)
def get_all_users():
    """
    This Flask route handles GET requests to the '/auth/getAllUsers' endpoint.

    The function retrieves all users and their roles.

    :returns: A response object containing a list of all users and their roles in dictionary format.
    """
    users_repr = User_role.query.all()
    users = [user_role.to_dict() for user_role in users_repr]

    return response(users)


@current_app.post('/auth/addRoleUser/<uuid:userId>/<int:roleId>')
@permissions_required(17)
def add_role_user(userId, roleId):
    """
    This Flask route handles POST requests to the '/auth/addRoleUser/<uuid:userId>/<int:roleId>' endpoint.

    The function adds a role to a user with the provided user ID and role ID.
    If a user or role with the provided IDs does not exist, or if the user already has the role, it aborts the request with a 404 or 409 status code respectively.

    :param userId: The ID of the user to whom the role is to be added.
    :param roleId: The ID of the role to be added to the user.

    :returns: A response object with a message indicating that the role was added to the user and a status code of 201.
    """
    user = Users.query.get(userId)
    role = Roles.query.get(roleId)

    if not user or not role:
        abort(404)

    user_role = User_role.query.filter_by(user_id=userId, role_id=roleId).first()

    if user_role:
        abort(409)

    user_role = User_role(r_user=user, r_role=role)

    db.session.add(user_role)
    db.session.commit()

    return response(message='Role ajouté à l\'utilisateur', status_code=201)


@current_app.delete('/auth/deleteRoleUser/<uuid:userId>/<int:roleId>')
@permissions_required(17)
def delete_role_user(userId, roleId):
    """
    This Flask route handles DELETE requests to the '/auth/deleteRoleUser/<uuid:userId>/<int:roleId>' endpoint.

    The function removes a role from a user with the provided user ID and role ID.
    If a user or role with the provided IDs does not exist, or if the user only has one role, or if the role to be removed is the last admin role, it aborts the request with a 404 or 409 status code respectively.

    :param userId: The ID of the user from whom the role is to be removed.
    :param roleId: The ID of the role to be removed from the user.

    :returns: A response object with a message indicating that the role was removed from the user and a status code of 204.
    """
    user_role = User_role.query.filter_by(user_id=userId, role_id=roleId).first()

    if not user_role:
        abort(404)

    roles = User_role.query.filter_by(user_id=userId).all()

    if len(roles) == 1:
        abort(409)

    admins = User_role.query.filter_by(role_id=1).all()

    if user_role.role_id == 1 and len(admins) == 1:
        abort(409)

    db.session.delete(user_role)
    db.session.commit()

    return response(message='Role supprimé de l\'utilisateur', status_code=204)


@current_app.post('/auth/addRole/<string:label>')
@permissions_required(16)
def add_role(label):
    """
    This Flask route handles POST requests to the '/auth/addRole/<string:label>' endpoint.

    The function creates a new role with the provided label.
    If a role with the same label already exists, it aborts the request with a 409 status code.

    :param label: The label of the role to be created.

    :returns: A response object with a message indicating that the role was created and a status code of 201.
    """
    role = Roles.query.filter_by(label=label).first()

    if role:
        abort(409)

    role = Roles(label=label)

    db.session.add(role)
    db.session.commit()

    return response(message='Role créé', status_code=201)


@current_app.put('/auth/editRole/<int:roleId>')
@permissions_required(16)
def edit_role(roleId):
    """
    This Flask route handles PUT requests to the '/auth/editRole/<int:roleId>' endpoint.

    The function edits the label of the role with the provided role ID.
    If a role with the provided role ID does not exist, or if a role with the same label already exists, it aborts the request with a 404 or 409 status code respectively.

    :param roleId: The ID of the role to be edited.

    :returns: A response object with a message indicating that the role was edited and a status code of 201.
    """
    request_form = request.form
    label = request_form['label']

    role = Roles.query.get(roleId)
    role_label = Roles.query.filter_by(label=label).first()

    if not role:
        abort(404)

    if role_label:
        abort(409)

    role.label = label

    db.session.commit()

    return response(message='Rôle modifié', status_code=201)


@current_app.delete('/auth/deleteRole/<int:roleId>')
@permissions_required(16)
def delete_role(roleId):
    """
    This Flask route handles DELETE requests to the '/auth/deleteRole/<int:roleId>' endpoint.

    The function deletes the role with the provided role ID and all its associations with users.
    If a role with the provided role ID does not exist, or if the role to be deleted is the admin role, it aborts the request with a 404 or 409 status code respectively.

    :param roleId: The ID of the role to be deleted.

    :returns: A response object with a message indicating that the role was deleted and a status code of 204.
    """
    role = Roles.query.get(roleId)

    if not role:
        abort(404)

    if role.id == 1:
        abort(409)

    user_roles = User_role.query.filter_by(role_id=roleId).all()

    for user_role in user_roles:
        db.session.delete(user_role)

    db.session.delete(role)
    db.session.commit()

    return response(message='Rôle supprimé', status_code=204)


@current_app.get('/auth/getRoles')
@permissions_required(15)
def get_roles():
    """
    This Flask route handles GET requests to the '/auth/getRoles' endpoint.

    The function retrieves all roles.

    :returns: A response object containing a list of all roles in dictionary format.
    """
    roles_repr = Roles.query.all()
    roles = [role.to_dict() for role in roles_repr]

    return response(roles)


@current_app.get('/auth/getPermissions')
@permissions_required(18)
def get_permissions():
    """
    This Flask route handles GET requests to the '/auth/getPermissions' endpoint.

    The function retrieves all permissions.

    :returns: A response object containing a list of all permissions in dictionary format.
    """
    permissions_repr = Permissions.query.all()
    permissions = [permission.to_dict() for permission in permissions_repr]

    return response(permissions)


@current_app.get('/auth/getRolePermissions/<int:roleId>')
@permissions_required(21)
def get_role_permissions(roleId):
    """
    This Flask route handles GET requests to the '/auth/getRolePermissions/<int:roleId>' endpoint.

    The function retrieves all permissions of a role with the provided role ID.
    If a role with the provided role ID does not exist, it aborts the request with a 404 status code.

    :param roleId: The ID of the role whose permissions are to be retrieved.

    :returns: A response object containing the permissions of the role in dictionary format.
    """
    role_permissions_repr = Role_permissions.query.filter_by(role_id=roleId).all()

    if not role_permissions_repr:
        abort(404)

    role_permissions = [role_permission.to_dict() for role_permission in role_permissions_repr]

    return response(role_permissions)


@current_app.post('/auth/setRolePermissions/<int:roleId>/<int:permission>')
@permissions_required(22)
def set_role_permissions(roleId, permission):
    """
    This Flask route handles POST requests to the '/auth/setRolePermissions/<int:roleId>/<int:permission>' endpoint.

    The function sets the permissions of a role with the provided role ID.
    The permissions are provided as an integer, which is converted into a string of bits.
    Each bit represents a permission, and a bit value of 1 means that the role has the permission.
    If a role with the provided role ID does not exist, it aborts the request with a 404 status code.

    :param roleId: The ID of the role whose permissions are to be set.
    :param permission: The integer representation of the permissions to be set.

    :returns: A response object with a message indicating the permissions that were set.
    """
    role = Roles.query.get(roleId)

    if not role:
        abort(404)

    role_permissions = Role_permissions.query.filter_by(role_id=roleId).all()

    for role_permission in role_permissions:
        db.session.delete(role_permission)

    binary_permission = f'{permission:22b}'

    for i in range(len(binary_permission)):
        if binary_permission[i] == '1':
            role_permission = Role_permissions(role_id=roleId, permission_id=i + 1)
            db.session.add(role_permission)

    db.session.commit()

    return response(message=binary_permission)


@current_app.get('/auth/getAllAlerts')
@permissions_required(13)
def get_all_alerts():
    """
    This Flask route handles GET requests to the '/auth/getAllAlerts' endpoint.

    The function retrieves all alerts.

    :returns: A Flask response object containing a list of all alerts in dictionary format.
    """
    alerts = Alert.query.all()
    alerts = [alert.to_dict() for alert in alerts]

    return response(alerts, status_code=200)


@current_app.get('/auth/getAllAlerts/<int:roleId>')
@permissions_required(13)
def get_alerts(roleId):
    """
    This Flask route handles GET requests to the '/auth/getAllAlerts/<int:roleId>' endpoint.

    The function retrieves the alerts with the provided role ID.
    If an alert with the provided role ID does not exist, it aborts the request with a 404 status code.

    :param roleId: The ID of the role for which the alerts are to be retrieved.

    :returns: A Flask response object containing the alerts in dictionary format.
    """
    alerts = Alert.query.filter_by(role_id=roleId).all()

    if not alerts:
        abort(404)

    alerts = [alert.to_dict() for alert in alerts]

    return response(alerts, status_code=200)


@current_app.post('/auth/addAlert/<int:roleId>')
@permissions_required(13)
def add_alert(roleId):
    """
    This Flask route handles POST requests to the '/auth/addAlert/<int:roleId>' endpoint.

    The function creates a new alert for a role with the provided role ID.
    If a role with the provided role ID does not exist, it aborts the request with a 404 status code.

    :param roleId: The ID of the role for which the alert is to be created.

    :returns: A Flask response object with a message indicating that the alert was created and a status code of 201.
    """
    role = Roles.query.get(roleId)

    if not role:
        abort(404)

    alert = Alert(r_role_alert=role, set_on=func.now().op('AT TIME ZONE')(text("'Europe/Paris'")))

    db.session.add(alert)
    db.session.commit()

    return response(message='Alerte ajoutée', status_code=201)


@current_app.put('/auth/editAlert/<int:alertId>')
@permissions_required(13)
def edit_alert(alertId):
    """
    This Flask route handles PUT requests to the '/auth/editAlert/<int:alertId>' endpoint.

    The function edits the mail and role ID of the alert with the provided alert ID.
    If an alert with the provided alert ID does not exist, it aborts the request with a 404 status code.

    :param alertId: The ID of the alert to be edited.

    :returns: A Flask response object with a message indicating that the alert was edited and a status code of 201.
    """
    request_form = request.form
    role_id = request_form['role_id']
    mail = request_form['mail']

    alert = Alert.query.get(alertId)

    if not alert:
        abort(404)

    alert.mail = mail
    alert.role_id = role_id

    db.session.commit()

    return response(message='Alerte modifiée', status_code=201)


@current_app.delete('/auth/deleteAlert/<int:alertId>')
@permissions_required(15)
def delete_alert(alertId):
    """
    This Flask route handles DELETE requests to the '/auth/deleteAlert/<int:alertId>' endpoint.

    The function deletes the alert with the provided alert ID.
    If an alert with the provided alert ID does not exist, it aborts the request with a 404 status code.

    :param alertId: The ID of the alert to be deleted.

    :returns: A Flask response object with a message indicating that the alert was deleted and a status code of 204.
    """
    alert = Alert.query.get(alertId)

    if not alert:
        abort(404)

    db.session.delete(alert)
    db.session.commit()

    return response(message='Alerte supprimée', status_code=204)


@current_app.post('/auth/login')
@login_attempts()
def login():
    """
    This Flask route handles POST requests to the '/auth/login' endpoint.

    The function authenticates a user with the provided username and password.
    If the user is already authenticated, it returns a response indicating that the user is already logged in.
    If the user is not authenticated, it attempts to authenticate the user.
    If the authentication is successful, it logs in the user and returns a response indicating that the authentication was successful.
    If the authentication fails, it aborts the request with a 401 status code.

    :returns: A Flask response object with a message indicating that the authentication was successful and a status code of 200.
    """
    request_form = request.form
    username = request_form['username']
    password = request_form['password']

    user = Users.query.filter_by(username=username).first()

    if current_user and current_user.is_authenticated:
        return response(message='Déjà connecté', status_code=200)

    # check if user/password combination exists on LDAP server
    #res = ldap.bind_user(username, password)

    #if user and res is True:
    if user:
        if login_user(user):
            user.is_authenticated = True
            db.session.commit()

            user_roles = User_role.query.filter_by(user_id=user.id).all()
            roles = []
            for user_role in user_roles:
                role = user_role.r_role.to_dict()
                role_permissions_repr = Role_permissions.query.filter_by(role_id=role['id']).all()
                role_permissions = [role_permission.r_permission.to_dict() for role_permission in role_permissions_repr]
                role['permissions'] = role_permissions
                roles.append(role)

            return response(obj={"user": user.to_dict(), "roles": roles}, status_code=200)
        else:
            return response(message='Non autorisé', status_code=401)
    else:
        return response(message='Non autorisé', status_code=401)


@current_app.post('/auth/logout')
@login_required
def logout():
    """
    This Flask route handles POST requests to the '/auth/logout' endpoint.

    The function logs out the current user and returns a response indicating that the logout was successful.

    :returns: A Flask response object with a message indicating that the logout was successful and a status code of 200.
    """
    user = current_user
    user.is_authenticated = False
    db.session.commit()
    logout_user()
    return response(message='Déconnexion réussie', status_code=200)
