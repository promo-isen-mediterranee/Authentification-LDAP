from datetime import timedelta, datetime
from functools import wraps
from os import environ
import pytz
from flask import request, abort, session
from flask_ldap3_login import AuthenticationResponseStatus
from flask_login import login_user, logout_user, login_required, current_user
from app import app, db, ldap_manager, login_manager, logger
from models import Users, User_role, Roles, LoginAttempts, Role_permissions, Permissions, Alert


def response(obj=None, message=None, status_code=200):
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
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            login_attempt = LoginAttempts.query.filter_by(ip_address=ip_address).first()

            if login_attempt and login_attempt.lockout_until > datetime.now(tz=pytz.timezone('Europe/Paris')):
                return abort(429)

            if not login_attempt:
                login_attempt = LoginAttempts(ip_address=ip_address)
                db.session.add(login_attempt)

            res = fn(*args, **kwargs)
            status_code = res[1]

            if status_code == 401:  # If the status code is 401 (Unauthorized), increment the failed login attempts
                login_attempt.attempts += 1
                if login_attempt.attempts % 5 == 0:
                    login_attempt.lockout_until = datetime.now(tz=pytz.timezone('Europe/Paris')) + timedelta(minutes=1)
            elif status_code == 200:  # If the status code is 200 (OK), reset the failed login attempts
                db.session.delete(login_attempt)

            db.session.commit()

            return res

        return decorated_function

    return wrapper


def permissions_required(*permissions):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
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


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=float(environ.get('SESSION_DURATION_SECONDS')))


@login_manager.user_loader
def user_loader(userId):
    return Users.query.get(userId)


@app.errorhandler(400)
def bad_request(e):
    logger.exception(f'Error occurred')
    return response(message='Requête incorrecte', status_code=400)


@app.errorhandler(401)
def unauthorized(e):
    logger.exception(f'Error occurred')
    return response(message='Non autorisé', status_code=401)


@app.errorhandler(403)
def forbidden(e):
    logger.exception(f'Error occurred')
    return response(message='Accès interdit', status_code=403)


@app.errorhandler(404)
def page_not_found(e):
    logger.exception(f'Error occurred')
    return response(message='Resource introuvable', status_code=404)


@app.errorhandler(405)
def method_not_allowed(e):
    logger.exception(f'Error occurred')
    return response(message='Méthode non autorisée', status_code=405)


@app.errorhandler(409)
def conflict(e):
    logger.exception(f'Error occurred')
    return response(message='Conflit', status_code=409)


@app.errorhandler(429)
def too_many_requests(e):
    logger.exception(f'Error occurred')
    return response(message=e, status_code=429)


@app.errorhandler(500)
def internal_server_error(e):
    logger.exception(f'Error occurred')
    return response(message='Erreur interne du serveur', status_code=500)


@app.post('/auth/addUser')
@permissions_required(14)
def add_user():
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


@app.put('/auth/editUser/<uuid:userId>')
@permissions_required(14)
def edit_user(userId):
    request_form = request.form
    username = request_form['username']

    user = Users.query.get(userId)

    if not user:
        abort(404)

    user.username = username

    db.session.commit()

    return response(message='Utilisateur modifié', status_code=201)


@app.delete('/auth/deleteUser/<uuid:userId>')
@permissions_required(14)
def delete_user(userId):
    user_roles = User_role.query.filter_by(user_id=userId).all()

    if not user_roles:
        abort(404)

    user = user_roles[0].r_user

    for user_role in user_roles:
        db.session.delete(user_role)

    db.session.delete(user)
    db.session.commit()

    return response(message='Utilisateur supprimé', status_code=204)


@app.get('/auth/getUser/<uuid:userId>')
@permissions_required(13)
def get_user(userId):
    user_roles = User_role.query.filter_by(user_id=userId).all()

    if not user_roles:
        abort(404)

    user = user_roles[0].r_user.to_dict()
    roles = [user_role.r_role.to_dict() for user_role in user_roles]

    return response({"user": user, "roles": roles})


@app.get('/auth/getAllUsers')
@permissions_required(13)
def get_all_users():
    logger.info(f'Admin {current_user.username}  retrieved all users')

    users_repr = User_role.query.all()
    users = [user_role.to_dict() for user_role in users_repr]

    return response(users)


@app.post('/auth/addRoleUser/<uuid:userId>/<int:roleId>')
@permissions_required(17)
def add_role_user(userId, roleId):
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


@app.delete('/auth/deleteRoleUser/<uuid:userId>/<int:roleId>')
@permissions_required(17)
def delete_role_user(userId, roleId):
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


@app.post('/auth/addRole/<string:label>')
@permissions_required(16)
def add_role(label):
    role = Roles.query.filter_by(label=label).first()

    if role:
        abort(409)

    role = Roles(label=label)

    db.session.add(role)
    db.session.commit()

    return response(message='Role créé', status_code=201)


@app.put('/auth/editRole/<int:roleId>')
@permissions_required(16)
def edit_role(roleId):
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


@app.delete('/auth/deleteRole/<int:roleId>')
@permissions_required(16)
def delete_role(roleId):
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


@app.get('/auth/getRoles')
@permissions_required(15)
def get_roles():
    roles_repr = Roles.query.all()
    roles = [role.to_dict() for role in roles_repr]

    return response(roles)


@app.get('/auth/getPermissions')
@permissions_required(18)
def get_permissions():
    permissions_repr = Permissions.query.all()
    permissions = [permission.to_dict() for permission in permissions_repr]

    return response(permissions)


@app.get('/auth/getRolePermissions/<int:roleId>')
@permissions_required(21)
def get_role_permissions(roleId):
    role_permissions_repr = Role_permissions.query.filter_by(role_id=roleId).all()

    if not role_permissions_repr:
        abort(404)

    role_permissions = [role_permission.to_dict() for role_permission in role_permissions_repr]

    return response(role_permissions)


@app.post('/auth/setRolePermissions/<int:roleId>/<int:permission>')
@permissions_required(22)
def set_role_permissions(roleId, permission):
    # convert permission into string of bits

    role = Roles.query.get(roleId)

    if not role:
        abort(404)

    role_permissions = Role_permissions.query.filter_by(role_id=roleId).all()

    for role_permission in role_permissions:
        db.session.delete(role_permission)

    binary_permission = f'{permission:22b}'

    for i in range(len(binary_permission)):
        if binary_permission[i] == '1':
            role_permission = Role_permissions(role_id=roleId, permission_id=i+1)
            db.session.add(role_permission)

    db.session.commit()

    return response(message=binary_permission)


@app.get('/auth/getAllAlerts')
@permissions_required(13)
def get_all_alerts():
    alerts = Alert.query.all()
    alerts = [alert.to_dict() for alert in alerts]

    return response(alerts, status_code=200)


@app.post('/auth/addAlert/<int:roleId>')
@permissions_required(13)
def add_alert(roleId):
    role = Roles.query.get(roleId)

    if not role:
        abort(404)

    alert = Alert(r_role_alert=role, set_on = datetime.now(tz=pytz.timezone('Europe/Paris')))

    db.session.add(alert)
    db.session.commit()

    return response(message='Alerte ajoutée', status_code=201)


@app.put('/auth/editAlert/<int:alertId>')
@permissions_required(13)
def edit_alert(alertId):
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


@app.delete('/auth/deleteAlert/<int:alertId>')
@permissions_required(15)
def delete_alert(alertId):
    alert = Alert.query.get(alertId)

    if not alert:
        abort(404)

    db.session.delete(alert)
    db.session.commit()

    return response(message='Alerte supprimée', status_code=204)


@app.post('/auth/login')
@login_attempts()
def login():
    request_form = request.form
    username = request_form['username']
    password = request_form['password']

    user = Users.query.filter_by(username=username).first()

    if current_user and current_user.is_authenticated:
        return response(message='Déjà connecté', status_code=200)

    #ldap_response = ldap_manager.authenticate(username, password)
    if user:
        if login_user(user):
            user.is_authenticated = True
            db.session.commit()
            return response(message='Authentification réussie', status_code=200)
        else:
            abort(401)
    else:
        abort(401)


@app.post('/auth/logout')
@login_required
def logout():
    user = current_user
    user.is_authenticated = False
    db.session.commit()
    logout_user()
    return response(message='Déconnexion réussie', status_code=200)
