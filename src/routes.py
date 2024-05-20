from datetime import timedelta, datetime
from functools import wraps
from flask import request
from flask_ldap3_login import AuthenticationResponseStatus
from flask_login import login_user, logout_user, current_user
from app import app, db, ldap_manager, login_manager, logger
from models import Users, User_role, Roles, LoginAttempts


def response(object=None, message=None, status_code=200):
    dictionary = {}

    if status_code >= 400:
        dictionary["error"] = message
    else:
        if object is not None:
            dictionary = object
        elif message is not None:
            dictionary["message"] = message

    return dictionary, status_code


def login_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            if not roles:
                return fn(*args, **kwargs)

            user_roles = User_role.query.filter_by(user_id=current_user.id).all()
            uroles = [user_role.role.label for user_role in user_roles]
            for role in roles:
                for urole in uroles:
                    if role == urole:
                        return fn(*args, **kwargs)
            return login_manager.unauthorized()

        return decorated_view

    return wrapper


def login_attempts():
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            login_attempt = LoginAttempts.query.filter_by(ip_address=ip_address).first()

            if login_attempt and login_attempt.lockout_until > datetime.now():
                return response(message='Trop de tentatives de connexion. Réessayez dans une minute', status_code=429)

            if not login_attempt:
                login_attempt = LoginAttempts(ip_address=ip_address)
                db.session.add(login_attempt)

            res = fn(*args, **kwargs)

            if res[1] == 401:  # If the status code is 401 (Unauthorized), increment the failed login attempts
                login_attempt.attempts += 1
                if login_attempt.attempts % 5 == 0:
                    login_attempt.lockout_until = datetime.now() + timedelta(minutes=1)
                db.session.commit()
            elif res[1] == 200:  # If the status code is 200 (OK), reset the failed login attempts
                if login_attempt:
                    db.session.delete(login_attempt)
                    db.session.commit()

            return res

        return decorated_function

    return wrapper


@app.post('/auth/addUser')
def add_user():
    try:
        request_form = request.form
        username = request_form['username']
        role_id = request_form['role']

        user = Users.query.filter_by(username=username).first()

        if user:
            return response(message='Utilisateur déjà existant', status_code=409)

        user = Users(username=username)
        user_role = User_role(r_user=user, role_id=role_id)

        db.session.add(user)
        db.session.add(user_role)
        db.session.commit()

        return response(message='Utilisateur créé', status_code=201)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message=f'Erreur lors de la création de l\'utilisateur', status_code=500)


@app.put('/auth/editUser/<uuid:userId>')
def edit_user(userId):
    try:
        request_form = request.form
        username = request_form['username']

        user = Users.query.get(userId)

        if not user:
            return response(message='Utilisateur introuvable', status_code=404)

        user.username = username

        db.session.commit()

        return response(message='Utilisateur modifié', status_code=201)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la modification de l\'utilisateur', status_code=500)


@app.delete('/auth/deleteUser/<uuid:userId>')
def delete_user(userId):
    try:
        user_roles = User_role.query.filter_by(user_id=userId).all()

        if not user_roles:
            return response(message='Utilisateur introuvable', status_code=404)

        user = user_roles[0].r_user

        for user_role in user_roles:
            db.session.delete(user_role)

        db.session.delete(user)
        db.session.commit()

        return response(message='Utilisateur supprimé', status_code=204)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la suppression de l\'utilisateur', status_code=500)


@app.get('/auth/getUser/<uuid:userId>')
def get_user(userId):
    try:
        user_roles = User_role.query.filter_by(user_id=userId).all()

        if not user_roles:
            return response(message='Utilisateur introuvable', status_code=404)

        user = user_roles[0].r_user.to_dict()
        roles = [user_role.r_role.to_dict() for user_role in user_roles]

        return response({"user": user, "roles": roles})
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la récupération de l\'utilisateur', status_code=500)


@app.get('/auth/getAllUsers')
def get_all_users():
    try:
        #logger.info(f'Admin {current_user.username}  retrieved all users')

        users_repr = User_role.query.all()
        users = [user_role.to_dict() for user_role in users_repr]

        return response(users)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message=f'Erreur lors de la récupération des utilisateurs', status_code=500)


@app.post('/auth/addRoleUser/<uuid:userId>/<int:roleId>')
def add_role_user(userId, roleId):
    try:
        user = Users.query.get(userId)
        role = Roles.query.get(roleId)

        if not user or not role:
            return response(message='Utilisateur ou role introuvable', status_code=404)

        user_role = User_role.query.filter_by(user_id=userId, role_id=roleId).first()

        if user_role:
            return response(message='Role déjà attribué à l\'utilisateur', status_code=409)

        user_role = User_role(r_user=user, r_role=role)

        db.session.add(user_role)
        db.session.commit()

        return response(message='Role ajouté à l\'utilisateur', status_code=201)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de l\'ajout du role à l\'utilisateur', status_code=500)


@app.delete('/auth/deleteRoleUser/<uuid:userId>/<int:roleId>')
def delete_role_user(userId, roleId):
    try:
        user_role = User_role.query.filter_by(user_id=userId, role_id=roleId).first()

        if not user_role:
            return response(message='Role introuvable pour cet utilisateur', status_code=404)

        roles = User_role.query.filter_by(user_id=userId).all()

        if len(roles) == 1:
            return response(message='Impossible de supprimer le role de l\'utilisateur', status_code=409)

        admins = User_role.query.filter_by(role_id=1).all()

        if user_role.role_id == 1 and len(admins) == 1:
            return response(message='Impossible de supprimer le role de l\'utilisateur', status_code=409)

        db.session.delete(user_role)
        db.session.commit()

        return response(message='Role supprimé de l\'utilisateur', status_code=204)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la suppression du role de l\'utilisateur', status_code=500)


@app.post('/auth/addRole/<string:label>')
def add_role(label):
    try:
        role = Roles.query.filter_by(label=label).first()

        if role:
            return response(message='Ce nom de rôle est déjà pris', status_code=409)

        role = Roles(label=label)

        db.session.add(role)
        db.session.commit()

        return response(message='Role créé', status_code=201)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la création du rôle', status_code=500)


@app.put('/auth/editRole/<int:roleId>')
def edit_role(roleId):
    try:
        request_form = request.form
        label = request_form['label']

        role = Roles.query.get(roleId)
        role_label = Roles.query.filter_by(label=label).first()

        if not role:
            return response(message='Rôle introuvable', status_code=404)

        if role_label:
            return response(message='Ce nom de rôle est déjà pris', status_code=409)

        role.label = label

        db.session.commit()

        return response(message='Rôle modifié', status_code=201)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la modification du rôle', status_code=500)


@app.delete('/auth/deleteRole/<int:roleId>')
def delete_role(roleId):
    try:
        role = Roles.query.get(roleId)

        if not role:
            return response(message='Rôle introuvable', status_code=404)

        if role.id == 1:
            return response(message='Impossible de supprimer le rôle', status_code=409)

        user_roles = User_role.query.filter_by(role_id=roleId).all()

        for user_role in user_roles:
            db.session.delete(user_role)

        db.session.delete(role)
        db.session.commit()

        return response(message='Rôle supprimé', status_code=204)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la suppression du rôle', status_code=500)


@app.get('/auth/getRoles')
def get_roles():
    try:
        roles_repr = Roles.query.all()
        roles = [role.to_dict() for role in roles_repr]

        return response(roles)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la récupération des rôles', status_code=500)


@app.post('/auth/login')
@login_attempts()
def login():
    try:
        request_form = request.form
        username = request_form['username']
        password = request_form['password']

        user = Users.query.filter_by(username=username).first()

        ldap_response = ldap_manager.authenticate(username, password)
        if user and ldap_response.status == AuthenticationResponseStatus.success:
            if login_user(user, duration=timedelta(hours=1)):
                user.is_authenticated = True
                db.session.commit()
                return response(message='Authentification réussie', status_code=200)
            else:
                return response(message='Authentification échouée', status_code=401)
        else:
            return response(message='Authentification échouée', status_code=401)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de l\'authentification', status_code=500)


@login_manager.user_loader
def user_loader(userId):
    return Users.query.get(userId)


@app.post('/auth/logout')
@login_required()
def logout():
    try:
        user = current_user
        user.is_authenticated = False
        db.session.commit()
        logout_user()
        return response(message='Déconnexion réussie', status_code=200)
    except Exception:
        logger.exception(f'Exception occurred')
        return response(message='Erreur lors de la déconnexion', status_code=500)
