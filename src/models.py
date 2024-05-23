import uuid

import pytz

from app import db


class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.UUID, primary_key=True, unique=True, nullable=False, default=uuid.uuid4)
    username = db.Column(db.String(101), nullable=False, unique=True)
    mail = db.Column(db.String(50), nullable=False, unique=True)
    nom = db.Column(db.String(50), nullable=False)
    prenom = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_authenticated = db.Column(db.Boolean, nullable=False, default=False)

    def get_id(self):
        return self.id

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username
        }


class Roles(db.Model):
    __tablename__ = "role"

    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False, autoincrement=True)
    label = db.Column(db.String(20), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "label": self.label
        }


class User_role(db.Model):
    __tablename__ = "user_role"

    user_id = db.Column(db.UUID, db.ForeignKey('users.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)

    r_user = db.relationship(Users, backref="users")
    r_role = db.relationship(Roles, backref="role")

    def to_dict(self):
        return {
            "user": self.r_user.to_dict(),
            "role": self.r_role.to_dict()
        }


class LoginAttempts(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(15), nullable=False, unique=True)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    lockout_until = db.Column(db.DateTime, nullable=False, default=db.func.now(tz=pytz.timezone('Europe/Paris')))


class Permissions(db.Model):
    __tablename__ = "permission"

    id = db.Column(db.Integer, primary_key=True, unique=True, nullable=False, autoincrement=True)
    label = db.Column(db.String(20), nullable=False, unique=True)

    def to_dict(self):
        return {
            "id": self.id,
            "label": self.label
        }


class Role_permissions(db.Model):
    __tablename__ = "role_permission"

    role_id = db.Column(db.Integer, db.ForeignKey('role.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id', onupdate='CASCADE', ondelete='CASCADE'), primary_key=True)

    r_role = db.relationship(Roles, backref="role_permissions")
    r_permission = db.relationship(Permissions, backref="permission")

    def to_dict(self):
        return {
            "role": self.r_role.to_dict(),
            "permission": self.r_permission.to_dict()
        }
