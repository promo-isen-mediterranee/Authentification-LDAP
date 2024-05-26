FROM python:3.12


###############################
#  Variables d'environnement  #
###############################

# Base de donnée
ENV DB_HOST=logistisen_db
ENV DB_PORT=5432
ENV DB_USER=postgres
ENV DB_PASSWORD=postgres
ENV DB_NAME=logistisen_db
ENV SQLALCHEMY_TRACK_MODIFICATIONS=False

# Serveur ldap
ENV LDAP_HOST="ad.mydomain.com"
ENV LDAP_PORT=389
ENV LDAP_BASE_DN="dc=mydomain,dc=com"
ENV LDAP_USER_DN="ou=users"
ENV LDAP_GROUP_DN="ou=groups"
ENV LDAP_USER_RDN_ATTR="cn"
ENV LDAP_USER_LOGIN_ATTR="username"
ENV LDAP_BIND_USER_DN=None
ENV LDAP_BIND_USER_PASSWORD=None
ENV LDAP_USE_SSL=False

# Flask
ENV FLASK_APP=API_Auth/src/main.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5050
ENV SESSION_DURATION_SECONDS=3600
ENV SECRET_KEY=c3Q2PO9y0XjN6Twk5u1MSyVIVpTlYRi5


###############################
#  Configuration de l'image   #
###############################

# Création du répertoire de travail
WORKDIR /API_Auth

# Copie des fichiers de configuration
COPY API_Auth/requirements.txt .

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code
COPY API_Auth/src /API_Auth/src

# Expose le port 5050
EXPOSE 5050

# Spécifie la commande à exécuter
CMD ["flask", "run"]