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
ENV LDAP_HOST="ldap.example.com"
ENV LDAP_PORT=389
ENV LDAP_BASE_DN="OU=users,DC=example,DC=com"
ENV LDAP_USERNAME="CN=user,OU=Users,DC=example,DC=com"
ENV LDAP_PASSWORD="password"
ENV LDAP_USER_OBJECT_FILTER="(&(objectclass=person)(uid=%s))"

# Flask
ENV FLASK_APP=/API_Authentication/src/__init__.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5050
ENV SESSION_DURATION_SECONDS=900

###############################
#  Configuration de l'image   #
###############################

# Création du répertoire de travail
WORKDIR /API_Authentication

# Copie des fichiers de configuration
COPY requirements.txt .

COPY ./pyproject.toml ./pyproject.toml

# Copie du code
COPY ./src ./src

COPY ./README.md ./README.md

RUN apt-get update -y && apt-get install -y libsasl2-dev python-dev-is-python3 libldap2-dev libssl-dev

# Installation des dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Expose le port 5050
EXPOSE 5050

# Spécifie la commande à exécuter
# CMD ["flask", "run"]
CMD ["waitress-serve", "--port", "5050", "src:app"]