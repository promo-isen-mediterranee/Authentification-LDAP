FROM python:3.12


###############################
#  Variables d'environnement  #
###############################

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
#CMD ["flask", "run"]
CMD ["waitress-serve", "--port", "5050", "src:app"]