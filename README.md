# HOW TO DOCKERIZE Flask app

## 1. Create a Flask app

```python
import logging
from os import environ
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = \
    f"postgresql://{environ.get('DB_USER')}:{environ.get('DB_PASSWORD')}@{environ.get('DB_HOST')}:{environ.get('DB_PORT')}/{environ.get('DB_NAME')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

db = SQLAlchemy(app)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.FileHandler('../app.log')

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


@app.route('/users')
def users():
    users = User.query.all()
    return {'users': users}


@app.route('/')
def hello_world():
    return 'Hello, World!'


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()
```

## 2. Create a requirements.txt file in the Flask app directory

```txt
Flask~=3.0.3
Flask-SQLAlchemy~=3.1.1
Flask-Login~=0.6.3
Flask-Cors~=4.0.1
setuptools~=69.5.1
flask-ldap3-login~=1.0.2a1
psycopg2~=2.9.9
pydap~=3.4.1
```

## 3. Create a Dockerfile in the Flask app directory

```Dockerfile
FROM python:3.12

###############################
#  Environment Variables  #
###############################

# Database
ENV DB_HOST=logistisen_db
ENV DB_PORT=5432
ENV DB_USER=postgres
ENV DB_PASSWORD=postgres
ENV DB_NAME=logistisen_db
ENV SQLALCHEMY_TRACK_MODIFICATIONS=False

# Flask
ENV FLASK_APP=my-flask-app/src/main.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=5050

# some other environment variables
# ...


###############################
# Configuration of the image  #
###############################

# Create a directory for the app
WORKDIR /my-flask-app

# Copy the app code
COPY my-flask-app/requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY my-flask-app/src /my-flask-app/src

# Expose the port
EXPOSE 5050

# Spécifie la commande à exécuter
CMD ["flask", "run"]
```

## 4. Create a docker-compose.yml file in the parent directory of the Flask app

Creating the docker-compose.yml file in the parent directory of the Flask app allows to build multiple services in the
same file.
This will create an image for each service and run them in the same network. The services can communicate with each
other using the service name as the hostname.

```yaml
version: '3'
name: my-flask-app

services:
  my-db:
    image: postgres:16
    container_name: my-db-container
    volumes:
      - ./db_init:/docker-entrypoint-initdb.d
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: my_db
    ports:
      - "5432:5432"
  my-flask-app:
    build:
      context: .
      dockerfile: my-flask-app/Dockerfile
    container_name: my-flask-app
    ports:
      - "5050:5050"
    depends_on:
      - my-db
    volumes:
      - .:/my-flask-app:ro
```

## 5. Build and run the app
The following command will build the images and run the services in the background.

```bash
docker compose up --build -d
```