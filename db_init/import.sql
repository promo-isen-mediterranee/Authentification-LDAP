SET timezone = 'Europe/Paris';

CREATE TABLE IF NOT EXISTS category(
    id SERIAL PRIMARY KEY,
    label VARCHAR(50) NOT NULL,
    UNIQUE(label)
);

CREATE TABLE IF NOT EXISTS item (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    category_id INT REFERENCES category(id) ON UPDATE CASCADE,
    gain INT NOT NULL DEFAULT 100,
    UNIQUE(name, category_id)
);

CREATE TABLE IF NOT EXISTS location (
    id SERIAL PRIMARY KEY,
    address VARCHAR(50) NOT NULL,
    city VARCHAR(50) NOT NULL,
    room VARCHAR(10),
    UNIQUE(address, city, room)
);

CREATE TABLE IF NOT EXISTS item_location (
    id SERIAL PRIMARY KEY,
    item_id INT REFERENCES item(id) ON UPDATE CASCADE ON DELETE CASCADE,
    location_id INT REFERENCES location(id) ON UPDATE CASCADE,
    quantity INT NOT NULL
);

-- User and Role
CREATE TABLE IF NOT EXISTS users (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    username VARCHAR(101) NOT NULL,
    mail VARCHAR(50) NOT NULL,
    nom VARCHAR(50) NOT NULL,
    prenom VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_authenticated BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS role (
    id SERIAL PRIMARY KEY,
    label VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_role (
    user_id uuid REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    role_id INT REFERENCES role(id) ON UPDATE CASCADE,
    CONSTRAINT user_role_pkey PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS permission (
    id SERIAL PRIMARY KEY,
    label VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS role_permission (
    role_id INT REFERENCES role(id) ON UPDATE CASCADE ON DELETE CASCADE,
    permission_id INT REFERENCES permission(id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT role_permission_pkey PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(15) NOT NULL UNIQUE,
    attempts INT NOT NULL DEFAULT 0,
    lockout_until TIMESTAMP NOT NULL DEFAULT NOW()::timestamptz(0)
);

-- Event, EventStatus and Person
CREATE TABLE IF NOT EXISTS event_status (
    id SERIAL PRIMARY KEY,
    label VARCHAR(30) NOT NULL
);

CREATE TABLE IF NOT EXISTS person (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS event (
    id SERIAL PRIMARY KEY,
    name VARCHAR(265) NOT NULL,
    stand_size INT,
    contact_objective INT NOT NULL,
    date_start TIMESTAMP NOT NULL,
    date_end TIMESTAMP NOT NULL,
    status_id INT REFERENCES event_status(id) ON UPDATE CASCADE,
    location_id INT REFERENCES location(id) ON UPDATE CASCADE,
    item_manager uuid REFERENCES person(id) ON UPDATE CASCADE,
    CONSTRAINT check_dates_event CHECK (date_start <= date_end),
    CONSTRAINT check_dates_now CHECK (date(date_start) >= date(NOW())),
    UNIQUE(name, date_start, date_end, location_id)
);

CREATE TABLE IF NOT EXISTS attendee(
    user_id uuid REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    event_id INT REFERENCES event(id) ON UPDATE CASCADE,
    CONSTRAINT attendee_pkey PRIMARY KEY (user_id, event_id)
);

CREATE TABLE IF NOT EXISTS event_status_history (
    id SERIAL PRIMARY KEY,
    set_on TIMESTAMP NOT NULL,
    event_id INT REFERENCES event(id) ON UPDATE CASCADE ON DELETE CASCADE,
    status_id INT REFERENCES event_status(id) ON UPDATE CASCADE,
    set_by uuid REFERENCES users(id) ON UPDATE CASCADE
);

-- Reserved item
CREATE TABLE IF NOT EXISTS reserved_item (
    item_location_id INT REFERENCES item_location(id) ON UPDATE CASCADE,
    event_id INT REFERENCES event(id) ON UPDATE CASCADE,
    quantity INT NOT NULL,
    quantity_ret INT DEFAULT NULL,
    status BOOLEAN NOT NULL,
    reserved_on TIMESTAMP NOT NULL,
    reserved_by uuid REFERENCES users(id) ON UPDATE CASCADE,
    CONSTRAINT reserved_keys PRIMARY KEY (item_location_id, event_id)
);

-- Alert and emails
CREATE TABLE IF NOT EXISTS alert (
    id SERIAL PRIMARY KEY,
    user_id uuid REFERENCES users(id) ON UPDATE CASCADE ON DELETE CASCADE,
    role_id INT REFERENCES role(id) ON UPDATE CASCADE,
    set_on TIMESTAMP NOT NULL
);

INSERT INTO location (address, city, room) VALUES ('Palais Neptune', 'Toulon', '007');
INSERT INTO location (address, city, room) VALUES ('Parc Chanot', 'Marseille', '013');
INSERT INTO location (address, city, room) VALUES ('ISEN, Place Georges Pompidou', 'Toulon', '456');

INSERT INTO users(username, mail, prenom, nom) VALUES ('marc.etavard', 'marc.etavard@isen.yncrea.fr', 'Marc', 'Etavard');
INSERT INTO users(username, mail, prenom, nom) VALUES ('alex.olivier', 'alex.olivier@isen.yncrea.fr', 'Alëx', 'Olivier');
INSERT INTO users(username, mail, prenom, nom) VALUES ('corentin.thibaud', 'corentin.thibaud@isen.yncrea.fr', 'Corentin', 'Thibaud');
INSERT INTO users(username, mail, prenom, nom) VALUES ('juan.gomez-sanchez', 'juan.gomez-sanchez@isen.yncrea.fr', 'Juan', 'Gomez-Sanchez');
INSERT INTO users(username, mail, prenom, nom) VALUES ('dorian.bourdier', 'dorian.bourdier@isen.yncrea.fr', 'Dorian', 'Bourdier');

INSERT INTO role(label) VALUES ('Admin');

INSERT INTO user_role(user_id, role_id) VALUES((SELECT id FROM users WHERE username = 'marc.etavard'), 1);
INSERT INTO user_role(user_id, role_id) VALUES((SELECT id FROM users WHERE username = 'alex.olivier'), 1);
INSERT INTO user_role(user_id, role_id) VALUES((SELECT id FROM users WHERE username = 'corentin.thibaud'), 1);
INSERT INTO user_role(user_id, role_id) VALUES((SELECT id FROM users WHERE username = 'juan.gomez-sanchez'), 1);
INSERT INTO user_role(user_id, role_id) VALUES((SELECT id FROM users WHERE username = 'dorian.bourdier'), 1);


INSERT INTO person(last_name, first_name) VALUES ('ETAVARD', 'Marc');
INSERT INTO person(last_name, first_name) VALUES ('OLIVIER', 'Alëx');
INSERT INTO person(last_name, first_name) VALUES ('THIBAUD', 'Corentin');
INSERT INTO person(last_name, first_name) VALUES ('SANCHEZ', 'Juan');
INSERT INTO person(last_name, first_name) VALUES ('BOURDIER', 'Dorian');

INSERT INTO event_status(label) VALUES ('A faire');
INSERT INTO event_status(label) VALUES ('Prêt');
INSERT INTO event_status(label) VALUES ('Récupéré');
INSERT INTO event_status(label) VALUES ('En attente de réception');
INSERT INTO event_status(label) VALUES ('Réceptionné');
INSERT INTO event_status(label) VALUES ('Fini');

INSERT INTO event(name, stand_size, contact_objective, date_start, date_end, status_id, item_manager, location_id) 
VALUES('JPO', 100, 50, NOW()::timestamptz(0), NOW()::timestamptz(0), 1,
       (SELECT id FROM person WHERE last_name = 'ETAVARD'),
       (SELECT id FROM location WHERE city = 'Toulon' AND room = '007'));
INSERT INTO event(name, stand_size, contact_objective, date_start, date_end, status_id, item_manager, location_id) 
VALUES('Salon étudiant Studyrama', 150, 75, '2024-6-11', '2024-6-14', 1,
       (SELECT id FROM person WHERE last_name = 'OLIVIER'),
       (SELECT id FROM location WHERE city = 'Marseille'));

INSERT INTO category(label) VALUES ('Brochures');
INSERT INTO category(label) VALUES ('Kakémonos');
INSERT INTO category(label) VALUES ('Lettres');
INSERT INTO category(label) VALUES ('Goodies');
INSERT INTO category(label) VALUES ('Transats');
INSERT INTO category(label) VALUES ('RDD');

INSERT INTO item(name, category_id) VALUES('Puissance Alpha Générale', (SELECT id FROM category WHERE label = 'Brochures'));
INSERT INTO item(name, category_id) VALUES('Puissance Alpha Bachelors', (SELECT id FROM category WHERE label = 'Brochures'));
INSERT INTO item(name, category_id) VALUES('FISE', (SELECT id FROM category WHERE label = 'Brochures'));
INSERT INTO item(name, category_id) VALUES('RDD 2024', (SELECT id FROM category WHERE label = 'RDD'));

INSERT INTO item(name, category_id) VALUES('Vie Etudiante', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('R&D', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Ecole Entreprises', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('2 campus', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Ingé/Bachelors', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Cyber', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Chiffres clés', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Dev Jeux Vidéos', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('DNF', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('BIOST', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('CIN', (SELECT id FROM category WHERE label = 'Kakémonos'));
INSERT INTO item(name, category_id) VALUES('MPSI', (SELECT id FROM category WHERE label ='Kakémonos'));

INSERT INTO item(name, category_id) VALUES('Règles', (SELECT id FROM category WHERE label ='Goodies'));
INSERT INTO item(name, category_id) VALUES('Stylos', (SELECT id FROM category WHERE label ='Goodies'));
INSERT INTO item(name, category_id) VALUES('Goodies', (SELECT id FROM category WHERE label ='Goodies'));

INSERT INTO item(name, category_id) VALUES('Kakémonos', (SELECT id FROM category WHERE label ='Kakémonos'));
INSERT INTO item(name, category_id) VALUES('Lettres', (SELECT id FROM category WHERE label ='Lettres'));
INSERT INTO item(name, category_id) VALUES('Transats', (SELECT id FROM category WHERE label ='Transats'));





INSERT INTO item_location(item_id, location_id, quantity) VALUES(1, 3, 280);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(1, 2, 100);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(2, 3, 320);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(3, 3, 20);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(4, 3, 100);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(5, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(6, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(7, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(8, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(9, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(10, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(11, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(12, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(13, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(14, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(15, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(16, 3, 1);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(17, 3, 100);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(18, 3, 1000);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(19, 3, 1500);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(20, 3, 100);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(21, 3, 1000);
INSERT INTO item_location(item_id, location_id, quantity) VALUES(22, 3, 50);



INSERT INTO permission(label) VALUES ('Read Event');
INSERT INTO permission(label) VALUES ('Write Event');
INSERT INTO permission(label) VALUES ('Read Status');
INSERT INTO permission(label) VALUES ('Read Event History');
INSERT INTO permission(label) VALUES ('Read Item');
INSERT INTO permission(label) VALUES ('Write Item');
INSERT INTO permission(label) VALUES ('Read Location');
INSERT INTO permission(label) VALUES ('Write Location');
INSERT INTO permission(label) VALUES ('Read Category');
INSERT INTO permission(label) VALUES ('Write Category');
INSERT INTO permission(label) VALUES ('Write Reserve Item');
INSERT INTO permission(label) VALUES ('Read Reserve Item');
INSERT INTO permission(label) VALUES ('Read User');
INSERT INTO permission(label) VALUES ('Write User');
INSERT INTO permission(label) VALUES ('Read Role');
INSERT INTO permission(label) VALUES ('Write Role');
INSERT INTO permission(label) VALUES ('Write User Role');
INSERT INTO permission(label) VALUES ('Read Permission');
INSERT INTO permission(label) VALUES ('Read Role Permission');
INSERT INTO permission(label) VALUES ('Write Role Permission');

INSERT INTO role_permission(role_id, permission_id) VALUES(1, 1);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 2);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 3);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 4);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 5);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 6);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 7);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 8);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 9);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 10);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 11);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 12);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 13);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 14);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 15);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 16);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 17);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 18);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 19);
INSERT INTO role_permission(role_id, permission_id) VALUES(1, 20);
